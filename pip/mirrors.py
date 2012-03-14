"""
Library to support tools that access PyPI mirrors. The following
functional areas are covered:
- mirror selection (find_mirror)
- mirror verification
- key rollover
"""

import datetime
import hashlib
import errno
import random
import select
import socket
import time
from pip.backwardcompat import (b, u, _ord as ord,
                                decode_base64, _long)


def _mirror_list(first):
    """
    Generator producing all mirror names
    """
    ord_a = ord('a')
    try:
        last = socket.gethostbyname_ex('last.pypi.python.org')
    except socket.gaierror:
        return
    cur_index = ord(first) - ord_a
    cur = first + '.pypi.python.org'
    while True:
        for family, _, _, _, sockaddr in socket.getaddrinfo(cur, 0, 0, socket.SOCK_STREAM):
            yield cur, family, sockaddr[0]
        if last[0] == cur:
            break
        cur_index += 1
        if cur_index < 26:
            # a..z
            cur = chr(ord_a + cur_index)
        elif cur_index > 701:
            raise ValueError('too many mirrors')
        else:
            # aa, ab, ... zz
            cur = divmod(cur_index, 26)
            cur = chr(ord_a - 1 + cur[0]) + chr(ord_a + cur[1])
        cur += '.pypi.python.org'

def _batched_mirror_list(first):
    """
    Generator that does DNS lookups in batches of 10, and shuffles them.
    """
    batch = []
    for res in _mirror_list(first):
        batch.append(res)
        if len(batch) == 10:
            random.shuffle(batch)
            for res2 in batch:
                yield res2
            batch = []
    random.shuffle(batch)
    for res2 in batch:
        yield res2

class _Mirror:
    # status values:
    # 0: wants to send
    # 1: wants to recv
    # 2: completed, ok
    # 3: completed, failed
    def __init__(self, name, family, ip):
        self.name = name
        self.family = family
        self.ip = ip
        self.socket = socket.socket(family, socket.SOCK_STREAM)
        self.socket.setblocking(0)
        self.started = time.time()
        try:
            self.socket.connect((ip, 80))
        except socket.error, e:
            if e.errno != errno.EINPROGRESS:
                raise
        # now need to select for writing
        self.status = 0

    def write(self):
        url = 'last-modified'
        if self.name == 'a.pypi.python.org':
            # the master server doesn't provide last-modified,
            # as that would be pointless. Instead, /daytime can be
            # used as an indication of currency and responsiveness.
            url = 'daytime'
        self.socket.send('GET /%s HTTP/1.0\r\n'
                         'Host: %s\r\n'
                         '\r\n' % (url, self.name))
        self.status = 1

    def read(self):
        data = self.socket.recv(1200)
        self.response_time = time.time()-self.started
        # response should be much shorter
        assert len(data) < 1200
        self.socket.close()
        data = data.splitlines()
        if data[0].split()[1] == '200':
            # ok
            data = data[-1]
            try:
                self.last_modified = datetime.datetime.strptime(data, "%Y%m%dT%H:%M:%S")
                self.status = 2 # complete
            except ValueError:
                self.status = 3 # failed
        else:
            self.status = 3

    def failed(self):
        self.socket.close()
        self.status = 3

    def results(self):
        return self.name, self.family, self.ip, self.response_time, self.last_modified

def _select(mirrors):
    # perform select call on mirrors dictionary
    rlist = []
    wlist = []
    xlist = []
    for m in mirrors.values():
        if m.status == 0:
            wlist.append(m.socket)
            xlist.append(m.socket)
        elif m.status == 1:
            rlist.append(m.socket)
            xlist.append(m.socket)
    rlist, wlist, xlist = select.select(rlist, wlist, xlist, 0)
    completed = []
    for s in wlist:
        mirrors[s].write()
    for s in rlist:
        m = mirrors[s]
        del mirrors[s]
        m.read()
        if m.status == 2:
            completed.append(m)
    for s in xlist:
        mirrors[s].failed()
        del mirrors[s]
    return completed

def _close(mirrors):
    for m in mirrors:
        m.close()

def _newest(mirrors, amount=1):
    mirrors.sort(key=lambda m: m.last_modified)
    results = [mirror.results() for mirror in mirrors[-amount:]]
    if amount == 1:
        return results[0]
    return results[::-1]


def find_mirrors(start_with='a',
                 good_age=30*60,
                 slow_mirrors_wait=5,
                 prefer_fastest=True,
                 amount=1):
    """
    find_mirrors(start_with, good_age, slow_mirrors_wait, prefer_fastest)
       -> [(name, family, IP, response_time, last_modified)]

    Find a PyPI mirror matching given criteria.
    start_with indicates the first mirror that should be considered (defaults to 'a').
    If prefer_fastest is True, it stops with the first mirror responding. Mirrors 'compete'
    against each other in randomly-shuffled batches of 10.
    If this procedure goes on for longer than slow_mirrors_wait (default 5s) and prefer_fastest
    is false, return even if not all mirrors have been responding.
    If no matching mirror can be found, the newest one that did response is returned.
    If no mirror can be found at all, ValueError is raised
    """
    started = time.time()
    good_mirrors = []
    pending_mirrors = {} # socket:mirror
    good_last_modified = datetime.datetime.utcnow() - datetime.timedelta(seconds=good_age)
    for host, family, ip in _batched_mirror_list(start_with):
        try:
            m = _Mirror(host, family, ip)
        except socket.error:
            continue
        pending_mirrors[m.socket] = m
        for m in _select(pending_mirrors):
            if prefer_fastest and m.last_modified > good_last_modified:
                _close(pending_mirrors)
                return m.results()
            else:
                good_mirrors.append(m)

    while pending_mirrors:
        if time.time() > started + slow_mirrors_wait and good_mirrors:
            # if we have looked for 5s for a mirror, and we already have one
            # return the newest one
            _close(pending_mirrors)
            return _newest(good_mirrors, amount)
        for m in _select(pending_mirrors):
            if prefer_fastest and m.last_modified > good_last_modified:
                _close(pending_mirrors)
                return [m.results()]
            else:
                good_mirrors.append(m)
    if not good_mirrors:
        raise ValueError("No mirrors found")
    return _newest(good_mirrors, amount)

# Distribute and use freely; there are no restrictions on further
# dissemination and usage except those imposed by the laws of your
# country of residence.  This software is provided "as is" without
# warranty of fitness for use or suitability for any purpose, express
# or implied. Use at your own risk or not at all.
"""
Verify a DSA signature, for use with PyPI mirrors.

Originally copied from PyPI's own code:
https://svn.python.org/packages/trunk/pypi/tools/verify.py

Verification should use the following steps:
1. Download the DSA key from http://pypi.python.org/serverkey, as key_string
2. key = load_key(key_string)
3. Download the package page, from <mirror>/simple/<package>/, as data
4. Download the package signature, from <mirror>/serversig/<package>, as sig
5. Check verify(key, data, sig)
"""

try:
    from M2Crypto import EVP, DSA, BIO

    def load_key(string):
        """
        load_key(string) -> key

        Convert a PEM format public DSA key into
        an internal representation.
        """
        return DSA.load_pub_key_bio(BIO.MemoryBuffer(string))

    def verify(key, data, sig):
        """
        verify(key, data, sig) -> bool

        Verify autenticity of the signature created by key for
        data. data is the bytes that got signed; signature is the
        bytes that represent the signature, using the sha1+DSA
        algorithm. key is an internal representation of the DSA key
        as returned from load_key."""
        md = EVP.MessageDigest('sha1')
        md.update(data)
        digest = md.final()
        return key.verify_asn1(digest, sig)

except ImportError:

    # DSA signature algorithm, taken from pycrypto 2.0.1
    # The license terms are the same as the ones for this module.
    def _inverse(u, v):
        """
        _inverse(u:long, u:long):long
        Return the inverse of u mod v.
        """
        u3, v3 = _long(u), _long(v)
        u1, v1 = _long(1), _long(0)
        while v3 > 0:
            q = u3 // v3
            u1, v1 = v1, u1 - v1 * q
            u3, v3 = v3, u3 - v3 * q
        while u1 < 0:
            u1 = u1 + v
        return u1

    def _verify(key, M, sig):
        p, q, g, y = key
        r, s = sig
        if r <= 0 or r >= q or s <= 0 or s >= q:
            return False
        w = _inverse(s, q)
        u1, u2 = (M * w) % q, (r * w) % q
        v1 = pow(g, u1, p)
        v2 = pow(y, u2, p)
        v = (v1 * v2) % p
        v = v % q
        return v == r

    # END OF pycrypto

    def _bytes2int(b):
        value = 0
        for c in b:
            value = value * 256 + ord(c)
        return value

    _SEQUENCE = 0x30  # cons
    _INTEGER = 2      # prim
    _BITSTRING = 3    # prim
    _OID = 6          # prim

    def _asn1parse(string):
        tag = ord(string[0])
        assert tag & 31 != 31  # only support one-byte tags
        length = ord(string[1])
        assert length != 128  # indefinite length not supported
        pos = 2
        if length > 128:
            # multi-byte length
            val = 0
            length -= 128
            val = _bytes2int(string[pos:pos + length])
            pos += length
            length = val
        data = string[pos:pos + length]
        rest = string[pos + length:]
        assert pos + length <= len(string)
        if tag == _SEQUENCE:
            result = []
            while data:
                value, data = _asn1parse(data)
                result.append(value)
        elif tag == _INTEGER:
            assert ord(data[0]) < 128  # negative numbers not supported
            result = 0
            for c in data:
                result = result * 256 + ord(c)
        elif tag == _BITSTRING:
            result = data
        elif tag == _OID:
            result = data
        else:
            raise ValueError("Unsupported tag %x" % tag)
        return (tag, result), rest

    def load_key(string):
        """
        load_key(string) -> key

        Convert a PEM format public DSA key into
        an internal representation."""
        lines = [line.strip() for line in string.splitlines()]
        assert lines[0] == b("-----BEGIN PUBLIC KEY-----")
        assert lines[-1] == b("-----END PUBLIC KEY-----")
        data = decode_base64(''.join([u(line) for line in lines[1:-1]]))
        spki, rest = _asn1parse(data)
        assert not rest
        # SubjectPublicKeyInfo  ::=  SEQUENCE  {
        #  algorithm            AlgorithmIdentifier,
        #  subjectPublicKey     BIT STRING  }
        assert spki[0] == _SEQUENCE
        algoid, key = spki[1]
        assert key[0] == _BITSTRING
        key = key[1]
        # AlgorithmIdentifier  ::=  SEQUENCE  {
        #  algorithm               OBJECT IDENTIFIER,
        #  parameters              ANY DEFINED BY algorithm OPTIONAL  }
        assert algoid[0] == _SEQUENCE
        algorithm, parameters = algoid[1]
        # dsaEncryption
        # assert algorithm[0] == _OID and algorithm[1] == '*\x86H\xce8\x04\x01'
        # Dss-Parms  ::=  SEQUENCE  {
        #  p             INTEGER,
        #  q             INTEGER,
        #  g             INTEGER  }
        assert parameters[0] == _SEQUENCE
        p, q, g = parameters[1]
        assert p[0] == q[0] == g[0] == _INTEGER
        p, q, g = p[1], q[1], g[1]
        # Parse bit string value as integer
        # assert key[0] == '\0'  # number of bits multiple of 8
        y, rest = _asn1parse(key[1:])
        assert not rest
        assert y[0] == _INTEGER
        y = y[1]
        return p, q, g, y

    def verify(key, data, sig):
        """
        verify(key, data, sig) -> bool

        Verify autenticity of the signature created by key for
        data. data is the bytes that got signed; signature is the
        bytes that represent the signature, using the sha1+DSA
        algorithm. key is an internal representation of the DSA key
        as returned from load_key."""
        sha = hashlib.sha1()
        sha.update(data)
        data = sha.digest()
        data = _bytes2int(data)
        # Dss-Sig-Value  ::=  SEQUENCE  {
        #      r       INTEGER,
        #      s       INTEGER  }
        sig, rest = _asn1parse(sig)
        assert not rest
        assert sig[0] == _SEQUENCE
        r, s = sig[1]
        assert r[0] == s[0] == _INTEGER
        sig = r[1], s[1]
        return _verify(key, data, sig)
