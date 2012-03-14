"""
Routines related to PyPI, indexes, PEP381 mirrors
"""
import sys
import os
import re
import hashlib
import gzip
import mimetypes
try:
    import threading
except ImportError:
    import dummy_threading as threading
import posixpath
import pkg_resources
import random
import socket
import string
import zlib

import requests

from pip.locations import serverkey_file
from pip.log import logger
from pip.util import Inf, normalize_name, splitext
from pip.exceptions import DistributionNotFound, BestVersionAlreadyInstalled
from pip.backwardcompat import (WindowsError, BytesIO,
                                Queue, urlparse,
                                URLError, HTTPError, b, u,
                                product, url2pathname,
                                OrderedDict, _ord as ord,
                                decode_base64, _long,
                                Empty as QueueEmpty)
from pip.download import urlopen, path_to_url2, url_to_path, geturl
from pip.mirrors import verify, load_key, find_mirrors

__all__ = ['PackageFinder']


_egg_fragment_re = re.compile(r'#egg=([^&]*)')
_egg_info_re = re.compile(r'([a-z0-9_.]+)-([a-z0-9_.-]+)', re.I)
_py_version_re = re.compile(r'-py([123]\.?[0-9]?)$')
_clean_re = re.compile(r'[^a-z0-9$&+,/:;=?@.#%~_\\|-]', re.I)
_md5_re = re.compile(r'md5=([a-f0-9]+)')


class PackageFinder(object):
    """This finds packages.

    This is meant to match easy_install's technique for looking for
    packages, by reading pages and looking for appropriate links
    """
    def __init__(self, find_links, index_urls,
                 use_mirrors=False, mirrors=None):
        self.find_links = find_links
        self.index_urls = index_urls
        self.dependency_links = []
        self.cache = PageCache()
        # These are boring links that have already been logged somehow:
        self.logged_links = set()
        if use_mirrors:
            self.mirror_urls = self._get_mirror_urls(mirrors)
            logger.info('Using PyPI mirrors:\n* %s' %
                        '\n* '.join([url.url for url in self.mirror_urls]))
        else:
            self.mirror_urls = ()
        serverkey_cache = open(serverkey_file, 'rb')
        try:
            self.serverkey = load_key(serverkey_cache.read())
        finally:
            serverkey_cache.close()

    def add_dependency_links(self, links):
        ## FIXME: this shouldn't be global list this, it should only
        ## apply to requirements of the package that specifies the
        ## dependency_links value
        ## FIXME: also, we should track comes_from (i.e., use Link)
        self.dependency_links.extend(links)

    @staticmethod
    def _sort_locations(locations):
        """
        Sort locations into "files" (archives) and "urls", and return
        a pair of lists (files, urls)
        """
        files = []
        urls = []

        # puts the url for the given file path into the appropriate
        # list
        def sort_path(url, path):
            new_url = path_to_url2(path)
            mimetype = mimetypes.guess_type(new_url, strict=False)[0]
            url.url = new_url
            if mimetype == 'text/html':
                urls.append(url)
            else:
                files.append(url)

        for url in locations:
            if isinstance(url, Link):
                url = url.copy()
            else:
                url = Link(url)
            if url.url.startswith('file:'):
                path = url_to_path(url.url)
                if os.path.isdir(path):
                    path = os.path.realpath(path)
                    for item in os.listdir(path):
                        sort_path(url, os.path.join(path, item))
                elif os.path.isfile(path):
                    sort_path(url, path)
            else:
                urls.append(url)
        return files, urls

    def make_package_url(self, url, name):
        """
        For maximum compatibility with easy_install, ensure the path
        ends in a trailing slash.  Although this isn't in the spec
        (and PyPI can handle it without the slash) some other index
        implementations might break if they relied on easy_install's
        behavior.
        """
        if isinstance(url, Link):
            package_url = url.copy()
        else:
            package_url = Link(url)
        new_url = posixpath.join(package_url.url, name)
        if not new_url.endswith('/'):
            new_url = new_url + '/'
        package_url.url = new_url
        return package_url

    def verify(self, requirement, url):
        """
        Verifies the URL for the given requirement using the PEP381
        verification code.
        """
        if url.comes_from and url.base_url:
            try:
                data = b(url.comes_from.content)
                serversig = requirement.serversig(url.base_url)
                if data and serversig:
                    return verify(self.serverkey, data, serversig)
            except ValueError:
                return False
        return False

    def find_requirement(self, req, upgrade):
        url_name = req.url_name
        # Only check main index if index URL is given:
        main_index_url = None
        if self.index_urls:
            # Check that we have the url_name correctly spelled:
            main_index_url = self.make_package_url(self.index_urls[0],
                                                   url_name)
            # This will also cache the page,
            # so it's okay that we get it again later:
            page = self._get_page(main_index_url, req)
            if page is None:
                url_name = self._find_url_name(Link(self.index_urls[0]), url_name, req) or req.url_name

        # Combine index URLs with mirror URLs here to allow
        # adding more index URLs from requirements files

        locations = []
        indexes_package_urls = []
        mirrors_package_urls = []
        if url_name is not None:
            indexes_package_urls = [self.make_package_url(url, url_name)
                                    for url in self.index_urls]
            locations.extend(indexes_package_urls)
            mirrors_package_urls = [self.make_package_url(url, url_name)
                                    for url in self.mirror_urls]
            locations.extend(mirrors_package_urls)

        locations.extend(self.find_links + self.dependency_links)

        for version in req.absolute_versions:
            if url_name is not None and main_index_url is not None:
                version_url = posixpath.join(main_index_url.url, version)
                locations = [version_url] + locations

        file_locations, url_locations = self._sort_locations(locations)

        locations = []
        for url in url_locations:
            if isinstance(url, Link):
                locations.append(url)
            else:
                locations.append(Link(url))
        logger.debug('URLs to search for versions for %s:' % req)
        for location in locations:
            logger.debug('* %s' % location)

        found_versions = []
        found_versions.extend(
            self._package_versions(
                [Link(url, '-f') for url in self.find_links], req.name.lower()))
        page_versions = []
        for page in self._get_pages(locations, req):
            logger.debug('Analyzing links from page %s' % page.url)
            logger.indent += 2
            try:
                page_versions.extend(self._package_versions(
                    page.links, req.name.lower()))
            finally:
                logger.indent -= 2

        dependency_versions = list(self._package_versions(
            [Link(url) for url in self.dependency_links], req.name.lower()))
        if dependency_versions:
            dependency_urls = [link.url for _, link, _ in dependency_versions]
            logger.info('dependency_links found: %s' %
                        ', '.join(dependency_urls))

        file_versions = list(self._package_versions(
                [Link(url) for url in file_locations], req.name.lower()))
        if (not found_versions and not page_versions and
                not dependency_versions and not file_versions):
            logger.fatal('Could not find any downloads that satisfy '
                         'the requirement %s' % req)
            raise DistributionNotFound('No distributions at all found for %s'
                                       % req)

        if req.satisfied_by is not None:
            found_versions.append((req.satisfied_by.parsed_version,
                                   Inf, req.satisfied_by.version))

        if file_versions:
            file_versions.sort(reverse=True)
            file_urls = [url_to_path(link.url) for _, link, _ in file_versions]
            logger.info('Local files found: %s' % ', '.join(file_urls))
            found_versions = file_versions + found_versions

        all_versions = found_versions + page_versions + dependency_versions

        applicable_versions = OrderedDict()
        for parsed_version, link, version in all_versions:
            if version not in req.req:
                req_specs = [''.join(s) for s in req.req.specs]
                logger.info("Ignoring link %s, version %s doesn't match %s" %
                            (link, version, ','.join(req_specs)))
                continue
            link_comes_from = None
            mirror_urls = [mirror.url for mirror in mirrors_package_urls]
            if link is not Inf:
                link_comes_from = getattr(link, 'comes_from', None)
                if link_comes_from is not None:
                    link.is_mirror = link_comes_from.url in mirror_urls
            applicable_versions.setdefault(version, []).append(link)

        for version in applicable_versions:
            random.shuffle(applicable_versions[version])

        sorted_applicable_versions = sorted(applicable_versions.items(),
            key=lambda v: pkg_resources.parse_version(v[0]), reverse=True)
        applicable_versions = OrderedDict(sorted_applicable_versions)

        all_links = [link for link in [links
                     for links in applicable_versions.values()]
                     if link is Inf]
        existing_applicable = bool(all_links)

        if not upgrade and existing_applicable:
            if Inf in applicable_versions[0][1]:
                logger.info('Existing installed version (%s) is most '
                            'up-to-date and satisfies requirement' %
                            req.satisfied_by.version)
                raise BestVersionAlreadyInstalled
            else:
                logger.info('Existing installed version (%s) satisfies '
                            'requirement (most up-to-date version is %s)' %
                            (req.satisfied_by.version,
                             applicable_versions[0][1]))
            return None

        if not applicable_versions:
            show_versions = [version for _, _, version in found_versions]
            logger.fatal('Could not find a version that satisfies '
                         'the requirement %s (from versions: %s)' %
                         (req, ', '.join(show_versions)))
            raise DistributionNotFound('No distributions matching '
                                       'the version for %s' % req)

        newest = list(applicable_versions.keys())[0]

        if Inf in applicable_versions:
            # We have an existing version, and it's the best version
            show_versions = [vers for vers in applicable_versions.keys()[1:]]
            logger.info('Installed version (%s) is most up-to-date '
                        '(past versions: %s)' %
                        (req.satisfied_by.version,
                         ', '.join(show_versions) or 'none'))
            raise BestVersionAlreadyInstalled

        if len(applicable_versions) > 1:
            logger.info('Using version %s (newest of versions: %s)' %
                        (newest, ', '.join(applicable_versions.keys())))

        return applicable_versions[newest]

    def _find_url_name(self, index_url, url_name, req):
        """
        Finds the true URL name of a package, when the given name isn't
        quite correct. This is usually used to implement case-insensitivity.
        """
        if not index_url.url.endswith('/'):
            # Vaguely part of the PyPI API... weird but true.
            ## FIXME: bad to modify this?
            index_url.url += '/'
        page = self._get_page(index_url, req)
        if page is None:
            logger.fatal('Cannot fetch index base URL %s' % index_url)
            return
        norm_name = normalize_name(req.url_name)
        for link in page.links:
            base = posixpath.basename(link.path.rstrip('/'))
            if norm_name == normalize_name(base):
                logger.notify('Real name of requirement %s is %s' % (url_name, base))
                return base
        return None

    def _get_pages(self, locations, req):
        """Yields (page, page_url) from the given locations, skipping
        locations that have errors, and adding download/homepage links"""
        pending_queue = Queue()
        for location in locations:
            pending_queue.put(location)
        done = []
        seen = set()
        threads = []
        for i in range(min(10, len(locations))):
            t = threading.Thread(target=self._get_queued_page, args=(req, pending_queue, done, seen))
            t.setDaemon(True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join()
        return done

    _log_lock = threading.Lock()

    def _get_queued_page(self, req, pending_queue, done, seen):
        while 1:
            try:
                location = pending_queue.get(False)
            except QueueEmpty:
                return
            if location in seen:
                continue
            seen.add(location)
            page = self._get_page(location, req)
            if page is None:
                continue
            done.append(page)
            for link in page.rel_links():
                pending_queue.put(link)

    def _sort_links(self, links):
        """
        Returns elements of links in order, non-egg links first,
        egg links second, while eliminating duplicates
        """
        eggs, no_eggs = [], []
        seen = set()
        for link in links:
            if link not in seen:
                seen.add(link)
                if link.egg_fragment:
                    eggs.append(link)
                else:
                    no_eggs.append(link)
        return no_eggs + eggs

    def _package_versions(self, links, search_name):
        for link in self._sort_links(links):
            for v in self._link_package_versions(link, search_name):
                yield v

    def _link_package_versions(self, link, search_name):
        """
        Return an iterable of triples (pkg_resources_version_key,
        link, python_version) that can be extracted from the given
        link.

        Meant to be overridden by subclasses, not called by clients.
        """
        if link.egg_fragment:
            egg_info = link.egg_fragment
        else:
            egg_info, ext = link.splitext()
            if not ext:
                if link not in self.logged_links:
                    logger.debug('Skipping link %s; not a file' % link)
                    self.logged_links.add(link)
                return []
            if egg_info.endswith('.tar'):
                # Special double-extension case:
                egg_info = egg_info[:-4]
                ext = '.tar' + ext
            if ext not in ('.tar.gz', '.tar.bz2', '.tar', '.tgz', '.zip'):
                if link not in self.logged_links:
                    logger.debug('Skipping link %s; unknown archive format: %s' % (link, ext))
                    self.logged_links.add(link)
                return []
            if "macosx10" in link.path and ext == '.zip':
                if link not in self.logged_links:
                    logger.debug('Skipping link %s; macosx10 one' % (link))
                    self.logged_links.add(link)
                return []
        version = self._egg_info_matches(egg_info, search_name, link)
        if version is None:
            logger.debug('Skipping link %s; wrong project name (not %s)' % (link, search_name))
            return []
        match = _py_version_re.search(version)
        if match:
            version = version[:match.start()]
            py_version = match.group(1)
            if py_version != sys.version[:3]:
                logger.debug('Skipping %s because Python version is incorrect' % link)
                return []
        logger.debug('Found link %s, version: %s' % (link, version))
        return [(pkg_resources.parse_version(version),
               link,
               version)]

    def _egg_info_matches(self, egg_info, search_name, link):
        match = _egg_info_re.search(egg_info)
        if not match:
            logger.debug('Could not parse version from link: %s' % link)
            return None
        name = match.group(0).lower()
        # To match the "safe" name that pkg_resources creates:
        name = name.replace('_', '-')
        if name.startswith(search_name.lower()):
            return match.group(0)[len(search_name):].lstrip('-')
        else:
            return None

    def _get_page(self, link, req):
        return HTMLPage.get_page(link, req, cache=self.cache)

    def _get_mirror_urls(self, mirrors=None):
        """
        Retrieves a list of URLs from the main mirror DNS entry
        unless a list of mirror URLs are passed.
        """
        if not mirrors:
            mirrors = find_mirrors(amount=10, start_with='b', prefer_fastest=False)
            mirrors = [mirror[0] for mirror in mirrors]

        mirror_urls = []
        for mirror_url in mirrors:
            # Make sure we have a valid URL
            if not mirror_url.startswith(("http://", "https://", "file://")):
                mirror_url = "http://%s" % mirror_url
            if not mirror_url.endswith("/simple"):
                mirror_url = "%s/simple/" % mirror_url
            if mirror_url not in mirror_urls:
                mirror_urls.append(mirror_url)

        return tuple(Link(url, is_mirror=True) for url in mirror_urls)


class PageCache(object):
    """Cache of HTML pages"""

    failure_limit = 3

    def __init__(self):
        self._failures = {}
        self._pages = {}
        self._archives = {}

    def too_many_failures(self, url):
        return self._failures.get(url, 0) >= self.failure_limit

    def get_page(self, url):
        return self._pages.get(url)

    def is_archive(self, url):
        return self._archives.get(url, False)

    def set_is_archive(self, url, value=True):
        self._archives[url] = value

    def add_page_failure(self, url, level):
        self._failures[url] = self._failures.get(url, 0)+level

    def add_page(self, urls, page):
        for url in urls:
            self._pages[url] = page


class HTMLPage(object):
    """Represents one page, along with its URL"""

    ## FIXME: these regexes are horrible hacks:
    _homepage_re = re.compile(r'<th>\s*home\s*page', re.I)
    _download_re = re.compile(r'<th>\s*download\s+url', re.I)
    ## These aren't so aweful:
    _rel_re = re.compile("""<[^>]*\srel\s*=\s*['"]?([^'">]+)[^>]*>""", re.I)
    _href_re = re.compile('href=(?:"([^"]*)"|\'([^\']*)\'|([^>\\s\\n]*))', re.I|re.S)
    _base_re = re.compile(r"""<base\s+href\s*=\s*['"]?([^'">]+)""", re.I)

    def __init__(self, content, url, headers=None):
        self.content = content
        self.url = url
        self.headers = headers

    def __str__(self):
        return self.url

    @classmethod
    def get_page(cls, link, req, cache=None, skip_archives=True):
        url = link.url
        url = url.split('#', 1)[0]
        if cache.too_many_failures(url):
            return None

        # Check for VCS schemes that do not support lookup as web pages.
        from pip.vcs import VcsSupport
        for scheme in VcsSupport.schemes:
            if url.lower().startswith(scheme) and url[len(scheme)] in '+:':
                logger.debug('Cannot look at %s URL %s' %
                             (scheme, link))
                return None

        if cache is not None:
            inst = cache.get_page(url)
            if inst is not None:
                return inst
        try:
            if skip_archives:
                if cache is not None:
                    if cache.is_archive(url):
                        return None
                filename = link.filename
                for bad_ext in ['.tar', '.tar.gz', '.tar.bz2', '.tgz', '.zip']:
                    if filename.endswith(bad_ext):
                        content_type = cls._get_content_type(url)
                        if content_type.lower().startswith('text/html'):
                            break
                        else:
                            logger.debug('Skipping page %s because of Content-Type: %s' % (link, content_type))
                            if cache is not None:
                                cache.set_is_archive(url)
                            return None
            logger.debug('Getting page %s' % url)

            # Tack index.html onto file:// URLs that point to directories
            parsed_url = urlparse.urlparse(url)
            scheme, netloc, path, params, query, fragment = parsed_url
            if scheme == 'file' and os.path.isdir(url2pathname(path)):
                # add trailing slash if not present so urljoin
                # doesn't trim final segment
                if not url.endswith('/'):
                    url += '/'
                url = urlparse.urljoin(url, 'index.html')
                logger.debug(' file: URL is directory, getting %s' % url)

            response = urlopen(url)
            inst = cls(u(response.content), response.url, response.headers)
        except (HTTPError, URLError, socket.timeout,
                socket.error, OSError, WindowsError,
                requests.RequestException):
            e = sys.exc_info()[1]
            desc = str(e)
            if isinstance(e, (socket.timeout, requests.Timeout)):
                log_meth = logger.info
                level = 1
                desc = 'timed out'
            elif isinstance(e, URLError):
                log_meth = logger.info
                if hasattr(e, 'reason') and isinstance(e.reason, (socket.timeout, requests.Timeout)):
                    desc = 'timed out'
                    level = 1
                else:
                    level = 2
            elif isinstance(e, HTTPError) and e.code == 404:
                ## FIXME: notify?
                log_meth = logger.info
                level = 2
            else:
                log_meth = logger.info
                level = 1
            log_meth('Could not fetch URL %s: %s' % (link, desc))
            log_meth('Will skip URL %s when looking for download links for %s' % (link.url, req))
            if cache is not None:
                cache.add_page_failure(url, level)
            return None
        if cache is not None:
            cache.add_page([url, response.url], inst)
        return inst

    @staticmethod
    def _get_content_type(url):
        """Get the Content-Type of the given url, using a HEAD request"""
        scheme, netloc, path, query, fragment = urlparse.urlsplit(url)
        if not scheme in ('http', 'https', 'ftp', 'ftps'):
            ## FIXME: some warning or something?
            ## assertion error?
            return ''
        response = urlopen(url, method='head')
        if hasattr(response, 'status_code') and response.status_code != 200 and scheme not in ('ftp', 'ftps'):
            ## FIXME: doesn't handle redirects
            return ''
        return response.headers.get('content-type', '')

    @property
    def base_url(self):
        if not hasattr(self, "_base_url"):
            match = self._base_re.search(self.content)
            if match:
                self._base_url = match.group(1)
            else:
                self._base_url = self.url
        return self._base_url

    @property
    def links(self):
        """
        Yields all links in the page
        """
        for match in self._href_re.finditer(self.content):
            url = match.group(1) or match.group(2) or match.group(3)
            url = self.clean_link(urlparse.urljoin(self.base_url, url))
            yield Link(url, self)

    def rel_links(self):
        for url in self.explicit_rel_links():
            yield url
        for url in self.scraped_rel_links():
            yield url

    def explicit_rel_links(self, rels=('homepage', 'download')):
        """
        Yields all links with the given relations
        """
        for match in self._rel_re.finditer(self.content):
            found_rels = match.group(1).lower().split()
            for rel in rels:
                if rel in found_rels:
                    break
            else:
                continue
            match = self._href_re.search(match.group(0))
            if not match:
                continue
            url = match.group(1) or match.group(2) or match.group(3)
            url = self.clean_link(urlparse.urljoin(self.base_url, url))
            yield Link(url, self)

    def scraped_rel_links(self):
        for regex in (self._homepage_re, self._download_re):
            match = regex.search(self.content)
            if not match:
                continue
            href_match = self._href_re.search(self.content, pos=match.end())
            if not href_match:
                continue
            url = href_match.group(1) or href_match.group(2) or href_match.group(3)
            if not url:
                continue
            url = self.clean_link(urlparse.urljoin(self.base_url, url))
            yield Link(url, self)

    def clean_link(self, url):
        """
        Makes sure a link is fully encoded.  That is, if a ' ' shows up in
        the link, it will be rewritten to %20 (while not over-quoting
        % or other characters).
        """
        def replacer(match):
            matched_group = match.group(0)
            return '%%%2x' % ord(matched_group)
        return _clean_re.sub(replacer, url.strip())


class Link(object):

    def __init__(self, url, comes_from=None, is_mirror=False, mirror_urls=None):
        self.url = url
        self.comes_from = comes_from
        self.is_mirror = is_mirror
        if mirror_urls is not None:
            for mirror in mirror_urls:
                if not isinstance(mirror, Link):
                    mirror = Link(mirror)
                if self.url.startswith(mirror.base_url):
                    self.is_mirror = True

    def __str__(self):
        if self.comes_from:
            return '%s (from %s)' % (self.url, self.comes_from)
        else:
            return self.url

    def __repr__(self):
        return '<Link %s>' % self

    def __eq__(self, other):
        return self.url == other.url

    def __hash__(self):
        return hash(self.url)

    @property
    def filename(self):
        url = self.url_fragment
        name = posixpath.basename(url)
        assert name, ('URL %r produced no filename' % url)
        return name

    @property
    def netloc(self):
        return urlparse.urlsplit(self.url)[1]

    @property
    def base_url(self):
        return urlparse.urlunsplit((self.scheme, self.netloc, '', '', ''))

    @property
    def scheme(self):
        return urlparse.urlsplit(self.url)[0]

    @property
    def path(self):
        return urlparse.urlsplit(self.url)[2]

    def splitext(self):
        return splitext(posixpath.basename(self.path.rstrip('/')))

    @property
    def url_fragment(self):
        url = self.url
        url = url.split('#', 1)[0]
        url = url.split('?', 1)[0]
        url = url.rstrip('/')
        return url

    @property
    def egg_fragment(self):
        match = _egg_fragment_re.search(self.url)
        if not match:
            return None
        return match.group(1)

    @property
    def md5_hash(self):
        match = _md5_re.search(self.url)
        if match:
            return match.group(1)
        return None

    @property
    def show_url(self):
        return posixpath.basename(self.url.split('#', 1)[0].split('?', 1)[0])

    def copy(self):
        return self.__class__(self.url, comes_from=self.comes_from,
                              is_mirror=self.is_mirror)


def get_requirement_from_url(url):
    """Get a requirement from the URL, if possible.  This looks for #egg
    in the URL"""
    link = Link(url)
    egg_info = link.egg_fragment
    if not egg_info:
        egg_info = splitext(link.filename)[0]
    return package_to_requirement(egg_info)


def package_to_requirement(package_name):
    """Translate a name like Foo-1.2 to Foo==1.3"""
    match = re.search(r'^(.*?)-(dev|\d.*)', package_name)
    if match:
        name = match.group(1)
        version = match.group(2)
    else:
        name = package_name
        version = ''
    if version:
        return '%s==%s' % (name, version)
    else:
        return name


def string_range(last):
    """
    Compute the range of string between "a" and last.

    This works for simple "a to z" lists, but also for "a to zz" lists.
    """
    for k in range(len(last)):
        for x in product(string.ascii_lowercase, repeat=k+1):
            result = ''.join(x)
            yield result
            if result == last:
                return
