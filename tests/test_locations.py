import sys
import os
import os.path
from mock import patch
from nose.tools import assert_equal
from tests.test_pip import without_real_prefix


@patch('sys.prefix', '/path/to/fake/sys.prefix')
@patch('sys.real_prefix', '/path/to/fake/sys.real_prefix')
def test_build_prefix_and_src_prefix_should_use_sys_prefix_dir_if_under_virtualenv():
    # reload module because it was imported before the test method
    import pip.locations
    reload(pip.locations)

    from pip.locations import build_prefix, src_prefix

    expected_build_prefix = os.path.join(sys.prefix, 'build')
    expected_src_prefix = os.path.join(sys.prefix, 'src')

    assert_equal(expected_build_prefix, build_prefix)
    assert_equal(expected_src_prefix, src_prefix)


@without_real_prefix
def test_build_prefix_and_src_prefix_should_use_default_storage_dir_if_not_under_virtualenv():
    # reload module because it was imported before the test method
    import pip.locations
    reload(pip.locations)

    from pip.locations import build_prefix, src_prefix, default_storage_dir

    expected_build_prefix = os.path.join(default_storage_dir, 'build')
    expected_src_prefix = os.path.join(default_storage_dir, 'src')

    assert_equal(expected_build_prefix, build_prefix)
    assert_equal(expected_src_prefix, src_prefix)

