import os
import os.path
from mock import patch
from nose.tools import assert_equal
from tests.test_pip import without_real_prefix


@patch('os.access')
@without_real_prefix
def test_should_use_os_access_to_check_write_permission_to_build_dir_and_src_dir(access_mock):
    """
    Ensure `os.access` is called to see if user can write in the current dir
    """
    # reload module because it was imported before the test method
    import pip.locations
    reload(pip.locations)

    access_mock.assert_called_with(os.getcwd(), os.W_OK)


@patch('tempfile.mkdtemp')
@patch('os.access')
@without_real_prefix
def test_build_prefix_and_src_should_be_in_a_temp_build_dir_if_cwd_is_not_writable(access_mock, mkdtemp_mock):
    """
    Test `build_prefix` and `src_prefix` are in a temporary directory
    when current working dir is not writable
    """
    access_mock.return_value = False
    mkdtemp_mock.return_value = temp_dir = '/path/to/temp/dir'

    # reload module because it was imported before the test method
    import pip.locations
    reload(pip.locations)
    from pip.locations import build_prefix, src_prefix

    assert_equal(build_prefix, os.path.join(temp_dir, 'build'))
    assert_equal(src_prefix, os.path.join(temp_dir, 'src'))


@patch('os.access')
@without_real_prefix
def test_build_prefix_and_src_should_be_in_cwd_if_there_is_permission_to_write_in_it(access_mock):
    access_mock.return_value = True

    # reload module because it was imported before the test method
    import pip.locations
    reload(pip.locations)
    from pip.locations import build_prefix, src_prefix

    assert_equal(build_prefix, os.path.join(os.getcwd(), 'build'))
    assert_equal(src_prefix, os.path.join(os.getcwd(), 'src'))

