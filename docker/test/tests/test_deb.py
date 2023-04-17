
import pytest

pytestmark = pytest.mark.deb


def test_buildpackage(deb_package_path):
    """Test that the package can be built."""
    assert deb_package_path.exists(), f'Package {deb_package_path} not found'
