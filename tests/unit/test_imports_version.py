"""Unit tests for package imports and reported version."""

import gitforensics
import gitforensics.cli
import gitforensics.detectors
import gitforensics.engine
import gitforensics.errors
import gitforensics.git
import gitforensics.github
import gitforensics.models
import gitforensics.reporting
import gitforensics.scoring


def test_package_version() -> None:
    """Test package version string."""
    assert gitforensics.__version__ == "0.1.0"


def test_package_imports() -> None:
    """Test submodules are importable."""
    assert gitforensics.cli is not None
    assert gitforensics.models is not None
    assert gitforensics.errors is not None
    assert gitforensics.git is not None
    assert gitforensics.github is not None
    assert gitforensics.engine is not None
    assert gitforensics.scoring is not None
    assert gitforensics.reporting is not None
    assert gitforensics.detectors is not None
