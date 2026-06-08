"""Baseline smoke test: the package imports and exposes a version."""

import delve


def test_package_imports_and_has_version() -> None:
    assert isinstance(delve.__version__, str)
    assert delve.__version__.count(".") >= 2
