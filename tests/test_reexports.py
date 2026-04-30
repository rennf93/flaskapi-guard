import pytest


def test_all_exports_importable() -> None:
    import flaskapi_guard

    for name in flaskapi_guard.__all__:
        assert hasattr(flaskapi_guard, name), f"{name} not found"


def test_extension_importable() -> None:
    from flaskapi_guard.extension import FlaskAPIGuard

    assert FlaskAPIGuard is not None


def test_adapters_importable() -> None:
    from flaskapi_guard.adapters import (
        FlaskGuardRequest,
        FlaskGuardResponse,
        FlaskResponseFactory,
    )

    assert FlaskGuardRequest is not None
    assert FlaskGuardResponse is not None
    assert FlaskResponseFactory is not None


def test_version_exported_matches_package_metadata() -> None:
    from importlib.metadata import version

    from flaskapi_guard import __version__

    assert __version__ == version("flaskapi_guard")
    assert __version__ != "0.0.0+unknown"


def test_version_falls_back_when_package_metadata_missing(
    monkeypatch: "pytest.MonkeyPatch",
) -> None:
    import importlib
    from importlib.metadata import PackageNotFoundError

    import flaskapi_guard

    def _raise(name: str) -> str:
        raise PackageNotFoundError(name)

    monkeypatch.setattr("importlib.metadata.version", _raise)
    reloaded = importlib.reload(flaskapi_guard)
    try:
        assert reloaded.__version__ == "0.0.0+unknown"
    finally:
        importlib.reload(flaskapi_guard)
