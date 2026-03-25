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
