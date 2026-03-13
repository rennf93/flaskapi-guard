from collections.abc import Generator

import pytest
from flask import Flask

from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.security_headers_handler import security_headers_manager
from flaskapi_guard.models import SecurityConfig


@pytest.fixture
def reset_headers_manager() -> Generator[None, None, None]:
    """Reset security headers manager state before each test."""
    security_headers_manager.reset()
    yield
    security_headers_manager.reset()


def test_security_headers_none_config(reset_headers_manager: None) -> None:
    """Test when config.security_headers is None."""
    app = Flask(__name__)

    config = SecurityConfig(
        security_headers=None,
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/test")
    def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    with app.test_client() as client:
        response = client.get("/test")

    assert security_headers_manager.enabled is False
    assert response.status_code == 200

    assert "X-Content-Type-Options" not in response.headers
    assert "X-Frame-Options" not in response.headers
    assert "X-XSS-Protection" not in response.headers
