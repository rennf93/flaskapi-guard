from collections.abc import Generator
from typing import Any

import pytest
from flask import Flask, Response

from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)
from flaskapi_guard.models import SecurityConfig


@pytest.fixture
def reset_headers_manager() -> Generator[None, None, None]:
    """Reset security headers manager state before each test."""
    security_headers_manager.reset()
    yield
    security_headers_manager.reset()


def test_default_security_headers(reset_headers_manager: None) -> None:
    """Test that default security headers are applied."""
    app = Flask(__name__)
    config = SecurityConfig(
        security_headers={"enabled": True},
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

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.headers["X-XSS-Protection"] == "1; mode=block"
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert "Permissions-Policy" in response.headers


def test_custom_csp_header(reset_headers_manager: None) -> None:
    """Test Content Security Policy header configuration."""
    app = Flask(__name__)
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "csp": {
                "default-src": ["'self'"],
                "script-src": ["'self'", "https://trusted.cdn.com"],
                "style-src": ["'self'", "'unsafe-inline'"],
            },
        },
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

    assert response.status_code == 200
    csp = response.headers["Content-Security-Policy"]
    assert "default-src 'self'" in csp
    assert "script-src 'self' https://trusted.cdn.com" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp


def test_hsts_header(reset_headers_manager: None) -> None:
    """Test HTTP Strict Transport Security header."""
    app = Flask(__name__)
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "hsts": {
                "max_age": 31536000,
                "include_subdomains": True,
                "preload": True,
            },
        },
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

    assert response.status_code == 200
    hsts = response.headers["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts
    assert "includeSubDomains" in hsts
    assert "preload" in hsts


def test_custom_headers(reset_headers_manager: None) -> None:
    """Test custom security headers."""
    app = Flask(__name__)
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "custom": {
                "X-Custom-Header": "custom-value",
                "X-Another-Header": "another-value",
            },
        },
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

    assert response.status_code == 200
    assert response.headers["X-Custom-Header"] == "custom-value"
    assert response.headers["X-Another-Header"] == "another-value"


def test_frame_options_deny(reset_headers_manager: None) -> None:
    """Test X-Frame-Options with DENY value."""
    app = Flask(__name__)
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "frame_options": "DENY",
        },
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

    assert response.status_code == 200
    assert response.headers["X-Frame-Options"] == "DENY"


def test_custom_referrer_policy(reset_headers_manager: None) -> None:
    """Test custom Referrer-Policy header."""
    app = Flask(__name__)
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "referrer_policy": "no-referrer",
        },
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

    assert response.status_code == 200
    assert response.headers["Referrer-Policy"] == "no-referrer"


def test_permissions_policy_disabled(reset_headers_manager: None) -> None:
    """Test disabling Permissions-Policy header."""
    app = Flask(__name__)
    config = SecurityConfig(
        security_headers={
            "enabled": True,
            "permissions_policy": None,
        },
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

    assert response.status_code == 200
    assert "Permissions-Policy" not in response.headers


def test_security_headers_disabled(reset_headers_manager: None) -> None:
    """Test that security headers are not added when disabled."""
    app = Flask(__name__)
    config = SecurityConfig(
        security_headers={"enabled": False},
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

    assert response.status_code == 200
    assert "X-Content-Type-Options" not in response.headers
    assert "X-Frame-Options" not in response.headers


def test_security_headers_on_error_response(reset_headers_manager: None) -> None:
    """Test that security headers are added to error responses."""
    app = Flask(__name__)

    def custom_check(request: Any) -> Any:
        return Response("Forbidden by custom check", status=403)

    config = SecurityConfig(
        security_headers={"enabled": True},
        custom_request_check=custom_check,
        enable_redis=False,
        enable_agent=False,
        passive_mode=False,
    )
    FlaskAPIGuard(app, config=config)

    @app.route("/test")
    def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    with app.test_client() as client:
        response = client.get("/test")

    assert response.status_code == 403
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "SAMEORIGIN"
    assert response.text == "Forbidden by custom check"


def test_security_headers_manager_singleton() -> None:
    """Test that SecurityHeadersManager is a singleton."""
    manager1 = SecurityHeadersManager()
    manager2 = SecurityHeadersManager()

    assert manager1 is manager2
    assert manager1 is security_headers_manager


def test_headers_caching() -> None:
    """Test that headers are cached properly."""
    manager = SecurityHeadersManager()
    manager.configure(
        enabled=True,
        csp={"default-src": ["'self'"]},
    )

    headers1 = manager.get_headers("/test")
    assert "Content-Security-Policy" in headers1

    headers2 = manager.get_headers("/test")
    assert headers1 == headers2

    headers3 = manager.get_headers("/different")
    assert "Content-Security-Policy" in headers3


def test_new_default_security_headers() -> None:
    """Test that new security headers are in defaults."""
    manager = SecurityHeadersManager()

    headers = manager.get_headers()

    assert "X-Permitted-Cross-Domain-Policies" in headers
    assert headers["X-Permitted-Cross-Domain-Policies"] == "none"

    assert "X-Download-Options" in headers
    assert headers["X-Download-Options"] == "noopen"

    assert "Cross-Origin-Embedder-Policy" in headers
    assert headers["Cross-Origin-Embedder-Policy"] == "require-corp"

    assert "Cross-Origin-Opener-Policy" in headers
    assert headers["Cross-Origin-Opener-Policy"] == "same-origin"

    assert "Cross-Origin-Resource-Policy" in headers
    assert headers["Cross-Origin-Resource-Policy"] == "same-origin"


def test_original_headers_still_present() -> None:
    """Test that original security headers are still included."""
    manager = SecurityHeadersManager()

    headers = manager.get_headers()

    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["X-Frame-Options"] == "SAMEORIGIN"
    assert headers["X-XSS-Protection"] == "1; mode=block"
    assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert headers["Permissions-Policy"] == "geolocation=(), microphone=(), camera=()"
