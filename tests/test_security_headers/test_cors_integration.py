from collections.abc import Generator

import pytest
from flask import Flask

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


def test_cors_headers_with_security_headers(reset_headers_manager: None) -> None:
    """Test CORS headers integration with security headers."""
    app = Flask(__name__)
    config = SecurityConfig(
        security_headers={"enabled": True},
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["Content-Type"],
        cors_allow_credentials=True,
        enable_redis=False,
        enable_agent=False,
        passive_mode=True,
    )
    FlaskAPIGuard(app, config=config)

    @app.route("/test")
    def test_endpoint() -> dict[str, str]:
        return {"message": "test"}

    with app.test_client() as client:
        response = client.get("/test", headers={"Origin": "https://example.com"})

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert "GET, POST" in response.headers["Access-Control-Allow-Methods"]
    assert response.headers["Access-Control-Allow-Credentials"] == "true"


def test_get_cors_headers_no_config() -> None:
    """Test CORS headers when not configured."""
    manager = SecurityHeadersManager()
    manager.cors_config = None

    headers = manager.get_cors_headers("https://example.com")

    assert headers == {}


def test_get_cors_headers_allowed_origin() -> None:
    """Test CORS headers with allowed origin."""
    manager = SecurityHeadersManager()
    manager.cors_config = {
        "origins": ["https://example.com", "https://app.example.com"],
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["Content-Type"],
        "allow_credentials": True,
    }

    headers = manager.get_cors_headers("https://example.com")

    assert headers["Access-Control-Allow-Origin"] == "https://example.com"
    assert "GET, POST" in headers["Access-Control-Allow-Methods"]
    assert "Content-Type" in headers["Access-Control-Allow-Headers"]
    assert headers["Access-Control-Allow-Credentials"] == "true"
    assert headers["Access-Control-Max-Age"] == "3600"


def test_get_cors_headers_wildcard() -> None:
    """Test CORS headers with wildcard origin."""
    manager = SecurityHeadersManager()
    manager.cors_config = {
        "origins": ["*"],
        "allow_methods": ["GET"],
        "allow_headers": ["*"],
    }

    headers = manager.get_cors_headers("https://any-origin.com")

    assert headers["Access-Control-Allow-Origin"] == "*"
    assert "GET" in headers["Access-Control-Allow-Methods"]


def test_get_cors_headers_disallowed_origin() -> None:
    """Test CORS headers with disallowed origin."""
    manager = SecurityHeadersManager()
    manager.cors_config = {
        "origins": ["https://example.com"],
        "allow_methods": ["GET", "POST"],
    }

    headers = manager.get_cors_headers("https://evil.com")

    assert headers == {}


def test_get_cors_headers_invalid_config() -> None:
    """Test CORS headers with invalid configuration."""
    manager = SecurityHeadersManager()

    manager.cors_config = {
        "origins": "https://example.com",
        "allow_methods": ["GET"],
    }

    headers = manager.get_cors_headers("https://example.com")
    assert headers == {}

    manager.cors_config = {
        "origins": ["https://example.com"],
        "allow_methods": "GET",
        "allow_headers": ["Content-Type"],
    }

    headers = manager.get_cors_headers("https://example.com")
    assert "GET, POST" in headers["Access-Control-Allow-Methods"]

    manager.cors_config = {
        "origins": ["https://example.com"],
        "allow_methods": ["GET"],
        "allow_headers": "Content-Type",
    }

    headers = manager.get_cors_headers("https://example.com")
    assert "*" in headers["Access-Control-Allow-Headers"]


def test_cors_wildcard_with_credentials_blocked() -> None:
    """Test that wildcard origin with credentials is blocked."""
    manager = SecurityHeadersManager()

    manager.configure(cors_origins=["*"], cors_allow_credentials=True)

    assert manager.cors_config is not None
    assert manager.cors_config["allow_credentials"] is False

    headers = manager.get_cors_headers("https://example.com")
    assert "Access-Control-Allow-Origin" in headers
    assert "Access-Control-Allow-Credentials" not in headers


def test_cors_wildcard_runtime_credential_blocking(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test runtime blocking when wildcard origin has credentials enabled."""
    manager = SecurityHeadersManager()

    manager.cors_config = {
        "origins": ["*"],
        "allow_credentials": True,
        "allow_methods": ["GET", "POST"],
        "allow_headers": ["*"],
    }

    headers = manager.get_cors_headers("https://example.com")

    assert headers == {}

    assert (
        "Credentials cannot be used with wildcard origin - blocking CORS" in caplog.text
    )


def test_cors_specific_origin_with_credentials_allowed() -> None:
    """Test that specific origins with credentials are allowed."""
    manager = SecurityHeadersManager()

    manager.configure(cors_origins=["https://trusted.com"], cors_allow_credentials=True)

    assert manager.cors_config is not None
    assert manager.cors_config["allow_credentials"] is True

    headers = manager.get_cors_headers("https://trusted.com")
    assert headers["Access-Control-Allow-Origin"] == "https://trusted.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"


def test_cors_multiple_origins_validation() -> None:
    """Test CORS with multiple specific origins."""
    manager = SecurityHeadersManager()

    manager.configure(
        cors_origins=["https://site1.com", "https://site2.com"],
        cors_allow_credentials=True,
    )

    headers = manager.get_cors_headers("https://site1.com")
    assert headers["Access-Control-Allow-Origin"] == "https://site1.com"
    assert headers["Access-Control-Allow-Credentials"] == "true"

    headers = manager.get_cors_headers("https://evil.com")
    assert headers == {}
