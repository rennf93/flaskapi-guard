from collections.abc import Generator

import pytest
from flask import Flask
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager

from flaskapi_guard import FlaskAPIGuard, SecurityConfig


@pytest.fixture(autouse=True)
def reset_rate_limit_singleton() -> Generator[None, None, None]:
    RateLimitManager._instance = None
    yield
    RateLimitManager._instance = None


@pytest.fixture
def app() -> Flask:
    app = Flask(__name__)
    config = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom"],
        cors_allow_credentials=True,
        cors_max_age=600,
        blacklist=["10.0.0.99"],
        trusted_proxies=["127.0.0.1"],
        enable_redis=False,
    )
    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def root() -> dict[str, str]:
        return {"ok": "yes"}

    return app


def test_preflight_allowed_for_legitimate_origin(app: Flask) -> None:
    client = app.test_client()
    response = client.options(
        "/",
        headers={
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example.com"


def test_preflight_blocked_for_banned_ip(app: Flask) -> None:
    client = app.test_client()
    response = client.options(
        "/",
        headers={
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "POST",
            "X-Forwarded-For": "10.0.0.99",
        },
    )
    assert response.status_code == 403


def test_normal_request_carries_cors_headers(app: Flask) -> None:
    client = app.test_client()
    response = client.get(
        "/",
        headers={"Origin": "https://app.example.com"},
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"


@pytest.fixture
def app_with_passthrough() -> Flask:
    app = Flask(__name__)
    config = SecurityConfig(
        enable_cors=True,
        cors_allow_origins=["https://app.example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["X-Custom"],
        cors_allow_credentials=True,
        cors_max_age=600,
        exclude_paths=["/health"],
        trusted_proxies=["127.0.0.1"],
        enable_redis=False,
    )
    FlaskAPIGuard(app, config=config)

    @app.route("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    return app


def test_preflight_to_passthrough_path_returns_cors_response(
    app_with_passthrough: Flask,
) -> None:
    client = app_with_passthrough.test_client()
    response = client.options(
        "/health",
        headers={
            "Origin": "https://app.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example.com"


def test_normal_request_to_passthrough_path_carries_cors_headers(
    app_with_passthrough: Flask,
) -> None:
    client = app_with_passthrough.test_client()
    response = client.get(
        "/health",
        headers={"Origin": "https://app.example.com"},
    )
    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.example.com"
    assert response.headers["Access-Control-Allow-Credentials"] == "true"
