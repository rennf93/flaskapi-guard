from unittest.mock import Mock

import pytest
from flask import Flask

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard


@pytest.fixture
def rate_limiting_decorator_app(security_config: SecurityConfig) -> Flask:
    """Create Flask app with rate limiting decorator integration."""
    app = Flask(__name__)
    app.config["TESTING"] = True

    security_config.trusted_proxies = ["127.0.0.1"]
    security_config.enable_penetration_detection = False

    decorator = SecurityDecorator(security_config)

    @app.route("/rate-limited")
    @decorator.rate_limit(requests=10, window=60)
    def rate_limited_endpoint() -> dict[str, str]:
        return {"message": "Rate limited endpoint"}

    @app.route("/geo-rate-limited")
    @decorator.geo_rate_limit({"US": (100, 3600), "CN": (10, 3600), "*": (50, 3600)})
    def geo_rate_limited_endpoint() -> dict[str, str]:
        return {"message": "Geo rate limited endpoint"}

    FlaskAPIGuard(app, config=security_config)
    app.extensions["flaskapi_guard"]["guard_decorator"] = decorator

    return app


@pytest.mark.parametrize(
    "route_path,expected_rate_limit,expected_window,description",
    [
        ("/rate-limited", 10, 60, "rate_limit decorator"),
    ],
)
def test_rate_limiting_decorators_applied(
    rate_limiting_decorator_app: Flask,
    route_path: str,
    expected_rate_limit: int,
    expected_window: int,
    description: str,
) -> None:
    """Test that rate limiting decorators are applied correctly."""
    endpoint_map = {
        "/rate-limited": "rate_limited_endpoint",
    }
    endpoint_name = endpoint_map[route_path]
    view_func = rate_limiting_decorator_app.view_functions[endpoint_name]

    assert hasattr(view_func, "_guard_route_id"), f"{description} should have route ID"

    guard_ext = rate_limiting_decorator_app.extensions["flaskapi_guard"]
    decorator = guard_ext["guard_decorator"]
    route_id = view_func._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None, f"{description} should have route config"
    assert route_config.rate_limit == expected_rate_limit, (
        f"{description} should have correct rate limit"
    )
    assert route_config.rate_limit_window == expected_window, (
        f"{description} should have correct rate limit window"
    )


def test_geo_rate_limit_decorator_applied(
    rate_limiting_decorator_app: Flask,
) -> None:
    """Test that geo rate limit decorator is applied correctly."""
    view_func = rate_limiting_decorator_app.view_functions["geo_rate_limited_endpoint"]

    assert hasattr(view_func, "_guard_route_id"), (
        "geo_rate_limit decorator should have route ID"
    )

    guard_ext = rate_limiting_decorator_app.extensions["flaskapi_guard"]
    decorator = guard_ext["guard_decorator"]
    route_id = view_func._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None, "geo_rate_limit should have route config"
    expected_limits = {"US": (100, 3600), "CN": (10, 3600), "*": (50, 3600)}
    assert route_config.geo_rate_limits == expected_limits, (
        "geo_rate_limit should store limits in geo_rate_limits"
    )


@pytest.mark.parametrize(
    "endpoint,expected_message,description",
    [
        ("/rate-limited", "Rate limited endpoint", "rate_limit endpoint"),
        ("/geo-rate-limited", "Geo rate limited endpoint", "geo_rate_limit endpoint"),
    ],
)
def test_rate_limiting_endpoints_response(
    rate_limiting_decorator_app: Flask,
    endpoint: str,
    expected_message: str,
    description: str,
) -> None:
    """Test calling rate limiting endpoints and their responses."""
    with rate_limiting_decorator_app.test_client() as client:
        headers = {"X-Forwarded-For": "8.8.8.8"}

        response = client.get(endpoint, headers=headers)

        assert response.status_code == 200, f"{description} should return 200"
        assert expected_message in response.data.decode(), (
            f"{description} should contain '{expected_message}'"
        )


def test_rate_limiting_decorators_unit(security_config: SecurityConfig) -> None:
    """Unit tests for rate limiting decorators."""
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    rate_limit_decorator = decorator.rate_limit(requests=5, window=120)
    decorated_func = rate_limit_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.rate_limit == 5
    assert route_config.rate_limit_window == 120

    mock_func2 = Mock()
    mock_func2.__name__ = mock_func2.__qualname__ = "test_func2"
    mock_func2.__module__ = "test_module"

    limits = {"US": (100, 3600), "EU": (50, 3600)}
    geo_rate_limit_decorator = decorator.geo_rate_limit(limits)
    decorated_func2 = geo_rate_limit_decorator(mock_func2)

    route_id2 = decorated_func2._guard_route_id
    route_config2 = decorator.get_route_config(route_id2)
    assert route_config2 is not None
    assert route_config2.geo_rate_limits == limits
