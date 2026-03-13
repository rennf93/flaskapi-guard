from unittest.mock import MagicMock, Mock, patch

import pytest
from flask import Flask

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard


@pytest.fixture
def advanced_decorator_app(security_config: SecurityConfig) -> Flask:
    """Create Flask app with advanced decorator integration."""
    app = Flask(__name__)
    app.config["TESTING"] = True

    security_config.trusted_proxies = ["127.0.0.1"]
    security_config.enable_penetration_detection = False

    decorator = SecurityDecorator(security_config)

    @app.route("/business-hours")
    @decorator.time_window("09:00", "17:00", "UTC")
    def business_hours_endpoint() -> dict[str, str]:
        return {"message": "Business hours access"}

    @app.route("/night-hours")
    @decorator.time_window("22:00", "06:00", "UTC")
    def night_hours_endpoint() -> dict[str, str]:
        return {"message": "Night hours access"}

    @app.route("/suspicious-enabled")
    @decorator.suspicious_detection(enabled=True)
    def suspicious_enabled_endpoint() -> dict[str, str]:
        return {"message": "Suspicious detection enabled"}

    @app.route("/suspicious-disabled")
    @decorator.suspicious_detection(enabled=False)
    def suspicious_disabled_endpoint() -> dict[str, str]:
        return {"message": "Suspicious detection disabled"}

    @app.route("/form-honeypot", methods=["POST"])
    @decorator.honeypot_detection(["bot_trap", "hidden_field"])
    def form_honeypot_endpoint() -> dict[str, str]:
        return {"message": "Form submitted successfully"}

    @app.route("/json-honeypot", methods=["POST"])
    @decorator.honeypot_detection(["spam_check", "robot_field"])
    def json_honeypot_endpoint() -> dict[str, str]:
        return {"message": "JSON submitted successfully"}

    FlaskAPIGuard(app, config=security_config)
    app.extensions["flaskapi_guard"]["guard_decorator"] = decorator

    return app


@pytest.mark.parametrize(
    "endpoint,mock_hour,expected_status,description",
    [
        ("/business-hours", 12, 200, "Noon should be allowed during business hours"),
        ("/business-hours", 6, 403, "Early morning should be blocked"),
        ("/business-hours", 20, 403, "Evening should be blocked"),
        ("/night-hours", 23, 200, "Late night should be allowed"),
        ("/night-hours", 2, 200, "Early morning should be allowed"),
        ("/night-hours", 14, 403, "Afternoon should be blocked"),
    ],
)
def test_time_window_restrictions(
    advanced_decorator_app: Flask,
    endpoint: str,
    mock_hour: int,
    expected_status: int,
    description: str,
) -> None:
    """Test time window restrictions."""
    from datetime import datetime, timezone

    mock_datetime = datetime(2024, 1, 1, mock_hour, 0, 0, tzinfo=timezone.utc)

    with patch(
        "flaskapi_guard.core.checks.implementations.time_window.datetime"
    ) as mock_dt:
        mock_dt.now.return_value = mock_datetime
        mock_dt.side_effect = lambda *args, **kw: datetime(*args, **kw)

        with advanced_decorator_app.test_client() as client:
            response = client.get(
                endpoint,
                headers={"X-Forwarded-For": "127.0.0.1"},
            )
            assert response.status_code == expected_status, description


def test_suspicious_detection_enabled(advanced_decorator_app: Flask) -> None:
    """Test that suspicious detection decorator is applied correctly."""
    for endpoint_name, view_func in advanced_decorator_app.view_functions.items():
        if endpoint_name == "suspicious_enabled_endpoint":
            assert hasattr(view_func, "_guard_route_id")

            guard_ext = advanced_decorator_app.extensions["flaskapi_guard"]
            decorator = guard_ext["guard_decorator"]
            route_id = view_func._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None
            assert route_config.enable_suspicious_detection is True


def test_suspicious_detection_disabled(advanced_decorator_app: Flask) -> None:
    """Test that suspicious detection disabled decorator is applied correctly."""
    for endpoint_name, view_func in advanced_decorator_app.view_functions.items():
        if endpoint_name == "suspicious_disabled_endpoint":
            assert hasattr(view_func, "_guard_route_id")

            guard_ext = advanced_decorator_app.extensions["flaskapi_guard"]
            decorator = guard_ext["guard_decorator"]
            route_id = view_func._guard_route_id
            route_config = decorator.get_route_config(route_id)

            assert route_config is not None
            assert route_config.enable_suspicious_detection is False


def test_suspicious_endpoints_response(advanced_decorator_app: Flask) -> None:
    """Test calling suspicious endpoints and their responses."""
    with advanced_decorator_app.test_client() as client:
        response = client.get(
            "/suspicious-enabled", headers={"X-Forwarded-For": "8.8.8.8"}
        )
        assert response.status_code == 200
        assert response.get_json()["message"] == "Suspicious detection enabled"

        response = client.get(
            "/suspicious-disabled", headers={"X-Forwarded-For": "8.8.8.8"}
        )
        assert response.status_code == 200
        assert response.get_json()["message"] == "Suspicious detection disabled"


@pytest.mark.parametrize(
    "endpoint,expected_fields,description",
    [
        (
            "/form-honeypot",
            ["bot_trap", "hidden_field"],
            "Form honeypot should have trap fields configured",
        ),
        (
            "/json-honeypot",
            ["spam_check", "robot_field"],
            "JSON honeypot should have trap fields configured",
        ),
    ],
)
def test_honeypot_detection_configuration(
    advanced_decorator_app: Flask,
    endpoint: str,
    expected_fields: list[str],
    description: str,
) -> None:
    """Test that honeypot detection decorators are configured correctly."""
    endpoint_map = {
        "/form-honeypot": "form_honeypot_endpoint",
        "/json-honeypot": "json_honeypot_endpoint",
    }
    endpoint_name = endpoint_map[endpoint]
    view_func = advanced_decorator_app.view_functions[endpoint_name]

    assert hasattr(view_func, "_guard_route_id")

    guard_ext = advanced_decorator_app.extensions["flaskapi_guard"]
    decorator = guard_ext["guard_decorator"]
    route_id = view_func._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None
    assert len(route_config.custom_validators) == 1, "Should have one custom validator"

    validator = route_config.custom_validators[0]
    assert hasattr(validator, "__code__")
    assert "trap_fields" in validator.__code__.co_freevars


def test_honeypot_detection_basic_functionality(
    advanced_decorator_app: Flask,
) -> None:
    """Test basic honeypot detection functionality - clean requests should pass."""
    with advanced_decorator_app.test_client() as client:
        response = client.post(
            "/form-honeypot",
            data={"name": "John", "email": "john@example.com"},
            headers={
                "X-Forwarded-For": "127.0.0.1",
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert response.status_code == 200

        response = client.post(
            "/json-honeypot",
            json={"name": "Jane", "message": "Hello"},
            headers={"X-Forwarded-For": "127.0.0.1"},
        )
        assert response.status_code == 200


def test_honeypot_form_detection(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["bot_trap"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": (
        "application/x-www-form-urlencoded" if key == "content-type" else default
    )
    mock_request.form = {"bot_trap": "filled"}

    result = validator(mock_request)
    assert result.status_code == 403


def test_honeypot_json_exception(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["spam_check"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": (
        "application/json" if key == "content-type" else default
    )
    mock_request.get_json.side_effect = Exception("JSON error")

    result = validator(mock_request)
    assert result is None


def test_honeypot_json_detection(security_config: SecurityConfig) -> None:
    decorator = SecurityDecorator(security_config)
    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    honeypot_decorator = decorator.honeypot_detection(["spam_check"])
    decorated_func = honeypot_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    validator = route_config.custom_validators[0]

    mock_request = MagicMock()
    mock_request.method = "POST"
    mock_request.headers.get = lambda key, default="": (
        "application/json" if key == "content-type" else default
    )
    mock_request.get_json.return_value = {"spam_check": "filled"}

    result = validator(mock_request)
    assert result.status_code == 403
