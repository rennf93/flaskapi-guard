from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from flask import Flask, Response

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.behavior_handler import BehaviorRule
from flaskapi_guard.handlers.ratelimit_handler import RateLimitManager


def test_set_decorator_handler() -> None:
    """Test set_decorator_handler method."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    decorator = SecurityDecorator(config)
    guard.set_decorator_handler(decorator)

    assert guard.guard_decorator is decorator

    guard.set_decorator_handler(None)
    assert guard.guard_decorator is None


def test_get_endpoint_id_with_route() -> None:
    """Test _get_endpoint_id method with route in scope."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    mock_request = Mock()
    mock_request.endpoint = "test_endpoint"
    mock_request.method = "GET"
    mock_request.path = "/test"

    mock_view_func = Mock()
    mock_view_func.__module__ = "test_module"
    mock_view_func.__qualname__ = "test_function"

    with app.test_request_context("/test"):
        app.view_functions["test_endpoint"] = mock_view_func
        endpoint_id = guard._get_endpoint_id(mock_request)
        assert endpoint_id == "test_module.test_function"

    mock_request.endpoint = "nonexistent"
    with app.test_request_context("/test"):
        endpoint_id = guard._get_endpoint_id(mock_request)
        assert endpoint_id == "GET:/test"


def test_should_bypass_check() -> None:
    """Test should_bypass_check method (via route_resolver)."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    assert not guard.route_resolver.should_bypass_check("ip", None)

    mock_route_config = Mock()
    mock_route_config.bypassed_checks = {"ip"}
    assert guard.route_resolver.should_bypass_check("ip", mock_route_config)
    assert not guard.route_resolver.should_bypass_check("rate_limit", mock_route_config)

    mock_route_config.bypassed_checks = {"all"}
    assert guard.route_resolver.should_bypass_check("ip", mock_route_config)
    assert guard.route_resolver.should_bypass_check("rate_limit", mock_route_config)


def test_check_route_ip_access_invalid_ip() -> None:
    """Test _check_route_ip_access with invalid IP."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = None
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = guard._check_route_ip_access("invalid_ip", mock_route_config)
    assert result is False


def test_check_route_ip_access_blacklist() -> None:
    """Test _check_route_ip_access with IP blacklist."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = ["192.168.1.100", "10.0.0.0/8"]
    mock_route_config.ip_whitelist = None
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = guard._check_route_ip_access("192.168.1.100", mock_route_config)
    assert result is False

    result = guard._check_route_ip_access("10.0.0.1", mock_route_config)
    assert result is False

    result = guard._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is None


def test_check_route_ip_access_whitelist() -> None:
    """Test _check_route_ip_access with IP whitelist."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = ["192.168.1.100", "10.0.0.0/8"]
    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = None

    result = guard._check_route_ip_access("192.168.1.100", mock_route_config)
    assert result is True

    result = guard._check_route_ip_access("10.0.0.1", mock_route_config)
    assert result is True

    result = guard._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False


def test_check_route_ip_access_countries() -> None:
    """Test _check_route_ip_access with country restrictions."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    mock_geo_handler = Mock()
    guard.geo_ip_handler = mock_geo_handler

    mock_route_config = Mock()
    mock_route_config.ip_blacklist = None
    mock_route_config.ip_whitelist = None

    mock_route_config.blocked_countries = ["XX"]
    mock_route_config.whitelist_countries = None
    mock_geo_handler.get_country.return_value = "XX"

    result = guard._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False

    mock_route_config.blocked_countries = None
    mock_route_config.whitelist_countries = ["US"]
    mock_geo_handler.get_country.return_value = "US"

    result = guard._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is True

    mock_geo_handler.get_country.return_value = "XX"
    result = guard._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False

    mock_geo_handler.get_country.return_value = None
    result = guard._check_route_ip_access("8.8.8.8", mock_route_config)
    assert result is False


def test_check_user_agent_allowed() -> None:
    """Test _check_user_agent_allowed method."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    mock_route_config = Mock()
    mock_route_config.blocked_user_agents = [r"badbot"]

    with patch("flaskapi_guard.utils.is_user_agent_allowed", return_value=True):
        result = guard._check_user_agent_allowed("badbot", mock_route_config)
        assert result is False

        result = guard._check_user_agent_allowed("goodbot", mock_route_config)
        assert result is True

    with patch(
        "flaskapi_guard.utils.is_user_agent_allowed", return_value=False
    ) as mock_global:
        result = guard._check_user_agent_allowed("somebot", None)
        assert result is False
        mock_global.assert_called_once()


def test_time_window_error_handling() -> None:
    """Test time window check error handling."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    invalid_time_restrictions = {"invalid": "data"}

    with patch.object(guard.validator.context.logger, "error") as mock_error:
        result = guard._check_time_window(invalid_time_restrictions)
        assert result is True
        mock_error.assert_called_once()


def test_time_window_overnight() -> None:
    """Test time window check with overnight window."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    time_restrictions = {"start": "22:00", "end": "06:00"}

    with patch("flaskapi_guard.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "23:00"
        result = guard._check_time_window(time_restrictions)
        assert result is True

    with patch("flaskapi_guard.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "05:00"
        result = guard._check_time_window(time_restrictions)
        assert result is True

    with patch("flaskapi_guard.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "12:00"
        result = guard._check_time_window(time_restrictions)
        assert result is False


def test_time_window_normal() -> None:
    """Test time window check with normal window."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    time_restrictions = {"start": "09:00", "end": "17:00"}

    with patch("flaskapi_guard.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "12:00"
        result = guard._check_time_window(time_restrictions)
        assert result is True

    with patch("flaskapi_guard.core.validation.validator.datetime") as mock_datetime:
        mock_datetime.now.return_value.strftime.return_value = "20:00"
        result = guard._check_time_window(time_restrictions)
        assert result is False


def test_behavioral_rules_without_guard_decorator() -> None:
    """Test behavioral rule processing when guard_decorator is None."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    guard.guard_decorator = None

    mock_request = Mock()
    mock_route_config = Mock()
    mock_route_config.behavior_rules = [BehaviorRule("usage", threshold=5, window=3600)]

    guard._process_decorator_usage_rules(mock_request, "127.0.0.1", mock_route_config)
    guard._process_decorator_return_rules(
        mock_request, Mock(), "127.0.0.1", mock_route_config
    )


def test_behavioral_usage_rules_with_decorator() -> None:
    """Test behavioral usage rule processing with guard decorator."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    mock_guard_decorator = Mock()
    mock_behavior_tracker = Mock()
    mock_guard_decorator.behavior_tracker = mock_behavior_tracker
    guard.guard_decorator = mock_guard_decorator

    mock_request = Mock()
    mock_request.endpoint = "test_endpoint"
    mock_request.method = "GET"
    mock_request.path = "/test"

    mock_route_config = Mock()
    usage_rule = BehaviorRule("usage", threshold=5, window=3600)
    mock_route_config.behavior_rules = [usage_rule]

    def mock_track_usage(*args: Any, **kwargs: Any) -> bool:
        return False  # pragma: no cover

    mock_behavior_tracker.track_endpoint_usage = mock_track_usage

    guard._process_decorator_usage_rules(mock_request, "127.0.0.1", mock_route_config)
    mock_behavior_tracker.apply_action.assert_not_called()

    def mock_track_usage_exceeded(*args: Any, **kwargs: Any) -> bool:
        return True  # pragma: no cover

    def mock_apply_action(*args: Any, **kwargs: Any) -> None:
        return None  # pragma: no cover

    mock_behavior_tracker.track_endpoint_usage = mock_track_usage_exceeded
    mock_behavior_tracker.apply_action = mock_apply_action

    guard._process_decorator_usage_rules(mock_request, "127.0.0.1", mock_route_config)


def test_behavioral_return_rules_with_decorator() -> None:
    """Test behavioral return rule processing with guard decorator."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    mock_guard_decorator = Mock()
    mock_behavior_tracker = Mock()
    mock_guard_decorator.behavior_tracker = mock_behavior_tracker
    guard.guard_decorator = mock_guard_decorator

    mock_request = Mock()
    mock_request.endpoint = "test_endpoint"
    mock_request.method = "GET"
    mock_request.path = "/test"

    mock_response = Mock()
    mock_route_config = Mock()
    return_rule = BehaviorRule(
        "return_pattern", threshold=3, window=3600, pattern="win"
    )
    mock_route_config.behavior_rules = [return_rule]

    def mock_track_pattern(*args: Any, **kwargs: Any) -> bool:
        return False  # pragma: no cover

    mock_behavior_tracker.track_return_pattern = mock_track_pattern

    guard._process_decorator_return_rules(
        mock_request, mock_response, "127.0.0.1", mock_route_config
    )
    mock_behavior_tracker.apply_action.assert_not_called()

    def mock_track_pattern_detected(*args: Any, **kwargs: Any) -> bool:
        return True  # pragma: no cover

    def mock_apply_action(*args: Any, **kwargs: Any) -> None:
        return None  # pragma: no cover

    mock_behavior_tracker.track_return_pattern = mock_track_pattern_detected
    mock_behavior_tracker.apply_action = mock_apply_action

    guard._process_decorator_return_rules(
        mock_request, mock_response, "127.0.0.1", mock_route_config
    )


def test_get_route_decorator_config_no_app() -> None:
    """Test get_route_config (via route_resolver) when no decorator available."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    with app.test_request_context("/test"):
        mock_request = Mock()
        mock_request.endpoint = None

        result = guard.route_resolver.get_route_config(mock_request)
        assert result is None


def test_get_route_decorator_config_no_guard_decorator() -> None:
    """Test get_route_config (via route_resolver) when no guard decorator available."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    guard.set_decorator_handler(None)

    with app.test_request_context("/test"):
        mock_request = Mock()
        mock_request.endpoint = "test"

        result = guard.route_resolver.get_route_config(mock_request)
        assert result is None


def test_get_route_decorator_config_fallback_to_guard_decorator() -> None:
    """Test get_route_config falls back to guard_decorator."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    decorator = SecurityDecorator(config)
    guard.set_decorator_handler(decorator)

    with app.test_request_context("/test"):
        mock_request = Mock()
        mock_request.endpoint = "nonexistent"

        result = guard.route_resolver.get_route_config(mock_request)
        assert result is None


def test_get_route_decorator_config_no_matching_route() -> None:
    """Test get_route_config (via route_resolver) when no matching route is found."""
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    decorator = SecurityDecorator(config)
    guard.set_decorator_handler(decorator)

    with app.test_request_context("/nonexistent"):
        mock_request = Mock()
        mock_request.endpoint = "nonexistent"

        result = guard.route_resolver.get_route_config(mock_request)
        assert result is None


def test_bypass_all_security_checks() -> None:
    """Test bypassing all security checks when 'all' is in bypassed_checks."""
    app = Flask(__name__)
    config = SecurityConfig()

    mock_route_config = RouteConfig()
    mock_route_config.bypassed_checks = {"all"}

    decorator = SecurityDecorator(config)

    @app.route("/test")
    @decorator.bypass(["all"])
    def test_endpoint() -> str:
        return "bypassed"

    FlaskAPIGuard(app, config=config)
    app.extensions["flaskapi_guard"]["guard_decorator"] = decorator

    with app.test_client() as client:
        response = client.get(
            "/test",
            headers={"X-Forwarded-For": "127.0.0.1"},
        )
        assert response.status_code == 200


def test_bypass_all_security_checks_with_custom_modifier() -> None:
    """Test bypassing all security checks with custom response modifier."""
    app = Flask(__name__)

    def custom_modifier(response: Response) -> Response:
        modified_response = Response("custom modified", status=202)
        return modified_response

    config = SecurityConfig(custom_response_modifier=custom_modifier)

    decorator = SecurityDecorator(config)

    @app.route("/test")
    @decorator.bypass(["all"])
    def test_endpoint() -> str:
        return "bypassed"

    FlaskAPIGuard(app, config=config)
    app.extensions["flaskapi_guard"]["guard_decorator"] = decorator

    with app.test_client() as client:
        response = client.get(
            "/test",
            headers={"X-Forwarded-For": "127.0.0.1"},
        )
        assert response.status_code == 202
        assert response.data == b"custom modified"


@pytest.mark.parametrize(
    "test_case,expected_status,description",
    [
        (
            {"max_request_size": 100, "headers": {"content-length": "200"}},
            413,
            "Test route-specific request size limits",
        ),
        (
            {
                "allowed_content_types": ["application/json"],
                "headers": {"content-type": "text/plain"},
            },
            415,
            "Test route-specific content type filtering",
        ),
        (
            {
                "custom_validators": [
                    MagicMock(
                        return_value=Response("Custom validation failed", status=400)
                    )
                ],
                "headers": {},
            },
            400,
            "Test custom validator returning a Response object",
        ),
        (
            {"custom_validators": [MagicMock(return_value=None)], "headers": {}},
            200,
            "Test custom validator returning None (allows request to proceed)",
        ),
    ],
)
def test_route_specific_extension_validations(
    test_case: dict, expected_status: int, description: str
) -> None:
    """Parametrized test for route-specific extension validation features."""
    app = Flask(__name__)
    config = SecurityConfig()
    config.enable_penetration_detection = False

    decorator = SecurityDecorator(config)

    route_config = RouteConfig()
    for attr, value in test_case.items():
        if attr != "headers":
            setattr(route_config, attr, value)

    @app.route("/test", methods=["GET", "POST"])
    def test_endpoint() -> str:
        return "ok"

    route_id = f"{test_endpoint.__module__}.{test_endpoint.__qualname__}"
    decorator._route_configs[route_id] = route_config
    test_endpoint._guard_route_id = route_id
    app.view_functions["test_endpoint"] = test_endpoint

    FlaskAPIGuard(app, config=config)
    app.extensions["flaskapi_guard"]["guard_decorator"] = decorator

    with app.test_client() as client:
        headers = {"X-Forwarded-For": "127.0.0.1"}
        headers.update(test_case["headers"])

        use_post = "max_request_size" in test_case
        with patch(
            "flaskapi_guard.core.checks.helpers.detect_penetration_attempt",
            return_value=(False, ""),
        ):
            if use_post:
                body = b"x" * 200
                response = client.post("/test", headers=headers, data=body)
            else:
                response = client.get("/test", headers=headers)
            assert response.status_code == expected_status


def test_route_specific_rate_limit_with_redis() -> None:
    """Test route-specific rate limiting with Redis initialization."""
    app = Flask(__name__)
    config = SecurityConfig(enable_redis=True, redis_url="redis://localhost:6379")
    config.enable_penetration_detection = False

    decorator = SecurityDecorator(config)

    route_config = RouteConfig()
    route_config.rate_limit = 5
    route_config.rate_limit_window = 60

    @app.route("/test")
    def test_endpoint() -> str:
        return "ok"

    route_id = f"{test_endpoint.__module__}.{test_endpoint.__qualname__}"
    decorator._route_configs[route_id] = route_config
    test_endpoint._guard_route_id = route_id
    app.view_functions["test_endpoint"] = test_endpoint

    guard = FlaskAPIGuard(app, config=config)
    app.extensions["flaskapi_guard"]["guard_decorator"] = decorator

    mock_redis_handler = Mock()
    guard.redis_handler = mock_redis_handler

    with app.test_client() as client:
        with patch.object(RateLimitManager, "initialize_redis") as mock_init_redis:
            with patch.object(RateLimitManager, "check_rate_limit", return_value=None):
                with patch(
                    "flaskapi_guard.core.checks.helpers.detect_penetration_attempt",
                    return_value=(False, ""),
                ):
                    client.get(
                        "/test",
                        headers={"X-Forwarded-For": "127.0.0.1"},
                    )
                    mock_init_redis.assert_called_once_with(mock_redis_handler)
