import logging
import os
import time
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest
from flask import Flask, Response
from redis.exceptions import RedisError

from flaskapi_guard.decorators.base import BaseSecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.cloud_handler import cloud_handler
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager
from flaskapi_guard.handlers.ratelimit_handler import rate_limit_handler
from flaskapi_guard.handlers.redis_handler import redis_handler
from flaskapi_guard.models import SecurityConfig

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


def test_rate_limiting() -> None:
    """
    Test the rate limiting functionality
    of the FlaskAPIGuard extension.
    """
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        rate_limit=2,
        rate_limit_window=1,
        enable_rate_limiting=True,
    )
    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        response = client.get("/")
        assert response.status_code == 200

        response = client.get("/")
        assert response.status_code == 200

        response = client.get("/")
        assert response.status_code == 429

        handler = rate_limit_handler(config)
        handler.reset()

        response = client.get("/")
        assert response.status_code == 200


def test_ip_whitelist_blacklist() -> None:
    """
    Test the IP whitelist/blacklist
    functionality of the FlaskAPIGuard extension.
    """
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        enable_penetration_detection=False,
        trusted_proxies=["127.0.0.1"],
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        response = client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert response.status_code == 200

        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == 403

        response = client.get("/", headers={"X-Forwarded-For": "10.0.0.1"})
        assert response.status_code == 403


def test_user_agent_filtering() -> None:
    """
    Test the user agent filtering
    functionality of the FlaskAPIGuard extension.
    """
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        blocked_user_agents=[r"badbot"],
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        response = client.get("/", headers={"User-Agent": "badbot"})
        assert response.status_code == 403

        response = client.get("/", headers={"User-Agent": "goodbot"})
        assert response.status_code == 200


def test_rate_limiting_multiple_ips(reset_state: None) -> None:
    """
    Test the rate limiting functionality
    of the FlaskAPIGuard extension with multiple IPs.
    """
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        rate_limit=2,
        rate_limit_window=1,
        enable_rate_limiting=True,
        whitelist=[],
        blacklist=[],
        enable_penetration_detection=False,
        trusted_proxies=["127.0.0.1"],
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        for i in range(1, 4):
            response = client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
            assert response.status_code == (200 if i <= 2 else 429)

        for i in range(1, 4):
            response = client.get("/", headers={"X-Forwarded-For": "192.168.1.5"})
            assert response.status_code == (200 if i <= 2 else 429)

        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.1"})
        assert response.status_code == 429

        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.5"})
        assert response.status_code == 429


def test_custom_request_check() -> None:
    """
    Test the custom request check
    functionality of the FlaskAPIGuard extension.
    """
    app = Flask(__name__)

    def custom_check(request: Any) -> Response | None:
        if request.headers.get("X-Custom-Header") == "block":
            return Response("Custom block", status=403)
        return None

    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        custom_request_check=custom_check,
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        response = client.get("/", headers={"X-Custom-Header": "block"})
        assert response.status_code == 403
        assert response.data == b"Custom block"

        response = client.get("/", headers={"X-Custom-Header": "allow"})
        assert response.status_code == 200


def test_custom_error_responses() -> None:
    """
    Test the custom error responses.
    """
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        blacklist=["192.168.1.3"],
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        rate_limit=5,
        rate_limit_window=1,
        auto_ban_threshold=10,
        enable_penetration_detection=False,
        trusted_proxies=["127.0.0.1"],
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.3"})
        assert response.status_code == 403
        assert response.data == b"Custom Forbidden"

        for _ in range(5):
            response = client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
            assert response.status_code == 200

        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.4"})
        assert response.status_code == 429
        assert response.data == b"Custom Too Many Requests"


@pytest.mark.parametrize(
    (
        "test_scenario, expected_status_code, extra_config, "
        "request_path, request_headers, use_custom_check"
    ),
    [
        # Normal case
        (
            "normal",
            200,
            {},
            "/",
            {},
            False,
        ),
        # Blacklisted IP
        (
            "blacklisted",
            403,
            {},
            "/",
            {"X-Forwarded-For": "192.168.1.5"},
            False,
        ),
        # HTTPS enforcement
        (
            "https_enforcement",
            301,
            {"enforce_https": True},
            "/",
            {},
            False,
        ),
        # Excluded path
        (
            "excluded_path",
            200,
            {"exclude_paths": ["/excluded"]},
            "/excluded",
            {},
            False,
        ),
        # Custom request check
        (
            "custom_request_check",
            418,
            {},
            "/",
            {"X-Custom-Check": "true"},
            True,
        ),
        # Custom request check - no trigger
        (
            "custom_request_check_no_trigger",
            200,
            {},
            "/",
            {},
            True,
        ),
    ],
)
def test_custom_response_modifier_parameterized(
    test_scenario: str,
    expected_status_code: int,
    extra_config: dict[str, Any],
    request_path: str,
    request_headers: dict[str, str],
    use_custom_check: bool,
) -> None:
    """
    Parameterized test for the custom response modifier covering all scenarios.
    """
    app = Flask(__name__)

    def custom_modifier(response: Response) -> Response:
        response.headers["X-Modified"] = "True"

        if response.status_code >= 400:
            import json

            try:
                content = response.data.decode()
            except Exception:
                content = str(response.data)

            new_response = Response(
                json.dumps({"detail": content}),
                status=response.status_code,
                content_type="application/json",
            )
            new_response.headers["X-Modified"] = "True"
            return new_response

        return response

    def custom_check(request: Any) -> Response | None:
        if "X-Custom-Check" in request.headers:
            return Response("I'm a teapot", status=418)
        return None

    config_args: dict[str, Any] = {
        "geo_ip_handler": IPInfoManager(IPINFO_TOKEN),
        "blacklist": ["192.168.1.5"],
        "custom_response_modifier": custom_modifier,
        "trusted_proxies": ["127.0.0.1"],
    }

    if use_custom_check:
        config_args["custom_request_check"] = custom_check

    config_args.update(extra_config)
    config = SecurityConfig(**config_args)

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    @app.route("/excluded")
    def excluded_path() -> dict[str, str]:
        return {"message": "Excluded Path"}

    with app.test_client() as client:
        response = client.get(request_path, headers=request_headers)

        assert response.headers.get("X-Modified") == "True"
        assert response.status_code == expected_status_code

        if expected_status_code >= 400:
            response = client.get(request_path, headers=request_headers)
            response_json = response.get_json()
            assert "detail" in response_json


def test_cloud_ip_blocking() -> None:
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        block_cloud_providers={"AWS", "GCP", "Azure"},
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with patch.object(cloud_handler, "is_cloud_ip", return_value=True):
        with app.test_client() as client:
            response = client.get("/", headers={"X-Forwarded-For": "13.59.255.255"})
            assert response.status_code == 403

    with patch.object(cloud_handler, "is_cloud_ip", return_value=False):
        with app.test_client() as client:
            response = client.get("/", headers={"X-Forwarded-For": "8.8.8.8"})
            assert response.status_code == 200


def test_excluded_paths() -> None:
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        exclude_paths=["/health"],
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    with app.test_client() as client:
        response = client.get("/health")
        assert response.status_code == 200


def test_cleanup_expired_request_times() -> None:
    """Test cleanup of expired request times"""
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        rate_limit=2,
        rate_limit_window=1,
    )
    guard = FlaskAPIGuard(app, config=config)

    handler = guard.rate_limit_handler
    assert handler is not None
    handler.reset()

    assert len(handler.request_timestamps) == 0

    current_time = time.time()
    # Test data
    handler.request_timestamps["ip1"].append(current_time)
    handler.request_timestamps["ip1"].append(current_time)
    handler.request_timestamps["ip2"].append(current_time)

    assert len(handler.request_timestamps["ip1"]) == 2
    assert len(handler.request_timestamps["ip2"]) == 1
    assert len(handler.request_timestamps) == 2

    # Reset and verify cleared
    handler.reset()
    assert len(handler.request_timestamps) == 0


def test_penetration_detection_disabled() -> None:
    """Test when penetration detection is disabled"""
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        enable_penetration_detection=False,
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    @app.route("/wp-admin")
    def admin_page() -> dict[str, str]:
        return {"message": "Admin"}

    with app.test_client() as client:
        response = client.get("/")
        assert response.status_code == 200

        response = client.get("/wp-admin")
        assert response.status_code == 200


def test_redis_initialization(security_config_redis: SecurityConfig) -> None:
    """Test Redis initialization in FlaskAPIGuard"""
    app = Flask(__name__)

    security_config_redis.block_cloud_providers = {"AWS"}

    # Mock external handlers before FlaskAPIGuard is created
    with (
        patch(
            "flaskapi_guard.handlers.redis_handler.RedisManager.initialize"
        ) as redis_init,
        patch(
            "flaskapi_guard.handlers.cloud_handler.cloud_handler.initialize_redis"
        ) as cloud_init,
        patch(
            "flaskapi_guard.handlers.ipban_handler.ip_ban_manager.initialize_redis"
        ) as ipban_init,
        patch.object(IPInfoManager, "initialize_redis") as ipinfo_init,
        patch(
            "flaskapi_guard.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis"
        ) as sus_init,
        patch(
            "flaskapi_guard.handlers.ratelimit_handler.RateLimitManager.initialize_redis"
        ) as rate_init,
    ):
        FlaskAPIGuard(app, config=security_config_redis)

        # Verify Redis handler initialization
        redis_init.assert_called_once()

        # Verify component initializations with Redis
        cloud_init.assert_called_once()
        ipban_init.assert_called_once()
        ipinfo_init.assert_called_once()
        sus_init.assert_called_once()
        rate_init.assert_called_once()


def test_redis_initialization_without_ipinfo_and_cloud(
    security_config_redis: SecurityConfig,
) -> None:
    """Test Redis initialization in FlaskAPIGuard"""
    app = Flask(__name__)

    security_config_redis.blocked_countries = []

    # Mock external handlers before FlaskAPIGuard is created
    with (
        patch(
            "flaskapi_guard.handlers.redis_handler.RedisManager.initialize"
        ) as redis_init,
        patch(
            "flaskapi_guard.handlers.cloud_handler.cloud_handler.initialize_redis"
        ) as cloud_init,
        patch(
            "flaskapi_guard.handlers.ipban_handler.ip_ban_manager.initialize_redis"
        ) as ipban_init,
        patch.object(IPInfoManager, "initialize_redis") as ipinfo_init,
        patch(
            "flaskapi_guard.handlers.suspatterns_handler.sus_patterns_handler.initialize_redis"
        ) as sus_init,
        patch(
            "flaskapi_guard.handlers.ratelimit_handler.RateLimitManager.initialize_redis"
        ) as rate_init,
    ):
        FlaskAPIGuard(app, config=security_config_redis)

        # Verify Redis handler initialization
        redis_init.assert_called_once()

        # Verify component initializations with Redis
        cloud_init.assert_not_called()
        ipban_init.assert_called_once()
        ipinfo_init.assert_not_called()
        sus_init.assert_called_once()
        rate_init.assert_called_once()


def test_redis_disabled(security_config: SecurityConfig) -> None:
    """Test guard behavior when Redis is disabled"""
    app = Flask(__name__)
    security_config.enable_redis = False
    guard = FlaskAPIGuard(app, config=security_config)

    assert guard.redis_handler is None

    assert guard.rate_limit_handler is not None
    guard.rate_limit_handler.reset()


def test_rate_limiting_disabled() -> None:
    """Test when rate limiting is disabled"""
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        enable_rate_limiting=False,
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        for _ in range(10):
            response = client.get("/")
            assert response.status_code == 200


def test_rate_limiting_with_redis(security_config_redis: SecurityConfig) -> None:
    """Test rate limiting with Redis"""

    app = Flask(__name__)
    security_config_redis.rate_limit = 2
    security_config_redis.rate_limit_window = 10
    security_config_redis.whitelist = []

    rate_handler = rate_limit_handler(security_config_redis)
    rate_handler.reset()

    FlaskAPIGuard(app, config=security_config_redis)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        # Should be allowed
        response = client.get("/")
        assert response.status_code == 200

        # Should be allowed
        response = client.get("/")
        assert response.status_code == 200

        # Should be rate limited because count > limit
        response = client.get("/")
        assert response.status_code == 429

        # Reset redis keys
        rate_handler.reset()

        # Should be allowed again
        response = client.get("/")
        assert response.status_code == 200


def test_rate_limit_reset_with_redis_errors(
    security_config_redis: SecurityConfig,
) -> None:
    """Test rate limit reset handling Redis errors"""

    security_config_redis.rate_limit = 2
    security_config_redis.enable_rate_limiting = True

    handler = redis_handler(security_config_redis)

    rate_handler = rate_limit_handler(security_config_redis)
    rate_handler.initialize_redis(handler)

    def mock_keys(*args: Any) -> None:
        raise Exception("Redis keys error")

    with (
        patch.object(rate_handler.redis_handler, "keys", mock_keys),
        patch.object(logging.Logger, "error") as mock_logger,
    ):
        rate_handler.reset()

        # Verify error was logged
        mock_logger.assert_called_once()
        args = mock_logger.call_args[0]
        assert "Failed to reset Redis rate limits" in args[0]


def test_passive_mode_penetration_detection() -> None:
    """Test penetration detection in passive mode"""
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        passive_mode=True,
        whitelist=[],
    )
    FlaskAPIGuard(app, config=config)

    @app.route("/login")
    def login() -> dict[str, str]:
        return {"message": "Login"}

    with (
        patch(
            "flaskapi_guard.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
            return_value=(True, "SQL injection attempt"),
        ),
        patch(
            "flaskapi_guard.core.checks.implementations.suspicious_activity.log_activity"
        ),
        patch(
            "flaskapi_guard.utils.detect_penetration_attempt",
            return_value=(True, "SQL injection attempt"),
        ),
    ):
        with app.test_client() as client:
            response = client.get("/login")
            assert response.status_code == 200


def test_sliding_window_rate_limiting() -> None:
    """Test that sliding window rate limiting works correctly"""
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        rate_limit=3,
        rate_limit_window=1,
        enable_rate_limiting=True,
    )

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    handler = rate_limit_handler(config)
    handler.reset()

    with app.test_client() as client:
        # First 3 requests should be allowed
        for _ in range(3):
            response = client.get("/")
            assert response.status_code == 200

        # 4th request should be rate limited
        response = client.get("/")
        assert response.status_code == 429

        # Wait for window to slide plus a little extra to be safe
        time.sleep(1.5)

        # After 1.5 seconds, the rate limit should reset
        response = client.get("/")
        assert response.status_code == 200


def test_rate_limiter_deque_cleanup(security_config: SecurityConfig) -> None:
    """Test cleanup of old requests from the deque"""
    handler = rate_limit_handler(security_config)
    handler.reset()

    current_time = time.time()
    window_start = current_time - security_config.rate_limit_window

    client_ip = "192.168.1.1"

    old_queue = handler.request_timestamps[client_ip]
    old_queue.append(window_start - 0.5)
    old_queue.append(window_start - 0.7)
    old_queue.append(window_start - 0.2)

    assert len(old_queue) == 3
    assert all(ts < window_start for ts in old_queue)

    app = Flask(__name__)
    app.config["TESTING"] = True

    def create_error_response(status_code: int, message: str) -> Response:
        return Response(message, status=status_code)

    response = create_error_response(429, "Test message")
    assert response.status_code == 429
    assert response.data == b"Test message"

    with app.test_request_context("/"):
        from flask import request

        result = handler.check_rate_limit(request, client_ip, create_error_response)

    assert result is None

    assert len(handler.request_timestamps[client_ip]) == 1

    handler.request_timestamps[client_ip].clear()
    handler.request_timestamps[client_ip].append(window_start - 10)  # Way before window
    handler.request_timestamps[client_ip].append(window_start + 0.5)  # Within window

    with app.test_request_context("/"):
        from flask import request

        result = handler.check_rate_limit(request, client_ip, create_error_response)

    assert result is None

    assert len(handler.request_timestamps[client_ip]) == 2
    assert all(ts >= window_start for ts in handler.request_timestamps[client_ip])


def test_lua_script_execution(security_config_redis: SecurityConfig) -> None:
    """Test that the Lua script is executed properly for rate limiting with Redis"""
    app = Flask(__name__)
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True

    guard = FlaskAPIGuard(app, config=config)
    handler = guard.rate_limit_handler
    assert handler is not None

    with patch.object(handler.redis_handler, "get_connection") as mock_get_connection:
        mock_conn = MagicMock()
        mock_conn.evalsha = MagicMock(return_value=1)

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)
        mock_get_connection.return_value = mock_context

        handler.rate_limit_script_sha = "test_script_sha"

        def create_error_response(status_code: int, message: str) -> Response:
            return Response(message, status=status_code)

        with app.test_request_context("/"):
            from flask import request

            result = handler.check_rate_limit(
                request, "192.168.1.1", create_error_response
            )
            assert result is None  # Should not be rate limited

            mock_conn.evalsha.assert_called_once()

            mock_conn.evalsha.reset_mock()
            mock_conn.evalsha.return_value = 3  # Over the limit

            result = handler.check_rate_limit(
                request, "192.168.1.1", create_error_response
            )
            assert result is not None
            assert result.status_code == 429


def test_fallback_to_pipeline(security_config_redis: SecurityConfig) -> None:
    """Test fallback to pipeline if Lua script fails"""
    app = Flask(__name__)
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True

    guard = FlaskAPIGuard(app, config=config)
    handler = guard.rate_limit_handler
    assert handler is not None

    with patch.object(handler.redis_handler, "get_connection") as mock_get_connection:
        mock_conn = MagicMock()

        mock_pipeline = Mock()
        mock_pipeline.zadd = Mock()
        mock_pipeline.zremrangebyscore = Mock()
        mock_pipeline.zcard = Mock()
        mock_pipeline.expire = Mock()

        mock_pipeline.execute = Mock(
            side_effect=[
                [0, 0, 1, True],  # zadd, zrem, zcard (1), expire results
                [0, 0, 3, True],  # zadd, zrem, zcard (3), expire results
            ]
        )

        mock_conn.pipeline = Mock(return_value=mock_pipeline)

        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock(return_value=False)
        mock_get_connection.return_value = mock_context

        handler.rate_limit_script_sha = None

        def create_error_response(status_code: int, message: str) -> Response:
            return Response(message, status=status_code)

        with app.test_request_context("/"):
            from flask import request

            result = handler.check_rate_limit(
                request, "192.168.1.1", create_error_response
            )
            assert result is None  # Should not be rate limited

            mock_conn.pipeline.assert_called_once()
            mock_pipeline.zadd.assert_called_once()
            mock_pipeline.zremrangebyscore.assert_called_once()
            mock_pipeline.zcard.assert_called_once()
            mock_pipeline.expire.assert_called_once()
            mock_pipeline.execute.assert_called_once()

            mock_conn.pipeline.reset_mock()
            mock_pipeline.zadd.reset_mock()
            mock_pipeline.zremrangebyscore.reset_mock()
            mock_pipeline.zcard.reset_mock()
            mock_pipeline.expire.reset_mock()
            mock_pipeline.execute.reset_mock()

            result = handler.check_rate_limit(
                request, "192.168.1.1", create_error_response
            )
            assert result is not None
            assert result.status_code == 429
            assert result.data == b"Too many requests"

            mock_conn.pipeline.assert_called_once()
            mock_pipeline.zadd.assert_called_once()
            mock_pipeline.zremrangebyscore.assert_called_once()
            mock_pipeline.zcard.assert_called_once()
            mock_pipeline.expire.assert_called_once()
            mock_pipeline.execute.assert_called_once()


def test_rate_limiter_redis_errors(security_config_redis: SecurityConfig) -> None:
    """Test Redis error handling in rate limit check"""
    app = Flask(__name__)
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True

    guard = FlaskAPIGuard(app, config=config)
    handler = guard.rate_limit_handler
    assert handler is not None

    def create_error_response(status_code: int, message: str) -> Response:
        return Response(message, status=status_code)

    error_response = create_error_response(429, "Rate limited")
    assert error_response.status_code == 429
    assert error_response.data == b"Rate limited"

    with (
        patch.object(handler.redis_handler, "get_connection") as mock_get_connection,
        patch.object(logging.Logger, "error") as mock_error,
        patch.object(logging.Logger, "info") as mock_info,
    ):
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(
            side_effect=RedisError("Redis connection error")
        )
        mock_get_connection.return_value = mock_conn

        handler.rate_limit_script_sha = "test_script_sha"

        with app.test_request_context("/"):
            from flask import request

            result = handler.check_rate_limit(
                request, "192.168.1.1", create_error_response
            )

            assert result is None

            mock_error.assert_called_once()
            assert "Redis rate limiting error" in mock_error.call_args[0][0]
            mock_info.assert_called_once_with("Falling back to in-memory rate limiting")

    with (
        patch.object(handler.redis_handler, "get_connection") as mock_get_connection,
        patch.object(logging.Logger, "error") as mock_error,
    ):
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(side_effect=Exception("Unexpected error"))
        mock_get_connection.return_value = mock_conn

        with app.test_request_context("/"):
            from flask import request

            result = handler.check_rate_limit(
                request, "192.168.1.1", create_error_response
            )

            assert result is None

            mock_error.assert_called_once()
            assert "Unexpected error in rate limiting" in mock_error.call_args[0][0]


def test_rate_limiter_init_redis_exception(
    security_config_redis: SecurityConfig,
) -> None:
    """Test exception handling during Redis script loading"""
    handler = rate_limit_handler(security_config_redis)

    mock_redis = Mock()
    mock_cm = MagicMock()
    mock_conn = MagicMock()
    mock_conn.script_load = MagicMock(side_effect=Exception("Script load failed"))
    mock_cm.__enter__.return_value = mock_conn
    mock_cm.__exit__ = MagicMock(return_value=False)
    mock_redis.get_connection.return_value = mock_cm

    mock_logger = Mock()
    handler.logger = mock_logger

    handler.initialize_redis(mock_redis)

    mock_logger.error.assert_called_once()
    error_msg = mock_logger.error.call_args[0][0]
    assert "Failed to load rate limiting Lua script: Script load failed" == error_msg


def test_ipv6_rate_limiting(
    security_config_redis: SecurityConfig, clean_rate_limiter: None
) -> None:
    """
    Test the rate limiting functionality
    of the FlaskAPIGuard extension with IPv6 addresses.
    """
    app = Flask(__name__)
    config = security_config_redis
    config.rate_limit = 2
    config.rate_limit_window = 1
    config.enable_rate_limiting = True
    config.trusted_proxies = ["127.0.0.1"]
    config.whitelist = []
    config.blocked_countries = []
    config.enable_penetration_detection = False

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    # Reset rate limiter to clear any stale state from previous tests
    handler = rate_limit_handler(config)
    handler.reset()

    with app.test_client() as client:
        response = client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == 200

        response = client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == 200

        response = client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == 429

        handler = rate_limit_handler(config)
        handler.reset()

        response = client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == 200


def test_ipv6_whitelist_blacklist(security_config_redis: SecurityConfig) -> None:
    """
    Test the IPv6 whitelist/blacklist
    functionality of the FlaskAPIGuard extension.
    """
    app = Flask(__name__)
    config = security_config_redis
    config.whitelist = ["::1", "2001:db8::1"]
    config.blacklist = ["2001:db8::dead:beef"]
    config.enable_penetration_detection = False
    config.trusted_proxies = ["127.0.0.1", "::1"]

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        # IPv6 loopback
        response = client.get("/", headers={"X-Forwarded-For": "::1"})
        assert response.status_code == 200

        # Whitelisted IPv6 address
        response = client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == 200

        # Blacklisted IPv6 address
        response = client.get("/", headers={"X-Forwarded-For": "2001:db8::dead:beef"})
        assert response.status_code == 403

        # Non-whitelisted IPv6 address (block)
        response = client.get("/", headers={"X-Forwarded-For": "2001:db8::2"})
        assert response.status_code == 403


def test_ipv6_cidr_whitelist_blacklist(
    security_config_redis: SecurityConfig,
) -> None:
    """
    Test IPv6 CIDR notation in whitelist/blacklist.
    """
    app = Flask(__name__)
    config = security_config_redis
    config.whitelist = ["2001:db8::/32"]
    config.blacklist = ["2001:db8:dead::/48"]
    config.enable_penetration_detection = False
    config.trusted_proxies = ["127.0.0.1", "::1"]

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        # IPv6 address in whitelisted CIDR
        response = client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == 200

        response = client.get("/", headers={"X-Forwarded-For": "2001:db8:1::1"})
        assert response.status_code == 200

        # IPv6 address in blacklisted CIDR (blacklist overrides whitelist)
        response = client.get("/", headers={"X-Forwarded-For": "2001:db8:dead::beef"})
        assert response.status_code == 403

        # IPv6 address outside whitelisted CIDR
        response = client.get("/", headers={"X-Forwarded-For": "2001:db9::1"})
        assert response.status_code == 403


def test_mixed_ipv4_ipv6_handling(security_config_redis: SecurityConfig) -> None:
    """
    Test handling of mixed IPv4 and IPv6 addresses in configuration.
    """
    app = Flask(__name__)
    config = security_config_redis
    config.whitelist = ["127.0.0.1", "::1", "192.168.1.0/24", "2001:db8::/32"]
    config.blacklist = ["192.168.1.100", "2001:db8:dead::beef"]
    config.enable_penetration_detection = False
    config.trusted_proxies = ["127.0.0.1", "::1"]

    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        # IPv4 addresses
        response = client.get("/", headers={"X-Forwarded-For": "127.0.0.1"})
        assert response.status_code == 200

        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.50"})
        assert response.status_code == 200

        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.100"})
        assert response.status_code == 403

        # IPv6 addresses
        response = client.get("/", headers={"X-Forwarded-For": "::1"})
        assert response.status_code == 200

        response = client.get("/", headers={"X-Forwarded-For": "2001:db8::1"})
        assert response.status_code == 200

        response = client.get("/", headers={"X-Forwarded-For": "2001:db8:dead::beef"})
        assert response.status_code == 403


def test_emergency_mode_passive(security_config: SecurityConfig) -> None:
    """Test emergency mode in passive mode."""
    app = Flask(__name__)
    security_config.emergency_mode = True
    security_config.passive_mode = True
    security_config.trusted_proxies = ["127.0.0.1"]

    @app.route("/test")
    def test_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    FlaskAPIGuard(app, config=security_config)

    with app.test_client() as client:
        # Should pass in passive mode
        response = client.get("/test", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 200


def test_cors_preflight() -> None:
    """Test that OPTIONS request returns 204 with CORS headers when enable_cors=True."""
    config = SecurityConfig(
        enable_redis=False,
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["Content-Type"],
    )
    app = Flask(__name__)
    app.config["TESTING"] = True
    FlaskAPIGuard(app, config=config)

    with app.test_client() as client:
        response = client.options("/", headers={"Origin": "https://example.com"})
        assert response.status_code == 204


def test_cors_disabled() -> None:
    """Test that no CORS headers are added when enable_cors=False."""
    config = SecurityConfig(
        enable_redis=False,
        enable_cors=False,
    )
    app = Flask(__name__)
    app.config["TESTING"] = True
    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        response = client.get("/", headers={"Origin": "https://example.com"})
        assert response.status_code == 200
        assert "Access-Control-Allow-Origin" not in response.headers


def test_cloud_ip_refresh_no_providers() -> None:
    """Test that refresh_cloud_ip_ranges returns early when no providers configured."""
    config = SecurityConfig(
        enable_redis=False,
        block_cloud_providers=None,
    )
    app = Flask(__name__)
    app.config["TESTING"] = True
    guard = FlaskAPIGuard(app, config=config)

    initial_refresh_time = guard.last_cloud_ip_refresh
    guard.refresh_cloud_ip_ranges()
    # Should not have updated the refresh time since no providers are configured
    assert guard.last_cloud_ip_refresh == initial_refresh_time


def test_init_without_config() -> None:
    """Test that ValueError is raised when no config is provided."""
    app = Flask(__name__)
    guard = FlaskAPIGuard()

    with pytest.raises(ValueError, match="SecurityConfig must be provided"):
        guard.init_app(app)


def test_agent_initialization_import_error() -> None:
    """Test agent initialization when guard_agent package is not installed."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-key",
    )
    app = Flask(__name__)
    app.config["TESTING"] = True

    # to_agent_config returns None when guard_agent is not installed (ImportError),
    # so the agent_handler stays None and we get the "invalid config" warning path.
    # To test the ImportError path inside extension.py, we need to_agent_config to
    # return a truthy value, and then the import inside extension.py to fail.
    with patch.object(
        SecurityConfig,
        "to_agent_config",
        return_value=MagicMock(),
    ):
        guard = FlaskAPIGuard(app, config=config)
        # guard_agent is not installed, so ImportError should be caught
        assert guard.agent_handler is None


def test_agent_initialization_success() -> None:
    """Test successful agent initialization with mocked guard_agent."""
    import sys

    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-key",
    )
    app = Flask(__name__)
    app.config["TESTING"] = True

    mock_agent_instance = MagicMock()
    mock_guard_agent_fn = MagicMock(return_value=mock_agent_instance)
    mock_agent_module = MagicMock()
    mock_agent_module.guard_agent = mock_guard_agent_fn

    mock_agent_config = MagicMock()

    with patch.object(
        SecurityConfig,
        "to_agent_config",
        return_value=mock_agent_config,
    ):
        with patch.dict(sys.modules, {"guard_agent": mock_agent_module}):
            guard = FlaskAPIGuard(app, config=config)
            assert guard.agent_handler is mock_agent_instance
            mock_guard_agent_fn.assert_called_once_with(mock_agent_config)


def test_agent_initialization_invalid_config() -> None:
    """Test agent initialization when to_agent_config returns None."""
    config = SecurityConfig(
        enable_redis=False,
        enable_agent=True,
        agent_api_key="test-key",
    )
    app = Flask(__name__)
    app.config["TESTING"] = True

    # Patch SecurityConfig.to_agent_config at class level to return None
    with patch(
        "flaskapi_guard.models.SecurityConfig.to_agent_config", return_value=None
    ):
        guard = FlaskAPIGuard(app, config=config)
        # to_agent_config returns None, so agent_handler stays None
        assert guard.agent_handler is None


def test_passive_mode_rate_limiting() -> None:
    """Test that in passive mode, rate limit is logged but request is not blocked."""
    app = Flask(__name__)
    config = SecurityConfig(
        enable_redis=False,
        passive_mode=True,
        rate_limit=1,
        rate_limit_window=60,
        enable_rate_limiting=True,
    )
    guard = FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        # First request — within limit
        response = client.get("/")
        assert response.status_code == 200

        # Second request — exceeds limit but passive mode should not block
        # The _check_rate_limit method returns None in passive mode
        with app.test_request_context("/"):
            from flask import request

            result = guard._check_rate_limit(request, "127.0.0.1")
            assert result is None


def test_reset_method() -> None:
    """Test that FlaskAPIGuard.reset() clears rate limits."""
    app = Flask(__name__)
    config = SecurityConfig(
        enable_redis=False,
        rate_limit=2,
        rate_limit_window=60,
        enable_rate_limiting=True,
    )
    guard = FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        # Exhaust rate limit
        client.get("/")
        client.get("/")
        response = client.get("/")
        assert response.status_code == 429

        # Reset via FlaskAPIGuard.reset()
        guard.reset()

        # Should be allowed again
        response = client.get("/")
        assert response.status_code == 200


def test_request_without_client() -> None:
    """Test handling of request when extract_client_ip returns 'unknown'."""
    config = SecurityConfig(
        enable_redis=False,
    )
    app = Flask(__name__)
    app.config["TESTING"] = True
    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        # Patch extract_client_ip to return "unknown" (simulates no remote_addr)
        with patch(
            "flaskapi_guard.extension.extract_client_ip", return_value="unknown"
        ):
            response = client.get("/")
            assert response.status_code == 200


def test_set_decorator_handler() -> None:
    """Test that setting decorator handler updates all components."""
    config = SecurityConfig(
        enable_redis=False,
    )
    app = Flask(__name__)
    app.config["TESTING"] = True
    guard = FlaskAPIGuard(app, config=config)

    mock_decorator = MagicMock(spec=BaseSecurityDecorator)
    guard.set_decorator_handler(mock_decorator)

    assert guard.guard_decorator is mock_decorator
    assert guard.route_resolver.context.guard_decorator is mock_decorator
    assert guard.behavioral_processor.context.guard_decorator is mock_decorator
    assert guard.response_factory.context.guard_decorator is mock_decorator
    assert guard.handler_initializer.guard_decorator is mock_decorator

    ext = app.extensions.get("flaskapi_guard")
    assert ext["guard_decorator"] is mock_decorator


def test_init_app_factory_pattern() -> None:
    """Test FlaskAPIGuard() then guard.init_app(app, config=config) pattern."""
    config = SecurityConfig(
        enable_redis=False,
    )
    app = Flask(__name__)
    app.config["TESTING"] = True

    guard = FlaskAPIGuard()
    assert guard.config is None
    assert guard._app is None

    guard.init_app(app, config=config)

    assert guard.config is config
    assert guard._app is app
    assert "flaskapi_guard" in app.extensions

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        response = client.get("/")
        assert response.status_code == 200


def test_security_headers_disabled() -> None:
    """Test when security_headers has enabled=False."""
    config = SecurityConfig(
        enable_redis=False,
        security_headers={"enabled": False},
    )
    app = Flask(__name__)
    app.config["TESTING"] = True
    FlaskAPIGuard(app, config=config)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    with app.test_client() as client:
        response = client.get("/")
        assert response.status_code == 200
        # Security headers like X-Content-Type-Options should not be present
        assert "X-Content-Type-Options" not in response.headers
