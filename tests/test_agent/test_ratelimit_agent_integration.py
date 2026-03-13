# tests/test_agent/test_ratelimit_agent_integration.py
import logging
from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Request

from flaskapi_guard.handlers.ratelimit_handler import RateLimitManager
from flaskapi_guard.models import SecurityConfig


class TestRateLimitManagerAgentIntegration:
    """Test RateLimitManager agent integration."""

    def test_initialize_agent(self) -> None:
        """Test initialize_agent method."""
        # Reset singleton
        RateLimitManager._instance = None

        config = SecurityConfig()
        manager = RateLimitManager(config)
        mock_agent = MagicMock()

        manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent

    def test_send_rate_limit_event_success(self) -> None:
        """Test _send_rate_limit_event success path."""
        # Reset singleton
        RateLimitManager._instance = None

        config = SecurityConfig(
            enable_rate_limiting=True, rate_limit=100, rate_limit_window=60
        )
        manager = RateLimitManager(config)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        # Create mock request
        mock_request = MagicMock(spec=Request)
        mock_request.path = "/api/test"
        mock_request.method = "GET"

        manager._send_rate_limit_event(
            request=mock_request, client_ip="192.168.1.100", request_count=150
        )

        # Verify event was sent
        mock_agent.send_event.assert_called_once()
        sent_event = mock_agent.send_event.call_args[0][0]

        # Verify event properties
        assert sent_event.event_type == "rate_limited"
        assert sent_event.ip_address == "192.168.1.100"
        assert sent_event.action_taken == "request_blocked"
        assert sent_event.reason == "Rate limit exceeded: 150 requests in 60s window"
        assert sent_event.endpoint == "/api/test"
        assert sent_event.method == "GET"
        assert sent_event.metadata["request_count"] == 150
        assert sent_event.metadata["rate_limit"] == 100
        assert sent_event.metadata["window"] == 60

    def test_send_rate_limit_event_exception_handling(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test _send_rate_limit_event exception handling."""
        # Reset singleton
        RateLimitManager._instance = None

        config = SecurityConfig(
            enable_rate_limiting=True, rate_limit=100, rate_limit_window=60
        )
        manager = RateLimitManager(config)
        mock_agent = MagicMock()
        mock_agent.send_event.side_effect = Exception("Network error")
        manager.agent_handler = mock_agent

        # Create mock request
        mock_request = MagicMock(spec=Request)
        mock_request.path = "/api/data"
        mock_request.method = "POST"

        # Enable logging
        caplog.set_level(logging.ERROR)

        # Should not raise exception
        manager._send_rate_limit_event(
            request=mock_request, client_ip="192.168.1.101", request_count=200
        )

        # Verify error was logged
        assert "Failed to send rate limit event to agent: Network error" in caplog.text

    def test_check_rate_limit_agent_event_called(self) -> None:
        """Test that _send_rate_limit_event is called when rate limit is exceeded."""
        # Reset singleton
        RateLimitManager._instance = None

        config = SecurityConfig(
            enable_rate_limiting=True,
            enable_redis=False,  # Use in-memory for simplicity
            rate_limit=1,  # Very low limit to trigger easily
            rate_limit_window=60,
            log_suspicious_level="WARNING",
        )
        manager = RateLimitManager(config)

        # Setup agent handler
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        # Create mock request
        mock_request = MagicMock(spec=Request)
        mock_request.path = "/api/endpoint"
        mock_request.method = "GET"

        # Create mock error response function
        def mock_error_response(status_code: int, message: str) -> Any:
            return f"Error: {status_code} - {message}"

        # Mock log_activity and _send_rate_limit_event to verify it's called
        with (
            patch("flaskapi_guard.handlers.ratelimit_handler.log_activity", MagicMock()),
            patch.object(
                manager, "_send_rate_limit_event", MagicMock()
            ) as mock_send_event,
        ):
            # First request should pass
            result1 = manager.check_rate_limit(
                request=mock_request,
                client_ip="192.168.1.100",
                create_error_response=mock_error_response,
            )
            assert result1 is None

            # Second request should be rate limited
            result2 = manager.check_rate_limit(
                request=mock_request,
                client_ip="192.168.1.100",
                create_error_response=mock_error_response,
            )

            # Should return error response
            assert result2 == "Error: 429 - Too many requests"

            # Verify _send_rate_limit_event was called
            mock_send_event.assert_called_once_with(mock_request, "192.168.1.100", 2)

    def test_check_rate_limit_redis_path_with_agent(self) -> None:
        """Test Redis path calls _send_rate_limit_event when rate limit exceeded."""
        # Reset singleton
        RateLimitManager._instance = None

        config = SecurityConfig(
            enable_rate_limiting=True,
            enable_redis=True,  # Enable Redis
            rate_limit=10,
            rate_limit_window=60,
            log_suspicious_level="WARNING",
        )
        manager = RateLimitManager(config)

        # Setup agent handler
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        # Mock Redis handler
        mock_redis = MagicMock()
        mock_redis_conn = MagicMock()
        mock_redis_conn.evalsha = MagicMock(return_value=15)  # Over limit as int
        mock_redis.get_connection = MagicMock(
            return_value=MagicMock(
                __enter__=MagicMock(return_value=mock_redis_conn),
                __exit__=MagicMock(return_value=None),
            )
        )
        manager.redis_handler = mock_redis
        manager.rate_limit_script_sha = "test_sha"

        # Create mock request
        mock_request = MagicMock(spec=Request)
        mock_request.path = "/api/test"
        mock_request.method = "POST"

        # Create mock error response function
        def mock_error_response(status_code: int, message: str) -> Any:
            return {"status": status_code, "message": message}

        # Mock log_activity to avoid actual logging
        with patch("flaskapi_guard.handlers.ratelimit_handler.log_activity", MagicMock()):
            # This should trigger rate limit via Redis
            result = manager.check_rate_limit(
                request=mock_request,
                client_ip="192.168.1.200",
                create_error_response=mock_error_response,
            )

            # Should return error response
            assert result == {"status": 429, "message": "Too many requests"}

            # Verify agent event was sent
            mock_agent.send_event.assert_called_once()
            sent_event = mock_agent.send_event.call_args[0][0]

            # Verify event details
            assert sent_event.event_type == "rate_limited"
            assert sent_event.ip_address == "192.168.1.200"
            assert sent_event.action_taken == "request_blocked"
            assert "Rate limit exceeded" in sent_event.reason
            assert sent_event.endpoint == "/api/test"
            assert sent_event.method == "POST"
            assert sent_event.metadata["request_count"] == 15


# Singleton cleanup fixture with SecurityEvent patching
@pytest.fixture(autouse=True)
def cleanup_ratelimit_singleton() -> Generator[Any, Any, Any]:
    """Cleanup RateLimitManager singleton before and after test."""
    # Reset before test
    RateLimitManager._instance = None

    # Create a custom __new__ that bypasses the global mock
    def custom_new(
        cls: type[RateLimitManager], config: SecurityConfig
    ) -> RateLimitManager:
        if cls._instance is None:
            cls._instance = object.__new__(cls)
            cls._instance.config = config
            cls._instance.request_timestamps = __import__("collections").defaultdict(
                lambda: __import__("collections").deque(maxlen=config.rate_limit * 2)
            )
            cls._instance.logger = logging.getLogger(__name__)
            cls._instance.redis_handler = None
            cls._instance.agent_handler = None
            cls._instance.rate_limit_script_sha = None
        cls._instance.config = config
        return cls._instance

    # Patch both __new__ and SecurityEvent
    with (
        patch.object(RateLimitManager, "__new__", custom_new),
        patch(
            "flaskapi_guard.handlers.ratelimit_handler.SecurityEvent", create=True
        ) as mock_event,
    ):
        from guard_agent.models import SecurityEvent

        mock_event.side_effect = SecurityEvent
        yield

    # Reset after test
    RateLimitManager._instance = None
