from unittest.mock import patch

from flask import Flask

from flaskapi_guard.core.checks.helpers import is_referrer_domain_allowed
from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.utils import (
    _extract_from_forwarded_header,
    _sanitize_for_log,
    detect_penetration_attempt,
    extract_client_ip,
)


class TestSanitizeForLog:
    """Test _sanitize_for_log edge cases."""

    def test_sanitize_empty_string(self) -> None:
        """Test sanitize with empty string returns empty string."""
        result = _sanitize_for_log("")
        assert result == ""

    def test_sanitize_none(self) -> None:
        """Test sanitize with None returns None."""
        result = _sanitize_for_log(None)
        assert result is None

    def test_sanitize_with_content(self) -> None:
        """Test sanitize with actual content works."""
        result = _sanitize_for_log("test\nvalue")
        assert result == "test\\nvalue"


class TestExtractFromForwardedHeader:
    """Test _extract_from_forwarded_header edge cases."""

    def test_extract_empty_header(self) -> None:
        """Test extract with empty header returns None."""
        result = _extract_from_forwarded_header("", 1)
        assert result is None

    def test_extract_with_valid_header(self) -> None:
        """Test extract with valid header."""
        result = _extract_from_forwarded_header("1.2.3.4, 5.6.7.8", 2)
        assert result == "1.2.3.4"


class TestExtractClientIPExceptionHandling:
    """Test extract_client_ip exception handling."""

    def test_extract_client_ip_with_invalid_forwarded_for(self) -> None:
        """Test extract_client_ip handles ValueError/IndexError gracefully."""
        app = Flask(__name__)
        with app.test_request_context(
            "/",
            method="GET",
            headers={"X-Forwarded-For": "invalid-ip-format"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        ):
            from flask import request

            config = SecurityConfig()
            config.trusted_proxies = ["127.0.0.1"]
            config.trusted_proxy_depth = 999  # Force IndexError

            with patch(
                "flaskapi_guard.utils._extract_from_forwarded_header",
                side_effect=ValueError("Invalid IP"),
            ):
                # Should fall back to connecting IP without raising exception
                result = extract_client_ip(request, config, None)
                assert result == "127.0.0.1"

    def test_extract_client_ip_logs_warning_on_error(self) -> None:
        """Test that extract_client_ip logs warning when exception occurs."""
        app = Flask(__name__)
        with app.test_request_context(
            "/",
            method="GET",
            headers={"X-Forwarded-For": "1.2.3.4"},
            environ_base={"REMOTE_ADDR": "127.0.0.1"},
        ):
            from flask import request

            config = SecurityConfig()
            config.trusted_proxies = ["127.0.0.1"]
            config.trusted_proxy_depth = 1

            with (
                patch(
                    "flaskapi_guard.utils._extract_from_forwarded_header",
                    side_effect=IndexError("Test error"),
                ),
                patch("flaskapi_guard.utils.logging") as mock_logging,
            ):
                result = extract_client_ip(request, config, None)

                # Should log warning about error processing
                assert result == "127.0.0.1"
                mock_logging.warning.assert_any_call(
                    "Error processing client IP: Test error"
                )


class TestDetectPenetrationAttemptURLPath:
    """Test detect_penetration_attempt URL path checking."""

    def test_detect_penetration_url_path_with_real_threat(self) -> None:
        """Test penetration detection in URL path with REAL threat."""
        app = Flask(__name__)
        with app.test_request_context(
            "/../../etc/passwd",
            method="GET",
        ):
            from flask import request

            detected, trigger = detect_penetration_attempt(request)

            # Should detect threat in URL path
            assert detected is True
            assert "URL path" in trigger


class TestSendAgentEvent:
    """Test send_agent_event helper from utils."""

    def test_send_agent_event_with_request(self) -> None:
        """Test send_agent_event sends event with request info."""
        import sys
        import types
        from unittest.mock import MagicMock, Mock

        from flaskapi_guard.utils import send_agent_event

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        # Mock guard_agent module
        mock_module = types.ModuleType("guard_agent")

        class MockSecurityEvent:
            def __init__(self, **kwargs: object) -> None:
                for k, v in kwargs.items():
                    setattr(self, k, v)

        mock_module.SecurityEvent = MockSecurityEvent  # type: ignore[attr-defined]
        original = sys.modules.get("guard_agent")
        sys.modules["guard_agent"] = mock_module

        try:
            app = Flask(__name__)
            with app.test_request_context(
                "/test",
                method="POST",
                headers={"User-Agent": "TestAgent"},
            ):
                from flask import request

                send_agent_event(
                    mock_agent,
                    "test_event",
                    "1.2.3.4",
                    "blocked",
                    "test reason",
                    request=request,
                )
                mock_agent.send_event.assert_called_once()
        finally:
            if original:
                sys.modules["guard_agent"] = original
            else:
                sys.modules.pop("guard_agent", None)

    def test_send_agent_event_no_agent(self) -> None:
        """Test send_agent_event returns early when no agent."""
        from flaskapi_guard.utils import send_agent_event

        # Should not raise
        send_agent_event(
            None, "test_event", "1.2.3.4", "blocked", "test reason"
        )

    def test_send_agent_event_exception(self) -> None:
        """Test send_agent_event handles exceptions gracefully."""
        from unittest.mock import Mock

        from flaskapi_guard.utils import send_agent_event

        mock_agent = Mock()
        mock_agent.send_event = Mock(side_effect=Exception("Agent error"))

        # Patch guard_agent to exist but raise when creating event
        import sys
        import types

        mock_module = types.ModuleType("guard_agent")
        mock_module.SecurityEvent = Mock(side_effect=Exception("Import error"))  # type: ignore[attr-defined]
        original = sys.modules.get("guard_agent")
        sys.modules["guard_agent"] = mock_module

        try:
            # Should not raise
            send_agent_event(
                mock_agent, "test_event", "1.2.3.4", "blocked", "test reason"
            )
        finally:
            if original:
                sys.modules["guard_agent"] = original
            else:
                sys.modules.pop("guard_agent", None)


class TestExtractClientIPWithTrustedProxies:
    """Test extract_client_ip with trusted proxy configuration."""

    def test_extract_client_ip_with_trusted_proxy_success(self) -> None:
        """Test extract_client_ip extracts from X-Forwarded-For via trusted proxy."""
        app = Flask(__name__)
        with app.test_request_context(
            "/",
            method="GET",
            headers={"X-Forwarded-For": "203.0.113.50, 192.168.1.1"},
            environ_base={"REMOTE_ADDR": "192.168.1.1"},
        ):
            from flask import request

            config = SecurityConfig()
            config.trusted_proxies = ["192.168.1.1"]
            config.trusted_proxy_depth = 1

            result = extract_client_ip(request, config, None)
            assert result == "203.0.113.50"

    def test_extract_client_ip_no_remote_addr(self) -> None:
        """Test extract_client_ip returns 'unknown' when remote_addr is None."""
        from unittest.mock import Mock

        config = SecurityConfig()

        # Use a mock request with remote_addr = None
        mock_request = Mock()
        mock_request.remote_addr = None
        mock_request.headers = {}

        result = extract_client_ip(mock_request, config, None)
        assert result == "unknown"


class TestReferrerDomainAllowedExceptionHandling:
    """Test is_referrer_domain_allowed exception handling."""

    def test_is_referrer_domain_allowed_with_none(self) -> None:
        """Test exception handling when referrer is None."""
        # exception handler returns False
        result = is_referrer_domain_allowed(None, ["example.com"])
        assert result is False

    def test_is_referrer_domain_allowed_with_invalid_type(self) -> None:
        """Test exception handling when referrer is invalid type."""
        # exception handler returns False
        result = is_referrer_domain_allowed(12345, ["example.com"])
        assert result is False

    def test_is_referrer_domain_allowed_with_malformed_url(self) -> None:
        """Test exception handling when URL parsing fails."""
        # exception handler returns False
        result = is_referrer_domain_allowed("://no-scheme", ["example.com"])
        assert result is False
