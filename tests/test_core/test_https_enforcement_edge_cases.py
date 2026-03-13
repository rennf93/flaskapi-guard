from unittest.mock import MagicMock, Mock, patch

import pytest
from flask import Flask, Request, g

from flaskapi_guard.core.checks.implementations.authentication import AuthenticationCheck
from flaskapi_guard.core.checks.implementations.emergency_mode import EmergencyModeCheck
from flaskapi_guard.core.checks.implementations.https_enforcement import (
    HttpsEnforcementCheck,
)
from flaskapi_guard.core.checks.implementations.referrer import ReferrerCheck
from flaskapi_guard.core.checks.implementations.request_size_content import (
    RequestSizeContentCheck,
)
from flaskapi_guard.core.checks.implementations.required_headers import (
    RequiredHeadersCheck,
)
from flaskapi_guard.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config."""
    config = SecurityConfig()
    config.enforce_https = True
    config.trust_x_forwarded_proto = True
    config.trusted_proxies = ["192.168.1.0/24", "10.0.0.1"]
    return config


@pytest.fixture
def mock_guard(security_config: SecurityConfig) -> Mock:
    """Create mock guard."""
    guard = Mock()
    guard.config = security_config
    guard.logger = Mock()
    guard.event_bus = Mock()
    guard.event_bus.send_https_violation_event = MagicMock()
    guard.response_factory = Mock()
    guard.response_factory.create_https_redirect = MagicMock(
        return_value=Mock(status_code=301)
    )
    return guard


@pytest.fixture
def https_check(mock_guard: Mock) -> HttpsEnforcementCheck:
    """Create HttpsEnforcementCheck instance."""
    return HttpsEnforcementCheck(mock_guard)


class TestHttpsEnforcementEdgeCases:
    """Test HttpsEnforcementCheck edge cases."""

    def test_is_trusted_proxy_cidr_match(
        self, https_check: HttpsEnforcementCheck
    ) -> None:
        """Test _is_trusted_proxy with CIDR range match."""
        # CIDR comparison returns True
        result = https_check._is_trusted_proxy("192.168.1.100")
        assert result is True

    def test_is_trusted_proxy_cidr_no_match(
        self, https_check: HttpsEnforcementCheck
    ) -> None:
        """Test _is_trusted_proxy with CIDR range no match."""
        # return False when no proxy matches
        result = https_check._is_trusted_proxy("172.16.0.1")
        assert result is False

    def test_is_trusted_proxy_single_ip_no_match(
        self, https_check: HttpsEnforcementCheck
    ) -> None:
        """Test _is_trusted_proxy with single IP that doesn't match."""
        # return False when single IP doesn't match
        result = https_check._is_trusted_proxy("10.0.0.2")
        assert result is False

    def test_check_passive_mode_no_redirect(
        self, https_check: HttpsEnforcementCheck, security_config: SecurityConfig
    ) -> None:
        """Test check in passive mode returns None instead of redirect."""
        # return None in passive mode
        security_config.passive_mode = True

        mock_request = Mock(spec=Request)
        mock_request.scheme = "http"
        mock_request.remote_addr = "1.2.3.4"
        mock_request.headers = {}

        app = Flask(__name__)
        with app.test_request_context():
            g.route_config = None
            result = https_check.check(mock_request)
            assert result is None

    def test_check_with_cidr_trusted_proxy_https_forwarded(
        self, https_check: HttpsEnforcementCheck
    ) -> None:
        """Test check with CIDR-matched proxy forwarding HTTPS."""
        # CIDR match allows X-Forwarded-Proto
        mock_request = Mock(spec=Request)
        mock_request.scheme = "http"
        mock_request.remote_addr = "192.168.1.50"  # Within CIDR range
        mock_request.headers = {"X-Forwarded-Proto": "https"}

        app = Flask(__name__)
        with app.test_request_context():
            g.route_config = None
            # Should pass because trusted proxy forwarded HTTPS
            result = https_check.check(mock_request)
            assert result is None

    @pytest.mark.parametrize(
        "connecting_ip,expected",
        [
            ("192.168.1.1", True),  # In CIDR range
            ("192.168.1.255", True),  # In CIDR range
            ("192.168.2.1", False),  # Outside CIDR range
            ("10.0.0.1", True),  # Exact single IP match
            ("10.0.0.2", False),  # Different single IP
            ("8.8.8.8", False),  # Completely different IP
        ],
    )
    def test_is_trusted_proxy_various_ips(
        self, https_check: HttpsEnforcementCheck, connecting_ip: str, expected: bool
    ) -> None:
        """Test _is_trusted_proxy with various IPs covering all branches."""
        result = https_check._is_trusted_proxy(connecting_ip)
        assert result == expected


class TestReferrerCheckPassiveModeUnit:
    """Unit tests for ReferrerCheck passive mode."""

    def test_handle_missing_referrer_passive_mode_unit(self) -> None:
        """Test _handle_missing_referrer returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()

        check = ReferrerCheck(guard)
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        request = Mock()

        with patch(
            "flaskapi_guard.core.checks.implementations.referrer.log_activity",
            return_value=MagicMock(),
        ):
            result = check._handle_missing_referrer(request, route_config)
            assert result is None

    def test_handle_invalid_referrer_passive_mode_unit(self) -> None:
        """Test _handle_invalid_referrer returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()

        check = ReferrerCheck(guard)
        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        request = Mock()

        with patch(
            "flaskapi_guard.core.checks.implementations.referrer.log_activity",
            return_value=MagicMock(),
        ):
            result = check._handle_invalid_referrer(
                request, "https://evil.com", route_config
            )
            assert result is None


class TestAuthenticationCheckPassiveModeUnit:
    """Unit test for AuthenticationCheck passive mode."""

    def test_authentication_check_passive_mode_unit(self) -> None:
        """Test authentication check returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()

        check = AuthenticationCheck(guard)
        route_config = RouteConfig()
        route_config.auth_required = "bearer"

        request = Mock()
        request.headers = {}

        app = Flask(__name__)
        with app.test_request_context():
            g.route_config = route_config
            with patch(
                "flaskapi_guard.core.checks.implementations.authentication.log_activity",
                return_value=MagicMock(),
            ):
                result = check.check(request)
                assert result is None


class TestEmergencyModeCheckPassiveModeUnit:
    """Unit test for EmergencyModeCheck passive mode."""

    def test_emergency_mode_check_no_client_ip_extracts_unit(self) -> None:
        """Test emergency mode extracts IP when client_ip is None - UNIT TEST."""
        # client_ip extracted when None
        config = SecurityConfig()
        config.emergency_mode = True
        config.emergency_whitelist = ["192.168.1.1"]

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()
        guard.agent_handler = None
        guard.create_error_response = MagicMock(return_value=Mock(status_code=503))

        check = EmergencyModeCheck(guard)

        request = Mock()

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = None
            with patch(
                "flaskapi_guard.core.checks.implementations.emergency_mode.extract_client_ip",
                return_value="8.8.8.8",  # Extracted IP not in whitelist
            ):
                with patch(
                    "flaskapi_guard.core.checks.implementations.emergency_mode.log_activity",
                    return_value=MagicMock(),
                ):
                    result = check.check(request)
                    assert result is not None  # Blocked because not in whitelist

    def test_emergency_mode_check_passive_mode_unit(self) -> None:
        """Test emergency mode check returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True
        config.emergency_mode = True

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()

        check = EmergencyModeCheck(guard)

        request = Mock()

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = "8.8.8.8"  # Not in whitelist
            with patch(
                "flaskapi_guard.core.checks.implementations.emergency_mode.log_activity",
                return_value=MagicMock(),
            ):
                result = check.check(request)
                assert result is None


class TestRequestSizeContentCheckPassiveModeUnit:
    """Unit tests for RequestSizeContentCheck passive mode."""

    def test_check_request_size_limit_passive_mode_unit(self) -> None:
        """Test _check_request_size_limit returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()

        check = RequestSizeContentCheck(guard)
        route_config = RouteConfig()
        route_config.max_request_size = 100

        request = Mock()
        request.headers = {"content-length": "1000"}

        with patch(
            "flaskapi_guard.core.checks.implementations.request_size_content.log_activity",
            return_value=MagicMock(),
        ):
            result = check._check_request_size_limit(request, route_config)
            assert result is None

    def test_check_content_type_allowed_passive_mode_unit(self) -> None:
        """Test _check_content_type_allowed returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()

        check = RequestSizeContentCheck(guard)
        route_config = RouteConfig()
        route_config.allowed_content_types = ["application/json"]

        request = Mock()
        request.headers = {"content-type": "text/html"}

        with patch(
            "flaskapi_guard.core.checks.implementations.request_size_content.log_activity",
            return_value=MagicMock(),
        ):
            result = check._check_content_type_allowed(request, route_config)
            assert result is None


class TestRequiredHeadersCheckPassiveModeUnit:
    """Unit test for RequiredHeadersCheck passive mode."""

    def test_required_headers_check_passive_mode_unit(self) -> None:
        """Test required headers check returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()

        check = RequiredHeadersCheck(guard)
        route_config = RouteConfig()
        route_config.required_headers = {"X-API-Key": "required"}

        request = Mock()
        request.headers = {}

        app = Flask(__name__)
        with app.test_request_context():
            g.route_config = route_config
            with patch(
                "flaskapi_guard.core.checks.implementations.required_headers.log_activity",
                return_value=MagicMock(),
            ):
                result = check.check(request)
                assert result is None


class TestEmergencyModeWhitelistedIP:
    """Test EmergencyModeCheck allows whitelisted IPs with log line."""

    def test_emergency_mode_whitelisted_ip_allowed(self) -> None:
        """Test whitelisted IP is allowed during emergency mode and log line is hit."""
        config = SecurityConfig()
        config.emergency_mode = True
        config.emergency_whitelist = ["1.2.3.4"]

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()

        check = EmergencyModeCheck(guard)
        request = Mock()

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = "1.2.3.4"  # In whitelist
            with patch(
                "flaskapi_guard.core.checks.implementations.emergency_mode.log_activity",
            ) as mock_log:
                result = check.check(request)
                assert result is None  # Allowed
                # Verify the "allowed" log was called
                mock_log.assert_called_once()
                call_kwargs = mock_log.call_args
                assert "Allowed access" in call_kwargs[1]["reason"]


class TestUserAgentRouteSpecificBlock:
    """Test UserAgentCheck with route-specific blocked agents."""

    def test_route_specific_blocked_user_agent(self) -> None:
        """Test user agent blocked by route-specific config sends decorator event."""
        from flaskapi_guard.core.checks.implementations.user_agent import UserAgentCheck

        config = SecurityConfig()
        config.passive_mode = False
        config.blocked_user_agents = []  # No global blocks

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()
        guard.create_error_response = MagicMock(
            return_value=Mock(status_code=403)
        )

        check = UserAgentCheck(guard)

        route_config = RouteConfig()
        route_config.blocked_user_agents = ["evilbot"]

        request = Mock()
        request.headers = {"User-Agent": "evilbot"}

        app = Flask(__name__)
        with app.test_request_context():
            g.is_whitelisted = False
            g.route_config = route_config
            with patch(
                "flaskapi_guard.core.checks.implementations.user_agent.log_activity",
            ):
                with patch(
                    "flaskapi_guard.core.checks.implementations.user_agent.check_user_agent_allowed",
                    return_value=False,
                ):
                    result = check.check(request)
                    assert result is not None
                    assert result.status_code == 403
                    # Verify decorator_violation event was sent
                    guard.event_bus.send_middleware_event.assert_called_once()
                    call_kwargs = guard.event_bus.send_middleware_event.call_args[1]
                    assert call_kwargs["event_type"] == "decorator_violation"


class TestCustomRequestCheckEvent:
    """Test CustomRequestCheck event sending when custom check blocks."""

    def test_custom_request_check_sends_event(self) -> None:
        """Test custom request check sends event when blocking."""
        from flaskapi_guard.core.checks.implementations.custom_request import (
            CustomRequestCheck,
        )

        config = SecurityConfig()
        config.passive_mode = False
        config.custom_request_check = lambda r: Mock(status_code=403)

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()
        guard.response_factory = Mock()
        guard.response_factory.apply_modifier = MagicMock(
            return_value=Mock(status_code=403)
        )

        check = CustomRequestCheck(guard)
        request = Mock()

        result = check.check(request)
        assert result is not None
        guard.event_bus.send_middleware_event.assert_called_once()
        call_kwargs = guard.event_bus.send_middleware_event.call_args[1]
        assert call_kwargs["event_type"] == "custom_request_check"


class TestSuspiciousActivityCheckPassiveModeUnit:
    """Unit test for SuspiciousActivityCheck passive mode."""

    def test_suspicious_activity_check_no_client_ip_unit(self) -> None:
        """Test suspicious activity check returns None when no client_ip - UNIT TEST."""
        # return None when client_ip is None
        config = SecurityConfig()
        config.passive_mode = False
        config.enable_penetration_detection = True

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()
        guard.route_resolver = Mock()
        guard.route_resolver.should_bypass_check = Mock(return_value=False)

        check = SuspiciousActivityCheck(guard)

        request = Mock()

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = None  # No client IP
            g.route_config = None
            g.is_whitelisted = False
            result = check.check(request)
            assert result is None

    def test_suspicious_activity_check_passive_mode_unit(self) -> None:
        """Test suspicious activity check returns None in passive mode - UNIT TEST."""
        # return None in passive mode
        config = SecurityConfig()
        config.passive_mode = True
        config.enable_penetration_detection = True

        guard = Mock()
        guard.config = config
        guard.logger = Mock()
        guard.event_bus = Mock()
        guard.event_bus.send_middleware_event = MagicMock()
        guard.route_resolver = Mock()
        guard.route_resolver.should_bypass_check = Mock(return_value=False)
        guard.suspicious_request_counts = {}  # Dict, not Mock

        check = SuspiciousActivityCheck(guard)

        request = Mock()

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = "1.2.3.4"
            g.route_config = None
            g.is_whitelisted = False
            with patch(
                "flaskapi_guard.core.checks.implementations.suspicious_activity.detect_penetration_patterns",
                return_value=(True, "SQL injection"),
            ):
                with patch(
                    "flaskapi_guard.core.checks.implementations.suspicious_activity.log_activity",
                    return_value=MagicMock(),
                ):
                    result = check.check(request)
                    assert result is None
                    # Verify count was incremented
                    assert guard.suspicious_request_counts["1.2.3.4"] == 1
