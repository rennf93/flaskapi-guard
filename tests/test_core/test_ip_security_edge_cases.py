from unittest.mock import MagicMock, Mock, patch

import pytest
from flask import Flask, Request, g

from flaskapi_guard.core.checks.implementations.ip_security import IpSecurityCheck
from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config."""
    config = SecurityConfig()
    config.passive_mode = False
    return config


@pytest.fixture
def mock_guard(security_config: SecurityConfig) -> Mock:
    """Create mock guard."""
    guard = Mock()
    guard.config = security_config
    guard.logger = Mock()
    guard.event_bus = Mock()
    guard.event_bus.send_middleware_event = MagicMock()
    guard.create_error_response = MagicMock(return_value=Mock(status_code=403))
    guard.route_resolver = Mock()
    guard.route_resolver.should_bypass_check = Mock(return_value=False)
    guard.geo_ip_handler = Mock()
    return guard


@pytest.fixture
def ip_security_check(mock_guard: Mock) -> IpSecurityCheck:
    """Create IpSecurityCheck instance."""
    return IpSecurityCheck(mock_guard)


class TestIpSecurityEdgeCases:
    """Test IpSecurityCheck edge cases."""

    def test_check_banned_ip_bypass(self, ip_security_check: IpSecurityCheck) -> None:
        """Test _check_banned_ip when ip_ban check is bypassed."""
        # return None when should_bypass_check returns True
        route_config = RouteConfig()
        mock_request = Mock(spec=Request)
        # Replace route_resolver with new mock
        ip_security_check.middleware.route_resolver = Mock()
        ip_security_check.middleware.route_resolver.should_bypass_check = Mock(
            return_value=True
        )

        result = ip_security_check._check_banned_ip(
            mock_request, "1.2.3.4", route_config
        )
        assert result is None

    def test_check_banned_ip_passive_mode(
        self,
        ip_security_check: IpSecurityCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_banned_ip in passive mode returns None."""
        # return None in passive mode
        security_config.passive_mode = True
        mock_request = Mock(spec=Request)

        with patch(
            "flaskapi_guard.core.checks.implementations.ip_security.ip_ban_manager"
        ) as mock_ban_mgr:
            mock_ban_mgr.is_ip_banned = MagicMock(return_value=True)

            with patch(
                "flaskapi_guard.core.checks.implementations.ip_security.log_activity"
            ) as mock_log:
                mock_log.return_value = MagicMock()

                result = ip_security_check._check_banned_ip(
                    mock_request, "1.2.3.4", None
                )
                assert result is None

    def test_check_route_ip_restrictions_passive_mode(
        self,
        ip_security_check: IpSecurityCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_route_ip_restrictions in passive mode returns None."""
        # return None in passive mode
        security_config.passive_mode = True
        route_config = RouteConfig()
        mock_request = Mock(spec=Request)

        with patch(
            "flaskapi_guard.core.checks.implementations.ip_security.check_route_ip_access"
        ) as mock_check:
            # Return False to trigger IP not allowed path
            mock_check.return_value = False

            with patch(
                "flaskapi_guard.core.checks.implementations.ip_security.log_activity"
            ) as mock_log:
                mock_log.return_value = None

                result = ip_security_check._check_route_ip_restrictions(
                    mock_request, "1.2.3.4", route_config
                )
                assert result is None

    def test_check_no_client_ip(self, ip_security_check: IpSecurityCheck) -> None:
        """Test check when client_ip is None."""
        mock_request = Mock(spec=Request)

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = None
            g.route_config = None
            # return None when client_ip is None
            result = ip_security_check.check(mock_request)
            assert result is None

    def test_check_global_ip_restrictions_passive_mode(
        self,
        ip_security_check: IpSecurityCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_global_ip_restrictions in passive mode."""
        # return None in passive mode
        security_config.passive_mode = True
        mock_request = Mock(spec=Request)

        app = Flask(__name__)
        with app.test_request_context():
            g.is_whitelisted = False
            with patch(
                "flaskapi_guard.core.checks.implementations.ip_security.is_ip_allowed"
            ) as mock_allowed:
                mock_allowed.return_value = False

                with patch(
                    "flaskapi_guard.core.checks.implementations.ip_security.log_activity"
                ) as mock_log:
                    mock_log.return_value = MagicMock()

                    result = ip_security_check._check_global_ip_restrictions(
                        mock_request, "1.2.3.4"
                    )
                    assert result is None

    def test_check_with_bypass_ip_check(
        self, ip_security_check: IpSecurityCheck
    ) -> None:
        """Test check when ip check is bypassed."""
        mock_request = Mock(spec=Request)

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = "1.2.3.4"
            g.route_config = None
            # Setup to bypass IP ban check first
            with patch(
                "flaskapi_guard.core.checks.implementations.ip_security.ip_ban_manager"
            ) as mock_ban_mgr:
                mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

                # Now bypass the main IP check - recreate the mock properly
                mock_bypass = Mock(side_effect=lambda check, config: check == "ip")
                # Replace route_resolver with new mock
                ip_security_check.middleware.route_resolver = Mock()
                ip_security_check.middleware.route_resolver.should_bypass_check = (
                    mock_bypass
                )

                result = ip_security_check.check(mock_request)
                assert result is None

    def test_full_flow_with_route_config(
        self, ip_security_check: IpSecurityCheck
    ) -> None:
        """Test full flow with route config."""
        route_config = RouteConfig()
        mock_request = Mock(spec=Request)

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = "1.2.3.4"
            g.route_config = route_config
            with patch(
                "flaskapi_guard.core.checks.implementations.ip_security.ip_ban_manager"
            ) as mock_ban_mgr:
                mock_ban_mgr.is_ip_banned = MagicMock(return_value=False)

                with patch(
                    "flaskapi_guard.core.checks.implementations.ip_security.check_route_ip_access"
                ) as mock_check:
                    mock_check.return_value = True

                    result = ip_security_check.check(mock_request)
                    assert result is None
