from unittest.mock import MagicMock, Mock, patch

import pytest
from flask import Flask, Request, Response, g

from flaskapi_guard.core.checks.implementations.rate_limit import RateLimitCheck
from flaskapi_guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config."""
    config = SecurityConfig()
    config.passive_mode = False
    config.endpoint_rate_limits = {"/api/test": (5, 60)}
    return config


@pytest.fixture
def mock_guard(security_config: SecurityConfig) -> Mock:
    """Create mock guard."""
    guard = Mock()
    guard.config = security_config
    guard.logger = Mock()
    guard.event_bus = Mock()
    guard.event_bus.send_middleware_event = MagicMock()
    guard.create_error_response = MagicMock(
        return_value=Response("Too Many Requests", status=429)
    )
    guard.route_resolver = Mock()
    guard.route_resolver.should_bypass_check = Mock(return_value=False)
    guard.redis_handler = None
    guard.rate_limit_handler = Mock()
    guard.rate_limit_handler.check_rate_limit = MagicMock(return_value=None)
    return guard


@pytest.fixture
def rate_limit_check(mock_guard: Mock) -> RateLimitCheck:
    """Create RateLimitCheck instance."""
    return RateLimitCheck(mock_guard)


class TestRateLimitEdgeCases:
    """Test RateLimitCheck edge cases."""

    def test_apply_rate_limit_check_passive_mode(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _apply_rate_limit_check returns None in passive mode."""
        security_config.passive_mode = True
        mock_request = Mock(spec=Request)

        with patch.object(
            rate_limit_check, "_create_rate_handler"
        ) as mock_create_handler:
            mock_handler = Mock()
            mock_handler.check_rate_limit = MagicMock(
                return_value=Response("Too Many Requests", status=429)
            )
            mock_create_handler.return_value = mock_handler

            result = rate_limit_check._apply_rate_limit_check(
                mock_request,
                "1.2.3.4",
                5,
                60,
                "test_event",
                {"reason": "test"},
            )
            assert result is None

    def test_check_global_rate_limit_passive_mode(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_global_rate_limit returns None in passive mode."""
        security_config.passive_mode = True
        mock_request = Mock(spec=Request)

        mock_handler = Mock()
        mock_handler.check_rate_limit = MagicMock(
            return_value=Response("Too Many Requests", status=429)
        )
        rate_limit_check.middleware.rate_limit_handler = mock_handler

        result = rate_limit_check._check_global_rate_limit(mock_request, "1.2.3.4")
        assert result is None

    def test_check_no_client_ip(self, rate_limit_check: RateLimitCheck) -> None:
        """Test check returns None when client_ip is None."""
        mock_request = Mock(spec=Request)

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = None
            g.route_config = None
            g.is_whitelisted = False
            result = rate_limit_check.check(mock_request)
            assert result is None

    def test_check_global_rate_limit_not_exceeded(
        self, rate_limit_check: RateLimitCheck
    ) -> None:
        """Test _check_global_rate_limit when rate limit not exceeded."""
        mock_request = Mock(spec=Request)

        mock_handler = Mock()
        mock_handler.check_rate_limit = MagicMock(return_value=None)
        rate_limit_check.middleware.rate_limit_handler = mock_handler

        result = rate_limit_check._check_global_rate_limit(mock_request, "1.2.3.4")
        assert result is None

    def test_check_global_rate_limit_exceeded_active_mode(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_global_rate_limit returns response in active mode."""
        security_config.passive_mode = False
        mock_request = Mock(spec=Request)

        response = Response("Too Many Requests", status=429)
        mock_handler = Mock()
        mock_handler.check_rate_limit = MagicMock(return_value=response)
        rate_limit_check.middleware.rate_limit_handler = mock_handler

        result = rate_limit_check._check_global_rate_limit(mock_request, "1.2.3.4")
        assert result == response

    def test_apply_rate_limit_check_active_mode_exceeded(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _apply_rate_limit_check returns response in active mode."""
        security_config.passive_mode = False
        mock_request = Mock(spec=Request)

        with patch.object(
            rate_limit_check, "_create_rate_handler"
        ) as mock_create_handler:
            mock_handler = Mock()
            response = Response("Too Many Requests", status=429)
            mock_handler.check_rate_limit = MagicMock(return_value=response)
            mock_create_handler.return_value = mock_handler

            result = rate_limit_check._apply_rate_limit_check(
                mock_request,
                "1.2.3.4",
                5,
                60,
                "test_event",
                {"reason": "test"},
            )
            assert result == response

    def test_apply_rate_limit_check_not_exceeded(
        self, rate_limit_check: RateLimitCheck
    ) -> None:
        """Test _apply_rate_limit_check when rate limit not exceeded."""
        mock_request = Mock(spec=Request)

        with patch.object(
            rate_limit_check, "_create_rate_handler"
        ) as mock_create_handler:
            mock_handler = Mock()
            mock_handler.check_rate_limit = MagicMock(return_value=None)
            mock_create_handler.return_value = mock_handler

            result = rate_limit_check._apply_rate_limit_check(
                mock_request,
                "1.2.3.4",
                5,
                60,
                "test_event",
                {"reason": "test"},
            )
            assert result is None

    def test_check_geo_rate_limit_no_geo_handler(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_geo_rate_limit returns None when geo_handler is None."""
        security_config.geo_ip_handler = None
        mock_request = Mock(spec=Request)
        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60)}

        result = rate_limit_check._check_geo_rate_limit(
            mock_request, "1.2.3.4", route_config
        )
        assert result is None

    def test_check_geo_rate_limit_country_match(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_geo_rate_limit when country matches geo limits."""
        geo_handler = Mock()
        geo_handler.get_country.return_value = "US"
        security_config.geo_ip_handler = geo_handler

        mock_request = Mock(spec=Request)
        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60)}

        response = Response("Too Many Requests", status=429)
        with patch.object(
            rate_limit_check, "_apply_rate_limit_check", new_callable=MagicMock
        ) as mock_apply:
            mock_apply.return_value = response
            result = rate_limit_check._check_geo_rate_limit(
                mock_request, "1.2.3.4", route_config
            )
            assert result == response
            mock_apply.assert_called_once()

    def test_check_geo_rate_limit_wildcard_match(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """
        Test _check_geo_rate_limit falls back to wildcard when country not in limits.
        """
        geo_handler = Mock()
        geo_handler.get_country.return_value = "FR"
        security_config.geo_ip_handler = geo_handler

        mock_request = Mock(spec=Request)
        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60), "*": (5, 30)}

        response = Response("Too Many Requests", status=429)
        with patch.object(
            rate_limit_check, "_apply_rate_limit_check", new_callable=MagicMock
        ) as mock_apply:
            mock_apply.return_value = response
            result = rate_limit_check._check_geo_rate_limit(
                mock_request, "1.2.3.4", route_config
            )
            assert result == response
            call_args = mock_apply.call_args
            assert call_args[0][2] == 5
            assert call_args[0][3] == 30

    def test_check_geo_rate_limit_no_match(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_geo_rate_limit returns None when no country or wildcard match."""
        geo_handler = Mock()
        geo_handler.get_country.return_value = "FR"
        security_config.geo_ip_handler = geo_handler

        mock_request = Mock(spec=Request)
        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60)}

        result = rate_limit_check._check_geo_rate_limit(
            mock_request, "1.2.3.4", route_config
        )
        assert result is None

    def test_check_geo_rate_limit_no_country(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test _check_geo_rate_limit with wildcard when country is None."""
        geo_handler = Mock()
        geo_handler.get_country.return_value = None
        security_config.geo_ip_handler = geo_handler

        mock_request = Mock(spec=Request)
        route_config = Mock()
        route_config.geo_rate_limits = {"*": (5, 30)}

        response = Response("Too Many Requests", status=429)
        with patch.object(
            rate_limit_check, "_apply_rate_limit_check", new_callable=MagicMock
        ) as mock_apply:
            mock_apply.return_value = response
            result = rate_limit_check._check_geo_rate_limit(
                mock_request, "1.2.3.4", route_config
            )
            assert result == response

    def test_check_returns_geo_rate_limit_response(
        self,
        rate_limit_check: RateLimitCheck,
        security_config: SecurityConfig,
    ) -> None:
        """Test check() returns geo rate limit response at priority 3."""
        mock_request = Mock(spec=Request)
        mock_request.path = "/api/test"

        route_config = Mock()
        route_config.geo_rate_limits = {"US": (10, 60)}
        route_config.rate_limit = None

        app = Flask(__name__)
        with app.test_request_context():
            g.client_ip = "1.2.3.4"
            g.route_config = route_config
            g.is_whitelisted = False
            security_config.endpoint_rate_limits = {}

            geo_response = Response("Too Many Requests", status=429)
            with patch.object(
                rate_limit_check, "_check_geo_rate_limit", new_callable=MagicMock
            ) as mock_geo:
                mock_geo.return_value = geo_response
                result = rate_limit_check.check(mock_request)
                assert result == geo_response
