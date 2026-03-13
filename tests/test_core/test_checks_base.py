from unittest.mock import MagicMock, Mock

import pytest
from flask import Request, Response

from flaskapi_guard.core.checks.base import SecurityCheck


class ConcreteSecurityCheck(SecurityCheck):
    """Concrete implementation of SecurityCheck for testing."""

    def check(self, request: Request) -> Response | None:
        """Implement abstract check method."""
        return None

    @property
    def check_name(self) -> str:
        """Implement abstract check_name property."""
        return "test_check"


@pytest.fixture
def mock_guard() -> Mock:
    """Create mock guard."""
    guard = Mock()
    guard.config = Mock()
    guard.config.passive_mode = False
    guard.logger = Mock()
    guard.event_bus = Mock()
    guard.event_bus.send_middleware_event = MagicMock()
    guard.create_error_response = MagicMock(
        return_value=Response("Forbidden", status=403)
    )
    return guard


@pytest.fixture
def security_check(mock_guard: Mock) -> ConcreteSecurityCheck:
    """Create ConcreteSecurityCheck instance."""
    return ConcreteSecurityCheck(mock_guard)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock(spec=Request)
    request.path = "/test"
    request.remote_addr = "127.0.0.1"
    return request


class TestSecurityCheck:
    """Test SecurityCheck base class."""

    def test_cannot_instantiate_abstract_class(self, mock_guard: Mock) -> None:
        """Test that SecurityCheck cannot be instantiated directly."""
        with pytest.raises(TypeError, match="Can't instantiate abstract class"):
            SecurityCheck(mock_guard)

    def test_init(self, mock_guard: Mock) -> None:
        """Test SecurityCheck initialization."""
        check = ConcreteSecurityCheck(mock_guard)
        assert check.middleware == mock_guard
        assert check.config == mock_guard.config
        assert check.logger == mock_guard.logger

    def test_check_abstract_method(
        self, security_check: ConcreteSecurityCheck, mock_request: Mock
    ) -> None:
        """Test abstract check method implementation."""
        result = security_check.check(mock_request)
        assert result is None

    def test_check_name_abstract_property(
        self, security_check: ConcreteSecurityCheck
    ) -> None:
        """Test abstract check_name property implementation."""
        assert security_check.check_name == "test_check"

    def test_send_event(
        self,
        security_check: ConcreteSecurityCheck,
        mock_request: Mock,
        mock_guard: Mock,
    ) -> None:
        """Test send_event method."""
        security_check.send_event(
            event_type="test_event",
            request=mock_request,
            action_taken="blocked",
            reason="test reason",
            extra_data="test",
        )

        mock_guard.event_bus.send_middleware_event.assert_called_once_with(
            event_type="test_event",
            request=mock_request,
            action_taken="blocked",
            reason="test reason",
            extra_data="test",
        )

    def test_send_event_no_extra_kwargs(
        self,
        security_check: ConcreteSecurityCheck,
        mock_request: Mock,
        mock_guard: Mock,
    ) -> None:
        """Test send_event method without extra kwargs."""
        security_check.send_event(
            event_type="test_event",
            request=mock_request,
            action_taken="allowed",
            reason="passed checks",
        )

        mock_guard.event_bus.send_middleware_event.assert_called_once_with(
            event_type="test_event",
            request=mock_request,
            action_taken="allowed",
            reason="passed checks",
        )

    def test_create_error_response(
        self, security_check: ConcreteSecurityCheck, mock_guard: Mock
    ) -> None:
        """Test create_error_response method."""
        response = security_check.create_error_response(403, "Forbidden")

        assert response.status_code == 403
        mock_guard.create_error_response.assert_called_once_with(403, "Forbidden")

    def test_create_error_response_different_codes(
        self, security_check: ConcreteSecurityCheck, mock_guard: Mock
    ) -> None:
        """Test create_error_response with different status codes."""
        mock_guard.create_error_response.reset_mock()
        mock_guard.create_error_response.return_value = Response(
            "Too Many Requests", status=429
        )

        response = security_check.create_error_response(429, "Too Many Requests")

        assert response.status_code == 429
        mock_guard.create_error_response.assert_called_once_with(
            429, "Too Many Requests"
        )

    def test_is_passive_mode_false(self, security_check: ConcreteSecurityCheck) -> None:
        """Test is_passive_mode when passive mode is disabled."""
        result = security_check.is_passive_mode()
        assert result is False

    def test_is_passive_mode_true(
        self, security_check: ConcreteSecurityCheck, mock_guard: Mock
    ) -> None:
        """Test is_passive_mode when passive mode is enabled."""
        mock_guard.config.passive_mode = True
        result = security_check.is_passive_mode()
        assert result is True
