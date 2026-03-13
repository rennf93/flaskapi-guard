from unittest.mock import MagicMock, Mock

import pytest
from flask import Response

from flaskapi_guard.core.bypass.context import BypassContext
from flaskapi_guard.core.bypass.handler import BypassHandler
from flaskapi_guard.decorators.base import RouteConfig


@pytest.fixture
def mock_response_factory() -> Mock:
    """Create mock response factory."""
    factory = Mock()
    factory.apply_modifier = MagicMock(return_value=Response("OK", status=200))
    return factory


@pytest.fixture
def mock_validator() -> Mock:
    """Create mock validator."""
    validator = Mock()
    validator.is_path_excluded = MagicMock(return_value=False)
    return validator


@pytest.fixture
def mock_route_resolver() -> Mock:
    """Create mock route resolver."""
    resolver = Mock()
    resolver.should_bypass_check = Mock(return_value=False)
    return resolver


@pytest.fixture
def mock_event_bus() -> Mock:
    """Create mock event bus."""
    event_bus = Mock()
    event_bus.send_middleware_event = MagicMock()
    return event_bus


@pytest.fixture
def mock_config() -> Mock:
    """Create mock config."""
    config = Mock()
    config.passive_mode = False
    return config


@pytest.fixture
def bypass_context(
    mock_config: Mock,
    mock_response_factory: Mock,
    mock_validator: Mock,
    mock_route_resolver: Mock,
    mock_event_bus: Mock,
) -> BypassContext:
    """Create bypass context."""
    return BypassContext(
        config=mock_config,
        logger=Mock(),
        response_factory=mock_response_factory,
        validator=mock_validator,
        route_resolver=mock_route_resolver,
        event_bus=mock_event_bus,
    )


@pytest.fixture
def bypass_handler(bypass_context: BypassContext) -> BypassHandler:
    """Create BypassHandler instance."""
    return BypassHandler(bypass_context)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock()
    request.path = "/test"
    request.remote_addr = "127.0.0.1"
    return request


class TestBypassHandler:
    """Test BypassHandler class."""

    def test_init(self, bypass_context: BypassContext) -> None:
        """Test BypassHandler initialization."""
        handler = BypassHandler(bypass_context)
        assert handler.context == bypass_context

    def test_handle_passthrough_no_client(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
    ) -> None:
        """Test handle_passthrough when request has no client."""
        mock_request.remote_addr = None

        response = bypass_handler.handle_passthrough(mock_request)

        # Flask extension returns None to let Flask proceed
        assert response is None

    def test_handle_passthrough_excluded_path(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        mock_validator: Mock,
    ) -> None:
        """Test handle_passthrough when path is excluded."""
        mock_validator.is_path_excluded.return_value = True

        response = bypass_handler.handle_passthrough(mock_request)

        # Flask extension returns None to let Flask proceed
        assert response is None
        mock_validator.is_path_excluded.assert_called_once_with(mock_request)

    def test_handle_passthrough_no_bypass(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        mock_validator: Mock,
    ) -> None:
        """Test handle_passthrough when no bypass conditions met."""
        mock_validator.is_path_excluded.return_value = False

        response = bypass_handler.handle_passthrough(mock_request)

        assert response is None
        mock_validator.is_path_excluded.assert_called_once_with(mock_request)

    def test_handle_security_bypass_no_route_config(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
    ) -> None:
        """Test handle_security_bypass when no route config provided."""
        response = bypass_handler.handle_security_bypass(mock_request, None)

        assert response is None

    def test_handle_security_bypass_should_not_bypass(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        mock_route_resolver: Mock,
    ) -> None:
        """Test handle_security_bypass when should_bypass_check returns False."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"ip_check"}
        mock_route_resolver.should_bypass_check.return_value = False

        response = bypass_handler.handle_security_bypass(mock_request, route_config)

        assert response is None
        mock_route_resolver.should_bypass_check.assert_called_once_with(
            "all", route_config
        )

    def test_handle_security_bypass_active_mode(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        mock_route_resolver: Mock,
        mock_event_bus: Mock,
        bypass_context: BypassContext,
    ) -> None:
        """Test handle_security_bypass in active mode (passive_mode=False)."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}
        mock_route_resolver.should_bypass_check.return_value = True
        bypass_context.config.passive_mode = False

        response = bypass_handler.handle_security_bypass(mock_request, route_config)

        # Flask extension returns None to let Flask proceed
        assert response is None
        mock_event_bus.send_middleware_event.assert_called_once()
        call_args = mock_event_bus.send_middleware_event.call_args[1]
        assert call_args["event_type"] == "security_bypass"
        assert call_args["action_taken"] == "all_checks_bypassed"
        assert call_args["endpoint"] == "/test"

    def test_handle_security_bypass_passive_mode(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        mock_route_resolver: Mock,
        mock_event_bus: Mock,
        bypass_context: BypassContext,
    ) -> None:
        """Test handle_security_bypass in passive mode (passive_mode=True)."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}
        mock_route_resolver.should_bypass_check.return_value = True
        bypass_context.config.passive_mode = True

        response = bypass_handler.handle_security_bypass(mock_request, route_config)

        # In passive mode, should return None
        assert response is None
        mock_event_bus.send_middleware_event.assert_called_once()

    def test_handle_security_bypass_with_multiple_bypassed_checks(
        self,
        bypass_handler: BypassHandler,
        mock_request: Mock,
        mock_route_resolver: Mock,
        mock_event_bus: Mock,
        bypass_context: BypassContext,
    ) -> None:
        """Test handle_security_bypass with multiple bypassed checks."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"ip_check", "rate_limit", "https_check"}
        mock_route_resolver.should_bypass_check.return_value = True
        bypass_context.config.passive_mode = False

        response = bypass_handler.handle_security_bypass(mock_request, route_config)

        assert response is None
        mock_event_bus.send_middleware_event.assert_called_once()
        call_args = mock_event_bus.send_middleware_event.call_args[1]
        assert set(call_args["bypassed_checks"]) == {
            "ip_check",
            "rate_limit",
            "https_check",
        }
