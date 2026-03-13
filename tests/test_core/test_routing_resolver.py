from unittest.mock import Mock

import pytest
from flask import Flask, Request

from flaskapi_guard.core.routing.context import RoutingContext
from flaskapi_guard.core.routing.resolver import RouteConfigResolver
from flaskapi_guard.decorators.base import BaseSecurityDecorator, RouteConfig


@pytest.fixture
def mock_config() -> Mock:
    """Create mock config."""
    config = Mock()
    config.block_cloud_providers = {"aws", "gcp"}
    return config


@pytest.fixture
def mock_guard_decorator() -> BaseSecurityDecorator:
    """Create mock guard decorator."""
    decorator = Mock(spec=BaseSecurityDecorator)
    route_config = RouteConfig()
    route_config.bypassed_checks = {"rate_limit"}
    decorator.get_route_config = Mock(return_value=route_config)
    return decorator


@pytest.fixture
def routing_context(
    mock_config: Mock, mock_guard_decorator: BaseSecurityDecorator
) -> RoutingContext:
    """Create routing context."""
    return RoutingContext(
        config=mock_config,
        logger=Mock(),
        guard_decorator=mock_guard_decorator,
    )


@pytest.fixture
def resolver(routing_context: RoutingContext) -> RouteConfigResolver:
    """Create RouteConfigResolver instance."""
    return RouteConfigResolver(routing_context)


class TestRouteConfigResolver:
    """Test RouteConfigResolver class."""

    def test_init(self, routing_context: RoutingContext) -> None:
        """Test RouteConfigResolver initialization."""
        resolver = RouteConfigResolver(routing_context)
        assert resolver.context == routing_context

    def test_get_guard_decorator_from_app_extensions(
        self, resolver: RouteConfigResolver, mock_guard_decorator: BaseSecurityDecorator
    ) -> None:
        """Test get_guard_decorator from app extensions."""
        app = Flask(__name__)
        app.extensions["flaskapi_guard"] = {"guard_decorator": mock_guard_decorator}

        result = resolver.get_guard_decorator(app)
        assert result == mock_guard_decorator

    def test_get_guard_decorator_from_context(
        self, resolver: RouteConfigResolver, mock_guard_decorator: BaseSecurityDecorator
    ) -> None:
        """Test get_guard_decorator from context when app has no extensions."""
        app = Flask(__name__)
        # No flaskapi_guard in extensions

        result = resolver.get_guard_decorator(app)
        assert result == mock_guard_decorator

    def test_get_guard_decorator_none_when_not_base_security_decorator(
        self, resolver: RouteConfigResolver
    ) -> None:
        """
        Test returns context decorator when app extensions have wrong type.
        """
        app = Flask(__name__)
        app.extensions["flaskapi_guard"] = {"guard_decorator": "not a decorator"}

        result = resolver.get_guard_decorator(app)
        # Should fall back to context decorator
        assert result == resolver.context.guard_decorator

    def test_get_guard_decorator_none_when_no_app(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test get_guard_decorator with None app."""
        result = resolver.get_guard_decorator(None)
        assert result == resolver.context.guard_decorator

    def test_get_guard_decorator_none_when_context_has_none(self) -> None:
        """Test get_guard_decorator when context has no decorator."""
        context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        result = resolver.get_guard_decorator(None)
        assert result is None

    def test_get_route_config_success(
        self,
        resolver: RouteConfigResolver,
        mock_guard_decorator: BaseSecurityDecorator,
    ) -> None:
        """Test get_route_config with successful match."""
        app = Flask(__name__)
        app.extensions["flaskapi_guard"] = {"guard_decorator": mock_guard_decorator}

        # Create a view function with guard route ID
        def test_view() -> str:
            return "ok"

        test_view._guard_route_id = "test_route_id"
        app.add_url_rule("/api/test", endpoint="test_endpoint", view_func=test_view)

        with app.test_request_context("/api/test"):
            # Simulate Flask resolving the endpoint
            adapter = app.url_map.bind("")
            endpoint, _ = adapter.match("/api/test")

            mock_request = Mock(spec=Request)
            mock_request.endpoint = endpoint

            result = resolver.get_route_config(mock_request)
            assert result is not None
            assert "rate_limit" in result.bypassed_checks

    def test_get_route_config_no_decorator(self) -> None:
        """Test get_route_config when no guard decorator available."""
        context = RoutingContext(config=Mock(), logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        app = Flask(__name__)
        with app.test_request_context("/test"):
            mock_request = Mock(spec=Request)
            mock_request.endpoint = "test"
            result = resolver.get_route_config(mock_request)
            assert result is None

    def test_get_route_config_no_matching_route(
        self,
        resolver: RouteConfigResolver,
        mock_guard_decorator: BaseSecurityDecorator,
    ) -> None:
        """Test get_route_config when no route matches."""
        app = Flask(__name__)
        app.extensions["flaskapi_guard"] = {"guard_decorator": mock_guard_decorator}

        # Add a route without guard route ID
        @app.route("/api/other")
        def other_view() -> str:
            return "ok"

        with app.test_request_context("/api/other"):
            mock_request = Mock(spec=Request)
            mock_request.endpoint = "other_view"

            result = resolver.get_route_config(mock_request)
            assert result is None

    def test_should_bypass_check_no_config(self, resolver: RouteConfigResolver) -> None:
        """Test should_bypass_check with no route config."""
        result = resolver.should_bypass_check("rate_limit", None)
        assert result is False

    def test_should_bypass_check_specific_check(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test should_bypass_check with specific check in bypassed_checks."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"rate_limit", "ip_check"}

        result = resolver.should_bypass_check("rate_limit", route_config)
        assert result is True

    def test_should_bypass_check_all_checks(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test should_bypass_check with 'all' in bypassed_checks."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"all"}

        result = resolver.should_bypass_check("any_check", route_config)
        assert result is True

    def test_should_bypass_check_not_bypassed(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test should_bypass_check when check is not bypassed."""
        route_config = RouteConfig()
        route_config.bypassed_checks = {"ip_check"}

        result = resolver.should_bypass_check("rate_limit", route_config)
        assert result is False

    def test_get_cloud_providers_from_route_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test get_cloud_providers_to_check from route config."""
        route_config = RouteConfig()
        route_config.block_cloud_providers = {"azure", "digitalocean"}

        result = resolver.get_cloud_providers_to_check(route_config)
        assert result == ["azure", "digitalocean"] or result == [
            "digitalocean",
            "azure",
        ]
        assert set(result) == {"azure", "digitalocean"}

    def test_get_cloud_providers_from_global_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test get_cloud_providers_to_check from global config."""
        route_config = RouteConfig()
        # No block_cloud_providers set

        result = resolver.get_cloud_providers_to_check(route_config)
        assert result == ["aws", "gcp"] or result == ["gcp", "aws"]
        assert set(result) == {"aws", "gcp"}

    def test_get_cloud_providers_none_when_no_config(
        self, resolver: RouteConfigResolver
    ) -> None:
        """Test get_cloud_providers_to_check with no route config."""
        result = resolver.get_cloud_providers_to_check(None)
        assert result == ["aws", "gcp"] or result == ["gcp", "aws"]
        assert set(result) == {"aws", "gcp"}

    def test_get_cloud_providers_none_when_empty(self) -> None:
        """Test get_cloud_providers_to_check when both configs are empty."""
        config = Mock()
        config.block_cloud_providers = set()
        context = RoutingContext(config=config, logger=Mock(), guard_decorator=None)
        resolver = RouteConfigResolver(context)

        result = resolver.get_cloud_providers_to_check(None)
        assert result is None
