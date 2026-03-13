# flaskapi_guard/core/routing/resolver.py
from typing import Any

from flask import Request, current_app

from flaskapi_guard.core.routing.context import RoutingContext
from flaskapi_guard.decorators.base import BaseSecurityDecorator, RouteConfig


class RouteConfigResolver:
    """
    Resolver for route configuration and decorator matching.

    Handles all routing-related operations including decorator access,
    route matching, bypass checking, and configuration resolution.
    """

    def __init__(self, context: RoutingContext):
        """
        Initialize the RouteConfigResolver.

        Args:
            context: RoutingContext with all required dependencies
        """
        self.context = context

    def get_guard_decorator(self, app: Any) -> BaseSecurityDecorator | None:
        """
        Get the guard decorator instance from app extensions or context.

        Args:
            app: Flask application instance

        Returns:
            BaseSecurityDecorator instance or None if not available
        """
        # Try to get decorator from app extensions first
        if app:
            flaskapi_guard_ext = app.extensions.get("flaskapi_guard", {})
            if isinstance(flaskapi_guard_ext, dict):
                app_guard_decorator = flaskapi_guard_ext.get("guard_decorator")
            else:
                app_guard_decorator = getattr(flaskapi_guard_ext, "guard_decorator", None)
            if isinstance(app_guard_decorator, BaseSecurityDecorator):
                return app_guard_decorator

        # Fall back to context-level decorator
        return self.context.guard_decorator if self.context.guard_decorator else None

    def get_route_config(self, request: Request) -> RouteConfig | None:
        """
        Get route-specific security configuration from decorators.

        Args:
            request: The incoming request

        Returns:
            RouteConfig if found, None otherwise
        """
        app = current_app

        # Get decorator instance
        guard_decorator = self.get_guard_decorator(app)
        if not guard_decorator:
            return None

        # Use Flask's endpoint resolution to find the view function
        if request.endpoint is None:
            return None
        view_func = current_app.view_functions.get(request.endpoint)
        if view_func is None:
            return None

        # Check if the view function has a guard route ID
        if hasattr(view_func, "_guard_route_id"):
            route_id = view_func._guard_route_id
            return guard_decorator.get_route_config(route_id)

        return None

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        """
        Check if a security check should be bypassed.

        Args:
            check_name: Name of the check to evaluate
            route_config: Route-specific configuration (optional)

        Returns:
            True if check should be bypassed, False otherwise
        """
        if not route_config:
            return False
        return (
            check_name in route_config.bypassed_checks
            or "all" in route_config.bypassed_checks
        )

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        """
        Get list of cloud providers to check (route-specific or global).

        Args:
            route_config: Route-specific configuration (optional)

        Returns:
            List of provider names or None
        """
        if route_config and route_config.block_cloud_providers:
            return list(route_config.block_cloud_providers)
        if self.context.config.block_cloud_providers:
            return list(self.context.config.block_cloud_providers)
        return None
