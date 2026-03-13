# flaskapi_guard/core/bypass/handler.py
from flask import Request, Response

from flaskapi_guard.core.bypass.context import BypassContext
from flaskapi_guard.decorators.base import RouteConfig


class BypassHandler:
    """Handles security check bypassing operations."""

    def __init__(self, context: BypassContext) -> None:
        """
        Initialize the BypassHandler.

        Args:
            context: Bypass context with config, logger, and dependencies
        """
        self.context = context

    def handle_passthrough(
        self,
        request: Request,
    ) -> Response | None:
        """
        Handle special cases that require immediate passthrough.

        This includes requests with no client information and excluded paths.

        Returns:
            None to let Flask proceed with the request
        """
        # No client information
        if not request.remote_addr:
            return None

        # Excluded paths
        if self.context.validator.is_path_excluded(request):
            return None

        return None

    def handle_security_bypass(
        self,
        request: Request,
        route_config: RouteConfig | None,
    ) -> Response | None:
        """
        Handle bypassed security checks.

        Returns:
            None to let Flask proceed with the request
        """
        if not route_config or not self.context.route_resolver.should_bypass_check(
            "all", route_config
        ):
            return None

        # Send security bypass event for monitoring
        self.context.event_bus.send_middleware_event(
            event_type="security_bypass",
            request=request,
            action_taken="all_checks_bypassed",
            reason="Route configured to bypass all security checks",
            bypassed_checks=list(route_config.bypassed_checks),
            endpoint=request.path,
        )

        if not self.context.config.passive_mode:
            return None

        return None
