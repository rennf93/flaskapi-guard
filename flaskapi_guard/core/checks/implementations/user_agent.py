from typing import Any

from flask import Request, Response, g

from flaskapi_guard.core.checks.base import SecurityCheck
from flaskapi_guard.core.checks.helpers import check_user_agent_allowed
from flaskapi_guard.utils import log_activity


class UserAgentCheck(SecurityCheck):
    """Check user agent restrictions."""

    @property
    def check_name(self) -> str:
        return "user_agent"

    def _get_action_taken(self) -> str:
        """Get the action taken string based on passive mode."""
        if self.config.passive_mode:
            return "logged_only"
        return "request_blocked"

    def _log_blocked_user_agent(self, request: Request, user_agent: str) -> None:
        """Log suspicious activity for blocked user agent."""
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Blocked user agent: {user_agent}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

    def _send_route_violation_event(self, request: Request, user_agent: str) -> None:
        """Send decorator violation event for route-specific user agent block."""
        if self.middleware.event_bus is None:
            return
        self.middleware.event_bus.send_middleware_event(
            event_type="decorator_violation",
            request=request,
            action_taken=self._get_action_taken(),
            reason=f"User agent '{user_agent}' blocked",
            decorator_type="access_control",
            violation_type="user_agent",
            blocked_user_agent=user_agent,
        )

    def _send_global_block_event(self, request: Request, user_agent: str) -> None:
        """Send event for global user agent block."""
        if self.middleware.event_bus is None:
            return
        self.middleware.event_bus.send_middleware_event(
            event_type="user_agent_blocked",
            request=request,
            action_taken=self._get_action_taken(),
            reason=f"User agent '{user_agent}' in global blocklist",
            user_agent=user_agent,
            filter_type="global",
        )

    def _send_block_event(
        self, request: Request, user_agent: str, route_config: Any
    ) -> None:
        """Send the appropriate block event based on route vs global config."""
        if route_config and route_config.blocked_user_agents:
            self._send_route_violation_event(request, user_agent)
        else:
            self._send_global_block_event(request, user_agent)

    def check(self, request: Request) -> Response | None:
        """Check user agent restrictions."""
        if getattr(g, "is_whitelisted", False):
            return None

        route_config = getattr(g, "route_config", None)
        user_agent = request.headers.get("User-Agent", "")

        if check_user_agent_allowed(user_agent, route_config, self.config):
            return None

        self._log_blocked_user_agent(request, user_agent)
        self._send_block_event(request, user_agent, route_config)

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="User-Agent not allowed",
            )
        return None
