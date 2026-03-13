# flaskapi_guard/core/checks/implementations/user_agent.py
from flask import Request, Response, g

from flaskapi_guard.core.checks.base import SecurityCheck
from flaskapi_guard.core.checks.helpers import check_user_agent_allowed
from flaskapi_guard.utils import log_activity


class UserAgentCheck(SecurityCheck):
    """Check user agent restrictions."""

    @property
    def check_name(self) -> str:
        return "user_agent"

    def check(self, request: Request) -> Response | None:
        """Check user agent restrictions."""
        if getattr(g, "is_whitelisted", False):
            return None

        route_config = getattr(g, "route_config", None)
        user_agent = request.headers.get("User-Agent", "")

        if not check_user_agent_allowed(user_agent, route_config, self.config):
            log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"Blocked user agent: {user_agent}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )

            # Send decorator violation event only for route-specific blocks
            if route_config and route_config.blocked_user_agents:
                # Route-specific user agent block
                if self.middleware.event_bus is not None:
                    self.middleware.event_bus.send_middleware_event(
                        event_type="decorator_violation",
                        request=request,
                        action_taken="request_blocked"
                        if not self.config.passive_mode
                        else "logged_only",
                        reason=f"User agent '{user_agent}' blocked",
                        decorator_type="access_control",
                        violation_type="user_agent",
                        blocked_user_agent=user_agent,
                    )
            else:
                # Global user agent block
                if self.middleware.event_bus is not None:
                    self.middleware.event_bus.send_middleware_event(
                        event_type="user_agent_blocked",
                        request=request,
                        action_taken="request_blocked"
                        if not self.config.passive_mode
                        else "logged_only",
                        reason=f"User agent '{user_agent}' in global blocklist",
                        user_agent=user_agent,
                        filter_type="global",
                    )

            if not self.config.passive_mode:
                return self.middleware.create_error_response(
                    status_code=403,
                    default_message="User-Agent not allowed",
                )
        return None
