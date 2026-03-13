# flaskapi_guard/core/checks/implementations/emergency_mode.py
from flask import Request, Response, g

from flaskapi_guard.core.checks.base import SecurityCheck
from flaskapi_guard.utils import extract_client_ip, log_activity


class EmergencyModeCheck(SecurityCheck):
    """Check emergency mode restrictions - blocks all except whitelisted IPs."""

    @property
    def check_name(self) -> str:
        return "emergency_mode"

    def check(self, request: Request) -> Response | None:
        """Check emergency mode - blocks all except whitelisted IPs."""
        if not self.config.emergency_mode:
            return None

        # Get client IP from flask.g (set by RouteConfigCheck)
        client_ip = getattr(g, "client_ip", None)
        if not client_ip:
            client_ip = extract_client_ip(
                request, self.config, self.middleware.agent_handler
            )

        # Allow only emergency whitelist IPs
        if client_ip not in self.config.emergency_whitelist:
            log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"[EMERGENCY MODE] Access denied for IP {client_ip}",
                level=self.config.log_suspicious_level,
                passive_mode=self.config.passive_mode,
            )

            # Send emergency mode blocking event
            if self.middleware.event_bus is not None:
                self.middleware.event_bus.send_middleware_event(
                    event_type="emergency_mode_block",
                    request=request,
                    action_taken="request_blocked"
                    if not self.config.passive_mode
                    else "logged_only",
                    reason=f"[EMERGENCY MODE] IP {client_ip} not in whitelist",
                    emergency_whitelist_count=len(self.config.emergency_whitelist),
                    emergency_active=True,
                )

            if not self.config.passive_mode:
                return self.middleware.create_error_response(
                    status_code=503,
                    default_message="Service temporarily unavailable",
                )
        else:
            # Log allowed emergency access
            log_activity(
                request,
                self.logger,
                log_type="info",
                reason=(
                    f"[EMERGENCY MODE] Allowed access for whitelisted IP {client_ip}"
                ),
                level="INFO",
            )

        return None
