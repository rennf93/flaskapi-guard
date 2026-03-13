# flaskapi_guard/core/checks/implementations/cloud_provider.py
from flask import Request, Response, g

from flaskapi_guard.core.checks.base import SecurityCheck
from flaskapi_guard.handlers.cloud_handler import cloud_handler
from flaskapi_guard.utils import log_activity


class CloudProviderCheck(SecurityCheck):
    """Check cloud provider blocking."""

    @property
    def check_name(self) -> str:
        return "cloud_provider"

    def check(self, request: Request) -> Response | None:
        """Check cloud provider blocking."""
        if getattr(g, "is_whitelisted", False):
            return None

        client_ip = getattr(g, "client_ip", None)
        route_config = getattr(g, "route_config", None)
        if not client_ip:
            return None

        if (
            self.middleware.route_resolver is not None
            and self.middleware.route_resolver.should_bypass_check(
                "clouds", route_config
            )
        ):
            return None

        # Get cloud providers to check
        cloud_providers_to_check = None
        if self.middleware.route_resolver is not None:
            cloud_providers_to_check = (
                self.middleware.route_resolver.get_cloud_providers_to_check(route_config)
            )
        if not cloud_providers_to_check:
            return None

        # Check if IP is from blocked cloud provider
        if not cloud_handler.is_cloud_ip(client_ip, set(cloud_providers_to_check)):
            return None

        # Log suspicious activity
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Blocked cloud provider IP: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        # Send cloud detection events
        if self.middleware.event_bus is not None:
            self.middleware.event_bus.send_cloud_detection_events(
                request,
                client_ip,
                cloud_providers_to_check,
                route_config,
                cloud_handler,
                self.config.passive_mode,
            )

        # Return error response if not in passive mode
        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Cloud provider IP not allowed",
            )

        return None
