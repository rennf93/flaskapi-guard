from typing import Any

from flask import Request, Response, g

from flaskapi_guard.core.checks.base import SecurityCheck
from flaskapi_guard.handlers.cloud_handler import cloud_handler
from flaskapi_guard.utils import log_activity


class CloudProviderCheck(SecurityCheck):
    """Check cloud provider blocking."""

    @property
    def check_name(self) -> str:
        return "cloud_provider"

    def _should_skip_check(self, route_config: Any) -> bool:
        """Determine if cloud provider check should be skipped."""
        if self.middleware.route_resolver is None:
            return False
        return self.middleware.route_resolver.should_bypass_check(
            "clouds", route_config
        )

    def _get_cloud_providers(self, route_config: Any) -> set[str] | None:
        """Get the set of cloud providers to check against."""
        if self.middleware.route_resolver is None:
            return None
        providers = self.middleware.route_resolver.get_cloud_providers_to_check(
            route_config
        )
        if not providers:
            return None
        return set(providers)

    def _log_and_send_events(
        self,
        request: Request,
        client_ip: str,
        cloud_providers_to_check: Any,
        route_config: Any,
    ) -> None:
        """Log suspicious activity and send cloud detection events."""
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Blocked cloud provider IP: {client_ip}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        if self.middleware.event_bus is not None:
            self.middleware.event_bus.send_cloud_detection_events(
                request,
                client_ip,
                cloud_providers_to_check,
                route_config,
                cloud_handler,
                self.config.passive_mode,
            )

    def check(self, request: Request) -> Response | None:
        """Check cloud provider blocking."""
        if getattr(g, "is_whitelisted", False):
            return None

        client_ip = getattr(g, "client_ip", None)
        route_config = getattr(g, "route_config", None)
        if not client_ip:
            return None

        if self._should_skip_check(route_config):
            return None

        cloud_providers = self._get_cloud_providers(route_config)
        if not cloud_providers:
            return None

        if not cloud_handler.is_cloud_ip(client_ip, cloud_providers):
            return None

        self._log_and_send_events(request, client_ip, cloud_providers, route_config)

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Cloud provider IP not allowed",
            )

        return None
