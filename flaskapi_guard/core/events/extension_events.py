import logging
from datetime import datetime, timezone
from typing import Any

from flask import Request

from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.utils import extract_client_ip


class SecurityEventBus:
    """Centralized event publishing for extension security events."""

    def __init__(
        self,
        agent_handler: Any,
        config: SecurityConfig,
        geo_ip_handler: Any = None,
    ):
        """
        Initialize the SecurityEventBus.

        Args:
            agent_handler: The agent handler instance for sending events
            config: Security configuration
            geo_ip_handler: Optional GeoIP handler for country lookup
        """
        self.agent_handler = agent_handler
        self.config = config
        self.geo_ip_handler = geo_ip_handler
        self.logger = logging.getLogger(__name__)

    def send_middleware_event(
        self,
        event_type: str,
        request: Request,
        action_taken: str,
        reason: str,
        **kwargs: Any,
    ) -> None:
        """
        Send extension-specific events to agent if enabled.

        This method should only be used for extension-specific events like
        decorator violations. Domain-specific events (IP bans, rate limits, etc.)
        should be sent by their respective handlers.

        Args:
            event_type: Type of security event
            request: The incoming request
            action_taken: Action that was taken
            reason: Reason for the action
            **kwargs: Additional metadata for the event
        """
        if not self.agent_handler or not self.config.agent_enable_events:
            return

        try:
            client_ip = extract_client_ip(request, self.config, self.agent_handler)

            country = None
            if self.geo_ip_handler:
                try:
                    country = self.geo_ip_handler.get_country(client_ip)
                except Exception:
                    pass

            from guard_agent import SecurityEvent

            event = SecurityEvent(
                timestamp=datetime.now(timezone.utc),
                event_type=event_type,
                ip_address=client_ip,
                country=country,
                user_agent=request.headers.get("User-Agent"),
                action_taken=action_taken,
                reason=reason,
                endpoint=request.path,
                method=request.method,
                metadata=kwargs,
            )

            self.agent_handler.send_event(event)
        except Exception as e:
            self.logger.error(f"Failed to send security event to agent: {e}")

    def send_https_violation_event(
        self, request: Request, route_config: RouteConfig | None
    ) -> None:
        """
        Send appropriate HTTPS violation event based on route config.

        Args:
            request: The incoming request
            route_config: Route-specific configuration (if any)
        """
        https_url = request.url.replace("http://", "https://", 1)

        if route_config and route_config.require_https:
            self.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="https_redirect",
                reason="Route requires HTTPS but request was HTTP",
                decorator_type="authentication",
                violation_type="require_https",
                original_scheme=request.scheme,
                redirect_url=https_url,
            )
        else:
            self.send_middleware_event(
                event_type="https_enforced",
                request=request,
                action_taken="https_redirect",
                reason="HTTP request redirected to HTTPS for security",
                original_scheme=request.scheme,
                redirect_url=https_url,
            )

    def send_cloud_detection_events(
        self,
        request: Request,
        client_ip: str,
        cloud_providers_to_check: list[str],
        route_config: RouteConfig | None,
        cloud_handler: Any,
        passive_mode: bool,
    ) -> None:
        """
        Send cloud provider detection events to handler and extension.

        Args:
            request: The incoming request
            client_ip: Client IP address
            cloud_providers_to_check: List of cloud providers to check
            route_config: Route-specific configuration (if any)
            cloud_handler: Cloud handler instance
            passive_mode: Whether extension is in passive mode
        """
        cloud_details = cloud_handler.get_cloud_provider_details(
            client_ip, set(cloud_providers_to_check)
        )
        if cloud_details and cloud_handler.agent_handler:
            provider, network = cloud_details
            cloud_handler.send_cloud_detection_event(
                client_ip,
                provider,
                network,
                "request_blocked" if not passive_mode else "logged_only",
            )

        if route_config and route_config.block_cloud_providers:
            self.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="request_blocked" if not passive_mode else "logged_only",
                reason=f"Cloud provider IP {client_ip} blocked",
                decorator_type="access_control",
                violation_type="cloud_provider",
                blocked_providers=list(cloud_providers_to_check),
            )
