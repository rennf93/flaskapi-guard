# flaskapi_guard/core/checks/implementations/referrer.py
from flask import Request, Response, g

from flaskapi_guard.core.checks.base import SecurityCheck
from flaskapi_guard.core.checks.helpers import is_referrer_domain_allowed
from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.utils import log_activity


class ReferrerCheck(SecurityCheck):
    """Check referrer requirements."""

    @property
    def check_name(self) -> str:
        return "referrer"

    def _handle_missing_referrer(
        self, request: Request, route_config: RouteConfig
    ) -> Response | None:
        """Handle missing referrer header violation."""
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason="Missing referrer header",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        if self.middleware.event_bus is not None:
            self.middleware.event_bus.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason="Missing referrer header",
                decorator_type="content_filtering",
                violation_type="require_referrer",
                allowed_domains=route_config.require_referrer,
            )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Referrer required",
            )

        return None

    def _handle_invalid_referrer(
        self, request: Request, referrer: str, route_config: RouteConfig
    ) -> Response | None:
        """Handle invalid referrer domain violation."""
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Invalid referrer: {referrer}",
            level=self.config.log_suspicious_level,
            passive_mode=self.config.passive_mode,
        )

        if self.middleware.event_bus is not None:
            self.middleware.event_bus.send_middleware_event(
                event_type="decorator_violation",
                request=request,
                action_taken="request_blocked"
                if not self.config.passive_mode
                else "logged_only",
                reason=f"Referrer '{referrer}' not in allowed domains",
                decorator_type="content_filtering",
                violation_type="require_referrer",
                referrer=referrer,
                allowed_domains=route_config.require_referrer,
            )

        if not self.config.passive_mode:
            return self.middleware.create_error_response(
                status_code=403,
                default_message="Invalid referrer",
            )

        return None

    def check(self, request: Request) -> Response | None:
        """Check referrer requirements."""
        route_config = getattr(g, "route_config", None)
        if not route_config or not route_config.require_referrer:
            return None

        referrer = request.headers.get("referer", "")

        # Handle missing referrer
        if not referrer:
            return self._handle_missing_referrer(request, route_config)

        # Check if referrer domain is allowed using helper function
        if not is_referrer_domain_allowed(referrer, route_config.require_referrer):
            return self._handle_invalid_referrer(request, referrer, route_config)

        return None
