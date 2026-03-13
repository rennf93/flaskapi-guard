from typing import Any

from flask import Request, Response

from flaskapi_guard.core.checks.base import SecurityCheck


class CustomRequestCheck(SecurityCheck):
    """Check custom request validation."""

    @property
    def check_name(self) -> str:
        return "custom_request"

    def _get_response_status(self, custom_response: Any) -> Any:
        """Extract status code from response, returning 'unknown' if unavailable."""
        if hasattr(custom_response, "status_code"):
            return custom_response.status_code
        return "unknown"

    def _get_check_function_name(self) -> str:
        """Get the name of the custom request check function."""
        check_fn = self.config.custom_request_check
        if check_fn is not None and hasattr(check_fn, "__name__"):
            return check_fn.__name__
        return "anonymous"

    def _send_custom_check_event(self, request: Request, custom_response: Any) -> None:
        """Send event for custom request check blocking."""
        if self.middleware.event_bus is None:
            return
        self.middleware.event_bus.send_middleware_event(
            event_type="custom_request_check",
            request=request,
            action_taken="request_blocked"
            if not self.config.passive_mode
            else "logged_only",
            reason="Custom request check returned blocking response",
            response_status=self._get_response_status(custom_response),
            check_function=self._get_check_function_name(),
        )

    def _apply_response_modifier(self, custom_response: Response) -> Response:
        """Apply response modifier if available, otherwise return as-is."""
        if self.middleware.response_factory is not None:
            return self.middleware.response_factory.apply_modifier(custom_response)
        return custom_response

    def check(self, request: Request) -> Response | None:
        """Check custom request validation."""
        if not self.config.custom_request_check:
            return None

        custom_response = self.config.custom_request_check(request)
        if not custom_response:
            return None

        self._send_custom_check_event(request, custom_response)

        if not self.config.passive_mode:
            return self._apply_response_modifier(custom_response)
        return None
