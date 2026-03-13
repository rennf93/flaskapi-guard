from flask import Request, Response

from flaskapi_guard.core.checks.base import SecurityCheck
from flaskapi_guard.utils import log_activity


class RequestLoggingCheck(SecurityCheck):
    """Log incoming requests."""

    @property
    def check_name(self) -> str:
        return "request_logging"

    def check(self, request: Request) -> Response | None:
        """Log the request."""
        log_activity(request, self.logger, level=self.config.log_request_level)
        return None
