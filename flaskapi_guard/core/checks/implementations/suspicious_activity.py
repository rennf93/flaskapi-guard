# flaskapi_guard/core/checks/implementations/suspicious_activity.py
from flask import Request, Response, g

from flaskapi_guard.core.checks.base import SecurityCheck
from flaskapi_guard.core.checks.helpers import detect_penetration_patterns
from flaskapi_guard.handlers.ipban_handler import ip_ban_manager
from flaskapi_guard.utils import log_activity


class SuspiciousActivityCheck(SecurityCheck):
    """
    Check for suspicious/penetration attempt patterns.

    Detects SQL injection, XSS, path traversal, and other attack patterns.
    Tracks suspicious request counts per IP and can trigger automatic IP banning
    when thresholds are exceeded.
    """

    @property
    def check_name(self) -> str:
        return "suspicious_activity"

    def _handle_suspicious_passive_mode(
        self, request: Request, client_ip: str, trigger_info: str
    ) -> None:
        """
        Handle suspicious activity detection in passive mode (logging only).

        Args:
            request: The request object
            client_ip: IP address exhibiting suspicious behavior
            trigger_info: Description of what triggered the detection
        """
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Suspicious activity detected: {client_ip}",
            passive_mode=True,
            trigger_info=trigger_info,
            level=self.config.log_suspicious_level,
        )

        message = "Suspicious pattern detected (passive mode)"

        if self.middleware.event_bus is not None:
            self.middleware.event_bus.send_middleware_event(
                event_type="penetration_attempt",
                request=request,
                action_taken="logged_only",
                reason=f"{message}: {trigger_info}",
                request_count=self.middleware.suspicious_request_counts[client_ip],
                passive_mode=True,
                trigger_info=trigger_info,
            )

    def _handle_suspicious_active_mode(
        self, request: Request, client_ip: str, trigger_info: str
    ) -> Response:
        """
        Handle suspicious activity detection in active mode (blocking).

        Blocks the request and optionally bans the IP if threshold is exceeded.

        Args:
            request: The request object
            client_ip: IP address exhibiting suspicious behavior
            trigger_info: Description of what triggered the detection

        Returns:
            Error response (403 if banned, 400 if just blocked)
        """
        sus_specs = f"{client_ip} - {trigger_info}"

        # Check if IP should be banned
        if (
            self.config.enable_ip_banning
            and self.middleware.suspicious_request_counts[client_ip]
            >= self.config.auto_ban_threshold
        ):
            ip_ban_manager.ban_ip(
                client_ip,
                self.config.auto_ban_duration,
                "penetration_attempt",
            )
            log_activity(
                request,
                self.logger,
                log_type="suspicious",
                reason=f"IP banned due to suspicious activity: {sus_specs}",
                level=self.config.log_suspicious_level,
            )

            return self.middleware.create_error_response(
                status_code=403,
                default_message="IP has been banned",
            )

        # Block request without banning
        log_activity(
            request,
            self.logger,
            log_type="suspicious",
            reason=f"Suspicious activity detected for IP: {sus_specs}",
            level=self.config.log_suspicious_level,
        )

        if self.middleware.event_bus is not None:
            self.middleware.event_bus.send_middleware_event(
                event_type="penetration_attempt",
                request=request,
                action_taken="request_blocked",
                reason=f"Penetration attempt detected: {trigger_info}",
                request_count=self.middleware.suspicious_request_counts[client_ip],
                trigger_info=trigger_info,
            )

        return self.middleware.create_error_response(
            status_code=400,
            default_message="Suspicious activity detected",
        )

    def check(self, request: Request) -> Response | None:
        """
        Check for suspicious/penetration attempt patterns.

        Uses pattern detection to identify SQL injection, XSS, path traversal, etc.
        Tracks request counts per IP and can trigger automatic banning.

        Returns:
            Response if suspicious activity detected and blocked, None otherwise
        """
        if getattr(g, "is_whitelisted", False):
            return None

        client_ip = getattr(g, "client_ip", None)
        route_config = getattr(g, "route_config", None)

        if not client_ip:
            return None

        # Detect penetration patterns using helper function
        should_bypass = None
        if self.middleware.route_resolver is not None:
            should_bypass = self.middleware.route_resolver.should_bypass_check
        detection_result, trigger_info = detect_penetration_patterns(
            request,
            route_config,
            self.config,
            should_bypass,
        )

        # Detection disabled by decorator - send event
        if trigger_info == "disabled_by_decorator":
            if self.middleware.event_bus is not None:
                self.middleware.event_bus.send_middleware_event(
                    event_type="decorator_violation",
                    request=request,
                    action_taken="detection_disabled",
                    reason="Suspicious pattern detection disabled by route decorator",
                    decorator_type="advanced",
                    violation_type="suspicious_detection_disabled",
                )
            return None

        if not detection_result:
            return None

        # Update request count for this IP
        self.middleware.suspicious_request_counts[client_ip] = (
            self.middleware.suspicious_request_counts.get(client_ip, 0) + 1
        )

        # Handle based on mode
        if self.config.passive_mode:
            self._handle_suspicious_passive_mode(request, client_ip, trigger_info)
            return None

        return self._handle_suspicious_active_mode(request, client_ip, trigger_info)
