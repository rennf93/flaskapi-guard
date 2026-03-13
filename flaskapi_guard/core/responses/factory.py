from collections.abc import Callable

from flask import Request, Response

from flaskapi_guard.core.responses.context import ResponseContext
from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.handlers.security_headers_handler import security_headers_manager
from flaskapi_guard.utils import extract_client_ip


class ErrorResponseFactory:
    """
    Factory for creating and processing HTTP responses.

    Handles error response creation, HTTPS redirects, security headers,
    CORS headers, and custom response modification.
    """

    def __init__(self, context: ResponseContext):
        """
        Initialize the ErrorResponseFactory.

        Args:
            context: ResponseContext with all required dependencies
        """
        self.context = context

    def create_error_response(self, status_code: int, default_message: str) -> Response:
        """
        Create an error response with a custom message.

        Args:
            status_code: HTTP status code for the error
            default_message: Default error message if no custom message configured

        Returns:
            Response object with custom message and security headers
        """
        custom_message = self.context.config.custom_error_responses.get(
            status_code, default_message
        )
        response = Response(custom_message, status=status_code)

        response = self.apply_security_headers(response)

        response = self.apply_modifier(response)

        return response

    def create_https_redirect(self, request: Request) -> Response:
        """
        Create HTTPS redirect response with custom modifier if configured.

        Args:
            request: The incoming HTTP request

        Returns:
            Redirect response to HTTPS version of the URL
        """
        https_url = request.url.replace("http://", "https://", 1)
        redirect_response = Response(
            response="",
            status=301,
            headers={"Location": https_url},
        )

        return self.apply_modifier(redirect_response)

    def apply_security_headers(
        self, response: Response, request_path: str | None = None
    ) -> Response:
        """
        Apply security headers to response.

        Args:
            response: Response object to add headers to
            request_path: Optional request path for path-specific headers

        Returns:
            Response with security headers added
        """
        headers_config = self.context.config.security_headers
        if headers_config and headers_config.get("enabled", True):
            security_headers = security_headers_manager.get_headers(request_path)
            for header_name, header_value in security_headers.items():
                response.headers[header_name] = header_value

        return response

    def apply_cors_headers(self, response: Response, origin: str) -> Response:
        """
        Apply CORS headers to response.

        Args:
            response: Response object to add CORS headers to
            origin: Origin header value from request

        Returns:
            Response with CORS headers added
        """
        headers_config = self.context.config.security_headers
        if headers_config and headers_config.get("enabled", True):
            cors_headers = security_headers_manager.get_cors_headers(origin)
            for header_name, header_value in cors_headers.items():
                response.headers[header_name] = header_value

        return response

    def apply_modifier(self, response: Response) -> Response:
        """
        Apply custom response modifier if configured.

        Args:
            response: Response object to modify

        Returns:
            Modified response or original if no modifier configured
        """
        if self.context.config.custom_response_modifier:
            return self.context.config.custom_response_modifier(response)
        return response

    def process_response(
        self,
        request: Request,
        response: Response,
        response_time: float,
        route_config: RouteConfig | None,
        process_behavioral_rules: Callable[[Request, Response, str, RouteConfig], None]
        | None = None,
    ) -> Response:
        """
        Process the response with behavioral rules, metrics, and headers.

        Args:
            request: The original request
            response: The response to process
            response_time: Response time in seconds
            route_config: Route-specific configuration (optional)
            process_behavioral_rules: Optional callback for behavioral rule processing

        Returns:
            Processed response with headers, metrics collected, and modifier applied
        """
        if route_config and route_config.behavior_rules and process_behavioral_rules:
            client_ip = extract_client_ip(
                request, self.context.config, self.context.agent_handler
            )
            process_behavioral_rules(request, response, client_ip, route_config)

        self.context.metrics_collector.collect_request_metrics(
            request, response_time, response.status_code
        )

        response = self.apply_security_headers(response, request.path)

        origin = request.headers.get("origin")
        if origin:
            response = self.apply_cors_headers(response, origin)

        return self.apply_modifier(response)
