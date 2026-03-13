import logging
import time
from typing import Any

from flask import Flask, Request, Response, g

from flaskapi_guard.core.behavioral import BehavioralContext, BehavioralProcessor
from flaskapi_guard.core.bypass import BypassContext, BypassHandler
from flaskapi_guard.core.checks.pipeline import SecurityCheckPipeline
from flaskapi_guard.core.events import MetricsCollector, SecurityEventBus
from flaskapi_guard.core.initialization import HandlerInitializer
from flaskapi_guard.core.responses import ErrorResponseFactory, ResponseContext
from flaskapi_guard.core.routing import RouteConfigResolver, RoutingContext
from flaskapi_guard.core.validation import RequestValidator, ValidationContext
from flaskapi_guard.decorators.base import BaseSecurityDecorator, RouteConfig
from flaskapi_guard.handlers.cloud_handler import cloud_handler
from flaskapi_guard.handlers.ratelimit_handler import RateLimitManager
from flaskapi_guard.handlers.security_headers_handler import security_headers_manager
from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.utils import extract_client_ip, setup_custom_logging


class FlaskAPIGuard:
    """
    Flask extension for implementing various
    security measures in a Flask application.

    This extension handles rate limiting,
    IP filtering, user agent filtering,
    and detection of potential
    penetration attempts.
    """

    def __init__(
        self,
        app: Flask | None = None,
        *,
        config: SecurityConfig | None = None,
    ) -> None:
        """
        Initialize the FlaskAPIGuard extension.

        Args:
            app (Flask | None):
                The Flask application. If provided, init_app is called immediately.
            config (SecurityConfig | None):
                Configuration object for security settings.
        """
        self.config: SecurityConfig | None = config
        self.logger: logging.Logger | None = None
        self.last_cloud_ip_refresh: int = 0
        self.suspicious_request_counts: dict[str, int] = {}
        self.last_cleanup: float = 0
        self.rate_limit_handler: RateLimitManager | None = None
        self.guard_decorator: BaseSecurityDecorator | None = None
        self.geo_ip_handler: Any = None
        self.redis_handler: Any = None
        self.agent_handler: Any = None
        self.security_pipeline: SecurityCheckPipeline | None = None
        self.event_bus: SecurityEventBus | None = None
        self.metrics_collector: MetricsCollector | None = None
        self.handler_initializer: HandlerInitializer | None = None
        self.response_factory: ErrorResponseFactory | None = None
        self.route_resolver: RouteConfigResolver | None = None
        self.validator: RequestValidator | None = None
        self.bypass_handler: BypassHandler | None = None
        self.behavioral_processor: BehavioralProcessor | None = None
        self._app: Flask | None = None

        if app is not None:
            self.init_app(app, config=config)

    def _resolve_config(self, config: SecurityConfig | None) -> None:
        """Resolve and validate the security configuration."""
        if config is not None:
            self.config = config
        elif self.config is None:
            raise ValueError("SecurityConfig must be provided")

    def _init_geo_ip_handler(self) -> None:
        """Initialize the geo IP handler if country rules are configured."""
        assert self.config is not None
        self.geo_ip_handler = None
        if self.config.whitelist_countries or self.config.blocked_countries:
            self.geo_ip_handler = self.config.geo_ip_handler

    def _init_redis_handler(self) -> None:
        """Initialize Redis handler if enabled in config."""
        assert self.config is not None
        self.redis_handler = None
        if self.config.enable_redis:
            from flaskapi_guard.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(self.config)

    def _init_agent_handler(self) -> None:
        """Initialize agent handler if enabled in config."""
        assert self.config is not None
        assert self.logger is not None
        self.agent_handler = None
        if not self.config.enable_agent:
            return

        agent_config = self.config.to_agent_config()
        if not agent_config:
            self.logger.warning(
                "Agent enabled but configuration is invalid. "
                "Check agent_api_key and other required fields."
            )
            return

        try:
            from guard_agent import guard_agent

            self.agent_handler = guard_agent(agent_config)
            self.logger.info("Guard Agent initialized successfully")
        except ImportError:
            self.logger.warning(
                "Agent enabled but guard_agent package not installed. "
                "Install with: pip install fastapi-guard-agent"
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize Guard Agent: {e}")
            self.logger.warning("Continuing without agent functionality")

    def _init_core_components(self) -> None:
        """Initialize event bus, metrics, handler initializer, and core components."""
        assert self.config is not None
        assert self.logger is not None

        self.event_bus = SecurityEventBus(
            self.agent_handler, self.config, self.geo_ip_handler
        )
        self.metrics_collector = MetricsCollector(self.agent_handler, self.config)

        self.handler_initializer = HandlerInitializer(
            config=self.config,
            redis_handler=self.redis_handler,
            agent_handler=self.agent_handler,
            geo_ip_handler=self.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
        )

        response_context = ResponseContext(
            config=self.config,
            logger=self.logger,
            metrics_collector=self.metrics_collector,
            agent_handler=self.agent_handler,
            guard_decorator=self.guard_decorator,
        )
        self.response_factory = ErrorResponseFactory(response_context)

    def _init_routing_and_validation(self) -> None:
        """Initialize routing, validation, bypass, and behavioral."""
        assert self.config is not None
        assert self.logger is not None
        assert self.event_bus is not None
        assert self.route_resolver is None
        assert self.response_factory is not None

        routing_context = RoutingContext(
            config=self.config,
            logger=self.logger,
            guard_decorator=self.guard_decorator,
        )
        self.route_resolver = RouteConfigResolver(routing_context)

        validation_context = ValidationContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
        )
        self.validator = RequestValidator(validation_context)

        bypass_context = BypassContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            route_resolver=self.route_resolver,
            response_factory=self.response_factory,
            validator=self.validator,
        )
        self.bypass_handler = BypassHandler(bypass_context)

        behavioral_context = BehavioralContext(
            config=self.config,
            logger=self.logger,
            event_bus=self.event_bus,
            guard_decorator=self.guard_decorator,
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)

    def init_app(self, app: Flask, config: SecurityConfig | None = None) -> None:
        """
        Initialize the extension with a Flask application.

        Args:
            app: The Flask application instance.
            config: Optional SecurityConfig. If not provided, uses the one
                    from __init__ or raises ValueError.
        """
        self._resolve_config(config)
        assert self.config is not None

        self.logger = setup_custom_logging(self.config.custom_log_file)
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts = {}
        self.last_cleanup = time.time()
        self.rate_limit_handler = RateLimitManager(self.config)

        self._configure_security_headers(self.config)
        self._init_geo_ip_handler()
        self._init_redis_handler()
        self._init_agent_handler()
        self._init_core_components()
        self._init_routing_and_validation()

        self._app = app

        app.extensions["flaskapi_guard"] = {
            "guard": self,
            "config": self.config,
            "guard_decorator": self.guard_decorator,
        }

        self._build_security_pipeline()

        self._initialize_handlers()

        app.before_request(self._before_request)
        app.after_request(self._after_request)

    def _initialize_handlers(self) -> None:
        """Synchronous version of SecurityMiddleware.initialize()."""
        assert self.handler_initializer is not None

        self.handler_initializer.guard_decorator = self.guard_decorator

        self.handler_initializer.initialize_redis_handlers()

        self.handler_initializer.initialize_agent_integrations()

    def _build_security_pipeline(self) -> None:
        """Build the security check pipeline with configured checks."""
        from flaskapi_guard.core.checks import (
            AuthenticationCheck,
            CloudIpRefreshCheck,
            CloudProviderCheck,
            CustomRequestCheck,
            CustomValidatorsCheck,
            EmergencyModeCheck,
            HttpsEnforcementCheck,
            IpSecurityCheck,
            RateLimitCheck,
            ReferrerCheck,
            RequestLoggingCheck,
            RequestSizeContentCheck,
            RequiredHeadersCheck,
            RouteConfigCheck,
            SecurityCheckPipeline,
            SuspiciousActivityCheck,
            TimeWindowCheck,
            UserAgentCheck,
        )

        checks = [
            RouteConfigCheck(self),
            EmergencyModeCheck(self),
            HttpsEnforcementCheck(self),
            RequestLoggingCheck(self),
            RequestSizeContentCheck(self),
            RequiredHeadersCheck(self),
            AuthenticationCheck(self),
            ReferrerCheck(self),
            CustomValidatorsCheck(self),
            TimeWindowCheck(self),
            CloudIpRefreshCheck(self),
            IpSecurityCheck(self),
            CloudProviderCheck(self),
            UserAgentCheck(self),
            RateLimitCheck(self),
            SuspiciousActivityCheck(self),
            CustomRequestCheck(self),
        ]

        self.security_pipeline = SecurityCheckPipeline(checks)
        assert self.logger is not None
        self.logger.info(
            f"Security pipeline initialized with {len(checks)} checks: "
            f"{self.security_pipeline.get_check_names()}"
        )

    def _configure_security_headers(self, config: SecurityConfig) -> None:
        """Configure security headers manager if enabled."""
        if not config.security_headers:
            security_headers_manager.enabled = False
            return

        if not config.security_headers.get("enabled", True):
            security_headers_manager.enabled = False
            return

        security_headers_manager.enabled = True
        headers_config = config.security_headers
        hsts_config = headers_config.get("hsts", {})

        security_headers_manager.configure(
            enabled=headers_config.get("enabled", True),
            csp=headers_config.get("csp"),
            hsts_max_age=hsts_config.get("max_age"),
            hsts_include_subdomains=hsts_config.get("include_subdomains", True),
            hsts_preload=hsts_config.get("preload", False),
            frame_options=headers_config.get("frame_options", "SAMEORIGIN"),
            content_type_options=headers_config.get("content_type_options", "nosniff"),
            xss_protection=headers_config.get("xss_protection", "1; mode=block"),
            referrer_policy=headers_config.get(
                "referrer_policy", "strict-origin-when-cross-origin"
            ),
            permissions_policy=headers_config.get("permissions_policy", "UNSET"),
            custom_headers=headers_config.get("custom"),
            cors_origins=config.cors_allow_origins if config.enable_cors else None,
            cors_allow_credentials=config.cors_allow_credentials,
            cors_allow_methods=config.cors_allow_methods,
            cors_allow_headers=config.cors_allow_headers,
        )

    def set_decorator_handler(
        self, decorator_handler: BaseSecurityDecorator | None
    ) -> None:
        """Set the SecurityDecorator instance for decorator support."""
        self.guard_decorator = decorator_handler
        if self.route_resolver:
            self.route_resolver.context.guard_decorator = decorator_handler
        if self.behavioral_processor:
            self.behavioral_processor.context.guard_decorator = decorator_handler
        if self.response_factory:
            self.response_factory.context.guard_decorator = decorator_handler
        if self.handler_initializer:
            self.handler_initializer.guard_decorator = decorator_handler
        if self._app is not None:
            ext = self._app.extensions.get("flaskapi_guard")
            if isinstance(ext, dict):
                ext["guard_decorator"] = decorator_handler

    def _execute_security_pipeline(self, request: Request) -> Response | None:
        """Execute the security check pipeline and return blocking response if any."""
        if self.security_pipeline:
            return self.security_pipeline.execute(request)
        return None

    def _process_behavioral_usage(
        self, request: Request, client_ip: str, route_config: RouteConfig | None
    ) -> None:
        """Process behavioral usage rules if applicable."""
        assert self.behavioral_processor is not None
        if route_config and route_config.behavior_rules and client_ip:
            self.behavioral_processor.process_usage_rules(
                request, client_ip, route_config
            )

    def _before_request(self) -> Response | None:
        """Security pipeline -- runs before each request."""
        from flask import request

        assert self.config is not None
        assert self.bypass_handler is not None
        assert self.route_resolver is not None
        assert self.behavioral_processor is not None

        g.request_start_time = time.time()

        if self.config.enable_cors and request.method == "OPTIONS":
            return self._handle_preflight(request)

        passthrough = self.bypass_handler.handle_passthrough(request)
        if passthrough is not None:
            return passthrough

        client_ip = extract_client_ip(request, self.config, self.agent_handler)
        route_config = self.route_resolver.get_route_config(request)

        g.client_ip = client_ip
        g.route_config = route_config

        bypass = self.bypass_handler.handle_security_bypass(request, route_config)
        if bypass is not None:
            return bypass

        blocking = self._execute_security_pipeline(request)
        if blocking:
            return blocking

        self._process_behavioral_usage(request, client_ip, route_config)

        return None

    def _after_request(self, response: Response) -> Response:
        """Post-processing -- runs after each request."""
        from flask import request

        assert self.response_factory is not None
        assert self.behavioral_processor is not None

        start_time = getattr(g, "request_start_time", time.time())
        response_time = time.time() - start_time
        route_config = getattr(g, "route_config", None)

        return self.response_factory.process_response(
            request,
            response,
            response_time,
            route_config,
            process_behavioral_rules=self.behavioral_processor.process_return_rules,
        )

    def _handle_preflight(self, request: Request) -> Response:
        """Handle CORS OPTIONS preflight request."""
        assert self.response_factory is not None

        response = Response("", status=204)
        origin = request.headers.get("origin", "")
        self.response_factory.apply_cors_headers(response, origin)
        return response

    def _create_https_redirect(self, request: Request) -> Response:
        """
        Create HTTPS redirect response with custom modifier if configured.

        Delegates to ErrorResponseFactory for redirect creation.
        """
        assert self.response_factory is not None
        return self.response_factory.create_https_redirect(request)

    def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        """Check if current time is within allowed time window (for tests)."""
        assert self.validator is not None
        return self.validator.check_time_window(time_restrictions)

    def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        """Check route-specific IP restrictions (for tests)."""
        from flaskapi_guard.core.checks.helpers import check_route_ip_access

        return check_route_ip_access(client_ip, route_config, self)

    def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        """Check if user agent is allowed (for tests)."""
        from flaskapi_guard.core.checks.helpers import check_user_agent_allowed

        return check_user_agent_allowed(user_agent, route_config, self.config)

    def _check_rate_limit(
        self,
        request: Request,
        client_ip: str,
        route_config: RouteConfig | None = None,
    ) -> Response | None:
        """Check rate limiting (for tests)."""
        assert self.rate_limit_handler is not None
        assert self.config is not None

        response = self.rate_limit_handler.check_rate_limit(
            request, client_ip, self.create_error_response
        )

        if response and self.config.passive_mode:
            return None

        return response

    def _process_response(
        self,
        request: Request,
        response: Response,
        response_time: float,
        route_config: RouteConfig | None,
    ) -> Response:
        """
        Process the response with behavioral rules, metrics, and headers.

        Delegates to ErrorResponseFactory and BehavioralProcessor.
        """
        assert self.response_factory is not None
        assert self.behavioral_processor is not None

        return self.response_factory.process_response(
            request,
            response,
            response_time,
            route_config,
            process_behavioral_rules=self.behavioral_processor.process_return_rules,
        )

    def _process_decorator_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> None:
        """Process behavioral usage rules (wrapper for tests)."""
        assert self.behavioral_processor is not None
        return self.behavioral_processor.process_usage_rules(
            request, client_ip, route_config
        )

    def _process_decorator_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        """Process behavioral return rules (wrapper for tests)."""
        assert self.behavioral_processor is not None
        return self.behavioral_processor.process_return_rules(
            request, response, client_ip, route_config
        )

    def _get_endpoint_id(self, request: Request) -> str:
        """Generate unique endpoint identifier (wrapper for tests)."""
        assert self.behavioral_processor is not None
        return self.behavioral_processor.get_endpoint_id(request)

    def refresh_cloud_ip_ranges(self) -> None:
        """Refresh cloud IP ranges."""
        assert self.config is not None

        if not self.config.block_cloud_providers:
            return

        cloud_handler.refresh(self.config.block_cloud_providers)
        self.last_cloud_ip_refresh = int(time.time())

    def create_error_response(self, status_code: int, default_message: str) -> Response:
        """
        Create an error response with a custom message.

        Delegates to ErrorResponseFactory for response creation.
        """
        assert self.response_factory is not None
        return self.response_factory.create_error_response(status_code, default_message)

    def reset(self) -> None:
        """Reset rate limiting state."""
        assert self.rate_limit_handler is not None
        self.rate_limit_handler.reset()
