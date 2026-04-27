import logging
import time
from typing import Any, cast

from flask import Flask, Response, g
from guard_core.models import SecurityConfig
from guard_core.protocols.response_protocol import GuardResponse
from guard_core.sync.core.behavioral import BehavioralContext, BehavioralProcessor
from guard_core.sync.core.bypass import BypassContext, BypassHandler
from guard_core.sync.core.checks.pipeline import SecurityCheckPipeline
from guard_core.sync.core.events import MetricsCollector, SecurityEventBus
from guard_core.sync.core.initialization import HandlerInitializer
from guard_core.sync.core.responses import ErrorResponseFactory, ResponseContext
from guard_core.sync.core.routing import RouteConfigResolver, RoutingContext
from guard_core.sync.core.validation import RequestValidator, ValidationContext
from guard_core.sync.decorators.base import BaseSecurityDecorator, RouteConfig
from guard_core.sync.handlers.cloud_handler import cloud_handler
from guard_core.sync.handlers.cors_handler import (
    CorsHandler,
    CorsPreflightResponse,
    is_preflight,
)
from guard_core.sync.handlers.ratelimit_handler import RateLimitManager
from guard_core.sync.handlers.security_headers_handler import security_headers_manager
from guard_core.sync.protocols.middleware_protocol import SyncGuardMiddlewareProtocol
from guard_core.sync.utils import extract_client_ip, setup_custom_logging

from flaskapi_guard.adapters import (
    FlaskGuardRequest,
    FlaskGuardResponse,
    FlaskResponseFactory,
    unwrap_response,
)


class FlaskAPIGuard:
    def __init__(
        self,
        app: Flask | None = None,
        *,
        config: SecurityConfig | None = None,
    ) -> None:
        self.config: SecurityConfig | None = config
        self.logger: logging.Logger | None = None
        self.last_cloud_ip_refresh: int = 0
        self.suspicious_request_counts: dict[str, dict[str, int]] = {}
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
        self._cors_handler: CorsHandler | None = None
        self._app: Flask | None = None
        self._guard_response_factory = FlaskResponseFactory()

        if app is not None:
            self.init_app(app, config=config)

    def _resolve_config(self, config: SecurityConfig | None) -> None:
        if config is not None:
            self.config = config
        elif self.config is None:
            raise ValueError("SecurityConfig must be provided")

    def _init_geo_ip_handler(self) -> None:
        assert self.config is not None
        self.geo_ip_handler = None
        if self.config.whitelist_countries or self.config.blocked_countries:
            self.geo_ip_handler = self.config.geo_ip_handler

    def _init_redis_handler(self) -> None:
        assert self.config is not None
        self.redis_handler = None
        if self.config.enable_redis:
            from guard_core.sync.handlers.redis_handler import RedisManager

            self.redis_handler = RedisManager(self.config)

    def _init_agent_handler(self) -> None:
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
                "Install with: uv add guard-agent"
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize Guard Agent: {e}")
            self.logger.warning("Continuing without agent functionality")

    def _init_core_components(self) -> None:
        assert self.config is not None
        assert self.logger is not None

        self.handler_initializer = HandlerInitializer(
            config=self.config,
            redis_handler=self.redis_handler,
            agent_handler=self.agent_handler,
            geo_ip_handler=self.geo_ip_handler,
            rate_limit_handler=self.rate_limit_handler,
            guard_decorator=self.guard_decorator,
        )

    def _init_route_resolver(self) -> None:
        assert self.config is not None
        assert self.logger is not None

        routing_context = RoutingContext(
            config=self.config,
            logger=self.logger,
            guard_decorator=self.guard_decorator,
        )
        self.route_resolver = RouteConfigResolver(routing_context)

    def _build_event_bus_and_contexts(self) -> None:
        assert self.config is not None
        assert self.logger is not None
        assert self.route_resolver is not None
        assert self.handler_initializer is not None

        if self.handler_initializer.composite_handler is not None:
            self.event_bus = self.handler_initializer.build_event_bus(
                geo_ip_handler=self.geo_ip_handler
            )
            self.metrics_collector = self.handler_initializer.build_metrics_collector()
        else:
            self.event_bus = SecurityEventBus(
                self.agent_handler, self.config, self.geo_ip_handler
            )
            self.metrics_collector = MetricsCollector(self.agent_handler, self.config)

        response_context = ResponseContext(
            config=self.config,
            logger=self.logger,
            metrics_collector=self.metrics_collector,
            agent_handler=self.agent_handler,
            guard_decorator=self.guard_decorator,
            response_factory=self._guard_response_factory,
        )
        self.response_factory = ErrorResponseFactory(response_context)

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
            behavior_tracker=self.handler_initializer.behavior_tracker,
        )
        self.behavioral_processor = BehavioralProcessor(behavioral_context)

    def init_app(self, app: Flask, config: SecurityConfig | None = None) -> None:
        self._resolve_config(config)
        assert self.config is not None

        self.logger = setup_custom_logging(
            self.config.custom_log_file, log_format=self.config.log_format
        )
        self.last_cloud_ip_refresh = 0
        self.suspicious_request_counts = {}
        self.last_cleanup = time.time()
        self.rate_limit_handler = RateLimitManager(self.config)

        self._configure_security_headers(self.config)
        self._init_geo_ip_handler()
        self._init_redis_handler()
        self._init_agent_handler()
        self._init_core_components()
        self._init_route_resolver()
        self._build_event_bus_and_contexts()

        self._app = app

        app.extensions["flaskapi_guard"] = {
            "guard": self,
            "config": self.config,
            "guard_decorator": self.guard_decorator,
        }

        self._build_security_pipeline()
        self._initialize_handlers()
        self._cors_handler = (
            CorsHandler(self.config) if self.config.enable_cors else None
        )

        app.before_request(self._before_request)
        app.after_request(self._after_request)

    def _initialize_handlers(self) -> None:
        assert self.handler_initializer is not None
        self.handler_initializer.guard_decorator = self.guard_decorator
        self.handler_initializer.initialize_redis_handlers()
        self.handler_initializer.initialize_agent_integrations()

        if self.handler_initializer.composite_handler is not None:
            self.agent_handler = self.handler_initializer.composite_handler
            self._build_event_bus_and_contexts()

    def _build_security_pipeline(self) -> None:
        from guard_core.sync.core.checks import (
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

        middleware = cast(SyncGuardMiddlewareProtocol, self)
        checks = [
            RouteConfigCheck(middleware),
            EmergencyModeCheck(middleware),
            HttpsEnforcementCheck(middleware),
            RequestLoggingCheck(middleware),
            RequestSizeContentCheck(middleware),
            RequiredHeadersCheck(middleware),
            AuthenticationCheck(middleware),
            ReferrerCheck(middleware),
            CustomValidatorsCheck(middleware),
            TimeWindowCheck(middleware),
            CloudIpRefreshCheck(middleware),
            IpSecurityCheck(middleware),
            CloudProviderCheck(middleware),
            UserAgentCheck(middleware),
            RateLimitCheck(middleware),
            SuspiciousActivityCheck(middleware),
            CustomRequestCheck(middleware),
        ]

        self.security_pipeline = SecurityCheckPipeline(checks)
        assert self.logger is not None
        self.logger.info(
            f"Security pipeline initialized with {len(checks)} checks: "
            f"{self.security_pipeline.get_check_names()}"
        )

    def _configure_security_headers(self, config: SecurityConfig) -> None:
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

    @property
    def guard_response_factory(self) -> FlaskResponseFactory:
        return self._guard_response_factory

    def _execute_security_pipeline(
        self, guard_request: FlaskGuardRequest
    ) -> Response | None:
        if self.security_pipeline:
            result = self.security_pipeline.execute(guard_request)
            if result is not None:
                return unwrap_response(result)
        return None

    def _process_behavioral_usage(
        self,
        guard_request: FlaskGuardRequest,
        client_ip: str,
        route_config: RouteConfig | None,
    ) -> None:
        assert self.behavioral_processor is not None
        if route_config and route_config.behavior_rules and client_ip:
            self.behavioral_processor.process_usage_rules(
                guard_request, client_ip, route_config
            )

    def _populate_guard_state(self, guard_request: FlaskGuardRequest) -> None:
        from flask import current_app, request

        if not request.endpoint:
            return
        view_func = current_app.view_functions.get(request.endpoint)
        if not view_func or not hasattr(view_func, "_guard_route_id"):
            return
        guard_request.state.guard_route_id = view_func._guard_route_id
        guard_request.state.guard_endpoint_id = (
            f"{view_func.__module__}.{view_func.__qualname__}"
        )

    def _handle_preflight(
        self,
        guard_request: FlaskGuardRequest,
        method: str,
        request_headers: dict[str, str],
    ) -> Response | None:
        if self._cors_handler is None:
            return None
        if not is_preflight(method, request_headers):
            return None
        blocking = self._execute_security_pipeline(guard_request)
        if blocking is not None:
            return self._attach_cors_to_blocked(blocking, request_headers)
        preflight = self._cors_handler.build_preflight_response(request_headers)
        return self._build_flask_preflight_response(preflight)

    def _check_passthrough(
        self,
        guard_request: FlaskGuardRequest,
        request_headers: dict[str, str],
    ) -> Response | None:
        assert self.bypass_handler is not None
        passthrough = self.bypass_handler.handle_passthrough(guard_request)
        if passthrough is None:
            return None
        return self._attach_cors_to_blocked(
            unwrap_response(passthrough), request_headers
        )

    def _check_security_bypass(
        self,
        guard_request: FlaskGuardRequest,
        route_config: RouteConfig | None,
        request_headers: dict[str, str],
    ) -> Response | None:
        assert self.bypass_handler is not None
        bypass = self.bypass_handler.handle_security_bypass(
            guard_request, route_config=route_config
        )
        if bypass is None:
            return None
        return self._attach_cors_to_blocked(unwrap_response(bypass), request_headers)

    def _before_request(self) -> Response | None:
        from flask import request

        assert self.config is not None
        assert self.bypass_handler is not None
        assert self.route_resolver is not None
        assert self.behavioral_processor is not None

        g.request_start_time = time.time()
        guard_request = FlaskGuardRequest(request)
        self._populate_guard_state(guard_request)

        request_headers = dict(request.headers)

        preflight_response = self._handle_preflight(
            guard_request, request.method, request_headers
        )
        if preflight_response is not None:
            return preflight_response

        passthrough_response = self._check_passthrough(guard_request, request_headers)
        if passthrough_response is not None:
            return passthrough_response

        client_ip = extract_client_ip(guard_request, self.config, self.agent_handler)
        route_config = self.route_resolver.get_route_config(guard_request)

        g.client_ip = client_ip
        g.route_config = route_config

        bypass_response = self._check_security_bypass(
            guard_request, route_config, request_headers
        )
        if bypass_response is not None:
            return bypass_response

        blocking = self._execute_security_pipeline(guard_request)
        if blocking is not None:
            return self._attach_cors_to_blocked(blocking, request_headers)

        self._process_behavioral_usage(guard_request, client_ip, route_config)

        return None

    def _after_request(self, response: Response) -> Response:
        from flask import request

        assert self.response_factory is not None
        assert self.behavioral_processor is not None

        start_time = getattr(g, "request_start_time", time.time())
        response_time = time.time() - start_time
        route_config = getattr(g, "route_config", None)

        guard_request = FlaskGuardRequest(request)
        guard_response = FlaskGuardResponse(response)
        result = self.response_factory.process_response(
            guard_request,
            guard_response,
            response_time,
            route_config,
            process_behavioral_rules=self.behavioral_processor.process_return_rules,
        )
        flask_response = unwrap_response(result)

        if self._cors_handler is not None:
            cors_headers = self._cors_handler.build_response_headers(
                dict(request.headers)
            )
            for k, v in cors_headers.items():
                flask_response.headers[k] = v

        return flask_response

    def _attach_cors_to_blocked(
        self, response: Response, request_headers: dict[str, str]
    ) -> Response:
        if self._cors_handler is not None:
            cors_headers = self._cors_handler.build_response_headers(request_headers)
            for k, v in cors_headers.items():
                response.headers[k] = v
        return response

    def _build_flask_preflight_response(
        self, preflight: CorsPreflightResponse
    ) -> Response:
        flask_response = Response(
            preflight.body,
            status=preflight.status_code,
        )
        for k, v in preflight.headers.items():
            flask_response.headers[k] = v
        return flask_response

    def _check_time_window(self, time_restrictions: dict[str, str]) -> bool:
        assert self.validator is not None
        result: bool = self.validator.check_time_window(time_restrictions)
        return result

    def _check_route_ip_access(
        self, client_ip: str, route_config: RouteConfig
    ) -> bool | None:
        from guard_core.sync.core.checks.helpers import check_route_ip_access

        result: bool | None = check_route_ip_access(client_ip, route_config, self)
        return result

    def _check_user_agent_allowed(
        self, user_agent: str, route_config: RouteConfig | None
    ) -> bool:
        from guard_core.sync.core.checks.helpers import check_user_agent_allowed

        result: bool = check_user_agent_allowed(user_agent, route_config, self.config)
        return result

    def _process_decorator_usage_rules(
        self, request: Any, client_ip: str, route_config: RouteConfig
    ) -> None:
        assert self.behavioral_processor is not None
        guard_request = FlaskGuardRequest(request)
        self.behavioral_processor.process_usage_rules(
            guard_request, client_ip, route_config
        )

    def _process_decorator_return_rules(
        self,
        request: Any,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        assert self.behavioral_processor is not None
        guard_request = FlaskGuardRequest(request)
        guard_response = FlaskGuardResponse(response)
        self.behavioral_processor.process_return_rules(
            guard_request, guard_response, client_ip, route_config
        )

    def _get_endpoint_id(self, request: Any) -> str:
        assert self.behavioral_processor is not None
        guard_request = FlaskGuardRequest(request)
        result: str = self.behavioral_processor.get_endpoint_id(guard_request)
        return result

    def refresh_cloud_ip_ranges(self) -> None:
        assert self.config is not None

        if not self.config.block_cloud_providers:
            return

        cloud_handler.refresh(self.config.block_cloud_providers)
        self.last_cloud_ip_refresh = int(time.time())

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> GuardResponse:
        assert self.response_factory is not None
        result: GuardResponse = self.response_factory.create_error_response(
            status_code, default_message
        )
        return result

    def reset(self) -> None:
        assert self.rate_limit_handler is not None
        self.rate_limit_handler.reset()
