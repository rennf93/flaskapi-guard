from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from flaskapi_guard.models import SecurityConfig


class HandlerInitializer:
    """Centralized handler initialization for extension."""

    def __init__(
        self,
        config: "SecurityConfig",
        redis_handler: Any = None,
        agent_handler: Any = None,
        geo_ip_handler: Any = None,
        rate_limit_handler: Any = None,
        guard_decorator: Any = None,
    ):
        """
        Initialize the HandlerInitializer.

        Args:
            config: Security configuration
            redis_handler: Optional Redis handler instance
            agent_handler: Optional agent handler instance
            geo_ip_handler: Optional GeoIP handler instance
            rate_limit_handler: Optional rate limit handler instance
            guard_decorator: Optional guard decorator instance
        """
        self.config = config
        self.redis_handler = redis_handler
        self.agent_handler = agent_handler
        self.geo_ip_handler = geo_ip_handler
        self.rate_limit_handler = rate_limit_handler
        self.guard_decorator = guard_decorator

    def initialize_redis_handlers(self) -> None:
        """Initialize Redis for all handlers that support it."""
        if not (self.config.enable_redis and self.redis_handler):
            return

        self.redis_handler.initialize()

        # Import handlers
        from flaskapi_guard.handlers.cloud_handler import cloud_handler
        from flaskapi_guard.handlers.ipban_handler import ip_ban_manager
        from flaskapi_guard.handlers.suspatterns_handler import sus_patterns_handler

        # Initialize cloud handler with Redis if cloud providers are blocked
        if self.config.block_cloud_providers:
            cloud_handler.initialize_redis(
                self.redis_handler, self.config.block_cloud_providers
            )

        # Initialize core handlers
        ip_ban_manager.initialize_redis(self.redis_handler)
        if self.geo_ip_handler is not None:
            self.geo_ip_handler.initialize_redis(self.redis_handler)
        if self.rate_limit_handler is not None:
            self.rate_limit_handler.initialize_redis(self.redis_handler)
        sus_patterns_handler.initialize_redis(self.redis_handler)

    def initialize_agent_for_handlers(self) -> None:
        """Initialize agent in all handlers that support it."""
        if not self.agent_handler:
            return

        # Import handlers
        from flaskapi_guard.handlers.cloud_handler import cloud_handler
        from flaskapi_guard.handlers.ipban_handler import ip_ban_manager
        from flaskapi_guard.handlers.suspatterns_handler import sus_patterns_handler

        # Initialize core handlers
        ip_ban_manager.initialize_agent(self.agent_handler)
        if self.rate_limit_handler is not None:
            self.rate_limit_handler.initialize_agent(self.agent_handler)
        sus_patterns_handler.initialize_agent(self.agent_handler)

        # Initialize cloud handler if enabled
        if self.config.block_cloud_providers:
            cloud_handler.initialize_agent(self.agent_handler)

        # Initialize geo IP handler if it has agent support
        if self.geo_ip_handler and hasattr(self.geo_ip_handler, "initialize_agent"):
            self.geo_ip_handler.initialize_agent(self.agent_handler)

    def initialize_dynamic_rule_manager(self) -> None:
        """Initialize dynamic rule manager if enabled."""
        if not (self.agent_handler and self.config.enable_dynamic_rules):
            return

        from flaskapi_guard.handlers.dynamic_rule_handler import DynamicRuleManager

        dynamic_rule_manager = DynamicRuleManager(self.config)
        dynamic_rule_manager.initialize_agent(self.agent_handler)

        if self.redis_handler:
            dynamic_rule_manager.initialize_redis(self.redis_handler)

    def initialize_agent_integrations(self) -> None:
        """Initialize agent and its integrations with Redis and decorators."""
        if not self.agent_handler:
            return

        self.agent_handler.start()

        # Connect agent to Redis if available
        if self.redis_handler:
            self.agent_handler.initialize_redis(self.redis_handler)
            self.redis_handler.initialize_agent(self.agent_handler)

        # Initialize agent in all handlers
        self.initialize_agent_for_handlers()

        # Initialize agent in decorator handler if it exists
        if self.guard_decorator and hasattr(self.guard_decorator, "initialize_agent"):
            self.guard_decorator.initialize_agent(self.agent_handler)

        # Initialize dynamic rule manager if enabled
        self.initialize_dynamic_rule_manager()
