---

title: API Reference - FlaskAPI Guard
description: Complete API documentation for FlaskAPI Guard security extension and its components
keywords: flaskapi guard api, security extension api, python api reference
---

API Reference Overview
======================

!!! info "Architecture"
    FlaskAPI Guard uses a modular core architecture. While the public API remains unchanged, the internal implementation is organized into specialized modules in `flaskapi_guard/core/`. See [Core Architecture](core-architecture.md) for details.

___

Core Components
---------------

Extension & Configuration
----------------------------

- **[FlaskAPIGuard](security-middleware.md)**: The main extension that handles all security features
- **[SecurityConfig](../tutorial/configuration/security-config.md)**: Configuration class for all security settings
- **[SecurityDecorator](decorators.md)**: Route-level security decorator system

Internal Core Modules
--------------------------------

!!! warning "Internal Implementation"
    These modules are internal implementation details. Always use the public API (`FlaskAPIGuard`, `SecurityConfig`, `SecurityDecorator`).

    Documentation provided for contributors and advanced users.

- **[Core Architecture](core-architecture.md)**: Complete internal architecture documentation
  - **SecurityCheckPipeline**: Chain of Responsibility pattern for security checks
  - **SecurityEventBus**: Centralized event dispatching
  - **MetricsCollector**: Request/response metrics collection
  - **HandlerInitializer**: Handler initialization logic
  - **ErrorResponseFactory**: Response creation and processing
  - **RouteConfigResolver**: Route configuration resolution
  - **RequestValidator**: Request validation utilities
  - **BypassHandler**: Security bypass handling
  - **BehavioralProcessor**: Behavioral rule processing

Handler Components
------------------

- **[IPBanManager](ipban-manager.md)**: Manages IP banning functionality
- **[IPInfoManager](ipinfo-manager.md)**: Handles IP geolocation using IPInfo's database
- **[SusPatternsManager](sus-patterns.md)**: Manages suspicious patterns for threat detection
- **[CloudManager](cloud-manager.md)**: Handles cloud provider IP range detection
- **[RateLimitManager](ratelimit-manager.md)**: Handles rate limiting functionality
- **[RedisManager](redis-manager.md)**: Handles Redis connections and atomic operations
- **[BehaviorTracker](behavior-manager.md)**: Handles behavioral analysis and monitoring
- **[SecurityHeadersManager](security-headers.md)**: Manages security headers

Utilities
---------

- **[Utilities](utilities.md)**: Helper functions for logging and request analysis

___

Key Classes and Instances
-------------------------

```python
# Core extension and configuration
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.models import SecurityConfig

# Security decorators
from flaskapi_guard.decorators import SecurityDecorator, RouteConfig
from flaskapi_guard.decorators.base import get_route_decorator_config

# Handler classes and their pre-initialized instances
from flaskapi_guard.handlers.cloud_handler import CloudManager, cloud_handler
from flaskapi_guard.handlers.ipban_handler import IPBanManager, ip_ban_manager
from flaskapi_guard.handlers.ratelimit_handler import RateLimitManager, rate_limit_handler
from flaskapi_guard.handlers.redis_handler import RedisManager, redis_handler
from flaskapi_guard.handlers.suspatterns_handler import SusPatternsManager, sus_patterns_handler
from flaskapi_guard.handlers.behavior_handler import BehaviorTracker, BehaviorRule

# Special case - requires parameters
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager
```

___

Singleton Pattern
-----------------

Most handler classes use a singleton pattern with `__new__` to ensure only one instance:

```python
class ExampleHandler:
    _instance = None

    def __new__(cls, *args, **kwargs) -> "ExampleHandler":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            # Initialize instance attributes
        return cls._instance
```

___

Configuration Model
-------------------

The `SecurityConfig` class is the central configuration point:

```python
class SecurityConfig:
    def __init__(
        self,
        geo_ip_handler: GeoIPHandler | None = None,
        whitelist: list[str] | None = None,
        blacklist: list[str] = [],
        blocked_countries: list[str] = [],
        whitelist_countries: list[str] = [],
        blocked_user_agents: list[str] = [],
        auto_ban_threshold: int = 5,
        auto_ban_duration: int = 3600,
        rate_limit: int = 100,
        rate_limit_window: int = 60,
        enable_cors: bool = False,
        # ... other parameters
    ):
        # ... initialization
```

___

Optimized Loading
-----------------

FlaskAPI Guard uses a smart loading strategy to improve performance:

- **IPInfoManager**: Only downloaded and initialized when country filtering is configured
- **CloudManager**: Only fetches cloud provider IP ranges when cloud blocking is enabled
- **Handlers Initialization**: Extension conditionally initializes components based on configuration

This approach reduces startup time and memory usage when not all security features are needed.

```python
# Conditional loading example from extension
def initialize(self) -> None:
    if self.config.enable_redis and self.redis_handler:
        self.redis_handler.initialize()
        # Only initialize when needed
        if self.config.block_cloud_providers:
            cloud_handler.initialize_redis(
                self.redis_handler, self.config.block_cloud_providers
            )
        ip_ban_manager.initialize_redis(self.redis_handler)
        # Only initialize if country filtering is enabled
        if self.geo_ip_handler is not None:
            self.geo_ip_handler.initialize_redis(self.redis_handler)
```

___

Security Decorators
-------------------

FlaskAPI Guard provides a comprehensive decorator system for route-level security controls:

SecurityDecorator Class
----------------------------

The main decorator class combines all security capabilities:

```python
from flaskapi_guard.decorators import SecurityDecorator

config = SecurityConfig()
guard_deco = SecurityDecorator(config)

# Apply to routes
@app.route("/api/sensitive")
@guard_deco.rate_limit(requests=5, window=300)
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])
@guard_deco.block_countries(["CN", "RU"])
def sensitive_endpoint():
    return {"data": "sensitive"}
```

___

Decorator Categories
-------------------

- **AccessControlMixin**: IP filtering, geographic restrictions, cloud provider blocking
- **AuthenticationMixin**: HTTPS enforcement, auth requirements, API key validation
- **RateLimitingMixin**: Custom rate limits, geographic rate limiting
- **BehavioralMixin**: Usage monitoring, return pattern analysis, frequency detection
- **ContentFilteringMixin**: Content type filtering, size limits, user agent blocking
- **AdvancedMixin**: Time windows, suspicious detection, honeypot detection

___

Integration with Extension
----------------------------

Decorators work seamlessly with FlaskAPIGuard:

```python
# Set up extension and decorators
FlaskAPIGuard(app, config=config)
app.extensions["flaskapi_guard"]["guard_decorator"] = guard_deco  # Required for integration
```

___

Route Configuration Priority
----------------------------

Configuration is applied in the following order of precedence:

1. Decorator Settings (highest priority)
2. Global Extension Settings
3. Default Settings (lowest priority)

This allows route-specific overrides while maintaining global defaults.
