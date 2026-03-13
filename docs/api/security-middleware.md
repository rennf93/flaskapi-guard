---

title: FlaskAPIGuard API - FlaskAPI Guard
description: Complete API reference for FlaskAPI Guard's FlaskAPIGuard extension class and its configuration options
keywords: security extension, flask extension, api security, extension configuration
---

FlaskAPIGuard
==================

The `FlaskAPIGuard` class is the core component of FlaskAPI Guard that handles all security features.

!!! info "Architecture"
    FlaskAPIGuard uses a modular architecture with specialized core modules. The extension acts as an orchestration layer, delegating to specialized handlers. See [Core Architecture](core-architecture.md) for internal details.

___

Class Definition
----------------

```python
class FlaskAPIGuard:
    def __init__(
        self,
        app: Flask | None = None,
        config: SecurityConfig | None = None
    ):
        """
        Initialize the FlaskAPIGuard extension.

        Args:
            app: The Flask application (optional for app factory pattern)
            config: Security configuration object

        Note:
            The extension initializes all core components using
            dependency injection for clean separation of concerns.
        """
```

___

Architecture Overview
---------------------

Request Processing Flow
-----------------------

The extension processes requests through a modular pipeline:

```text
Request -> before_request hook
    |
1. BypassHandler.handle_passthrough()
    |-- No client IP? -> Pass through
    +-- Excluded path? -> Pass through
    |
2. Extract client IP and route config
    |
3. BypassHandler.handle_security_bypass()
    +-- Decorator bypass? -> Pass through
    |
4. SecurityCheckPipeline.execute()
    |-- RouteConfigCheck
    |-- EmergencyModeCheck
    |-- HttpsEnforcementCheck
    |-- RequestLoggingCheck
    |-- RequestSizeContentCheck
    |-- RequiredHeadersCheck
    |-- AuthenticationCheck
    |-- ReferrerCheck
    |-- CustomValidatorsCheck
    |-- TimeWindowCheck
    |-- CloudIpRefreshCheck
    |-- IpSecurityCheck
    |-- CloudProviderCheck
    |-- UserAgentCheck
    |-- RateLimitCheck
    |-- SuspiciousActivityCheck
    +-- CustomRequestCheck
    |
5. BehavioralProcessor.process_usage_rules()
    |
6. (request proceeds to view function)
    |
Response -> after_request hook
    |
7. ErrorResponseFactory.process_response()
    |-- Apply security headers
    |-- Apply CORS headers
    |-- Collect metrics
    +-- Process behavioral return rules
    |
Response
```

Core Components
---------------

The extension delegates to these specialized modules:

- **SecurityCheckPipeline**: Executes security checks in sequence
- **SecurityEventBus**: Sends security events to monitoring agent
- **MetricsCollector**: Collects request/response metrics
- **HandlerInitializer**: Initializes Redis and Agent handlers
- **ErrorResponseFactory**: Creates and processes responses
- **RouteConfigResolver**: Resolves decorator configurations
- **RequestValidator**: Validates request properties
- **BypassHandler**: Handles security bypasses
- **BehavioralProcessor**: Processes behavioral rules

See [Core Architecture](core-architecture.md) for detailed documentation of each module.

___

Public Methods
--------------

init_app
--------

```python
def init_app(
    self,
    app: Flask,
    config: SecurityConfig | None = None
) -> None:
    """
    Initialize the extension with a Flask application.

    Supports the Flask app factory pattern. Registers before_request
    and after_request hooks, initializes handlers, and builds the
    security pipeline.

    Args:
        app: The Flask application
        config: Security configuration object (optional if passed to __init__)

    Example:
        ```python
        guard = FlaskAPIGuard()
        guard.init_app(app, config=config)
        ```
    """
```

create_error_response
---------------------

```python
def create_error_response(
    self,
    status_code: int,
    default_message: str
) -> Response:
    """
    Create standardized error responses.

    Delegates to ErrorResponseFactory for response creation.

    Args:
        status_code: HTTP status code
        default_message: Default error message

    Returns:
        Response: Error response with optional custom message

    Note:
        Custom error messages can be configured in SecurityConfig
        via the custom_error_responses dict.
    """
```

initialize
----------

```python
def initialize(self) -> None:
    """
    Initialize all components.

    This method is called automatically during init_app().

    Tasks performed:
        - Build security check pipeline
        - Initialize Redis handlers (if enabled)
        - Initialize agent integrations (if enabled)
        - Initialize dynamic rule manager (if configured)

    Example:
        ```python
        guard = FlaskAPIGuard(app, config=config)
        # initialize() is called automatically
        ```
    """
```

set_decorator_handler
---------------------

```python
def set_decorator_handler(
    self,
    decorator_handler: BaseSecurityDecorator | None
) -> None:
    """
    Set the SecurityDecorator instance for decorator support.

    This enables route-level security configuration via decorators.

    Args:
        decorator_handler: SecurityDecorator instance or None

    Example:
        ```python
        guard_deco = SecurityDecorator(config)
        guard.set_decorator_handler(guard_deco)
        ```
    """
```

configure_cors
--------------

```python
@staticmethod
def configure_cors(app: Flask, config: SecurityConfig) -> bool:
    """
    Configure CORS handling based on SecurityConfig.

    This is a convenience method for setting up CORS.

    Args:
        app: Flask application instance
        config: Security configuration with CORS settings

    Returns:
        bool: True if CORS was configured, False otherwise

    Example:
        ```python
        FlaskAPIGuard.configure_cors(app, config)
        FlaskAPIGuard(app, config=config)
        ```
    """
```

___

Handler Integration
-------------------

The extension works with singleton handler instances:

- All handler classes (IPBanManager, CloudManager, etc.) use the singleton pattern
- The extension initializes these existing instances conditionally based on configuration
- IPInfoManager is only initialized when country filtering is enabled
- CloudManager is only loaded when cloud provider blocking is configured
- This selective loading improves performance when not all features are used

Initialization Process
-----------------------

The extension uses `HandlerInitializer` to set up all handlers:

```python
# In __init__
self.handler_initializer = HandlerInitializer(
    config=self.config,
    redis_handler=self.redis_handler,
    agent_handler=self.agent_handler,
    geo_ip_handler=self.geo_ip_handler,
    rate_limit_handler=self.rate_limit_handler,
    guard_decorator=self.guard_decorator,
)

# In initialize()
self.handler_initializer.initialize_redis_handlers()
self.handler_initializer.initialize_agent_integrations()
```

___

Redis Configuration
-------------------

Enable Redis in SecurityConfig:

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://prod:6379/0",
    redis_prefix="prod_security:"
)
```

The extension automatically initializes:
- CloudManager cloud provider IP ranges
- IPBanManager distributed banning
- IPInfoManager IP geolocation
- RateLimitManager rate limiting
- RedisManager Redis caching
- SusPatternsManager suspicious patterns

___

Proxy Security Configuration
----------------------------

The extension supports secure handling of proxy headers:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # List of trusted proxy IPs/ranges
    trusted_proxy_depth=1,  # Number of proxies in the chain
    trust_x_forwarded_proto=True,  # Trust X-Forwarded-Proto header from trusted proxies
)
```

This prevents IP spoofing attacks through header manipulation.

___

Usage Examples
--------------

Basic Setup
-----------

```python
from flask import Flask
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.models import SecurityConfig

app = Flask(__name__)

config = SecurityConfig(
    rate_limit=100,
    enable_https=True,
    enable_cors=True
)

FlaskAPIGuard(app, config=config)
```

With Decorators
---------------

```python
from flask import Flask
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.decorators import SecurityDecorator

app = Flask(__name__)

config = SecurityConfig(rate_limit=100)
guard_deco = SecurityDecorator(config)

# Apply decorators to routes
@app.route("/api/limited")
@guard_deco.rate_limit(requests=10, window=300)
def limited_endpoint():
    return {"data": "limited"}

# Add extension and set decorator
guard = FlaskAPIGuard(app, config=config)
guard.set_decorator_handler(guard_deco)
```

With App Factory Pattern
-------------------------

```python
from flask import Flask
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.models import SecurityConfig

guard = FlaskAPIGuard()

def create_app():
    app = Flask(__name__)

    config = SecurityConfig(
        enable_redis=True,
        redis_url="redis://localhost:6379"
    )

    guard.init_app(app, config=config)

    return app
```

___

Internal Architecture
---------------------

!!! note "For Contributors"
    The internal architecture is documented in [Core Architecture](core-architecture.md). This section provides a high-level overview.

Modular Design
-------------------------

The extension delegates to specialized modules in `flaskapi_guard/core/`:

- **checks/**: Security check implementations (Chain of Responsibility pattern)
- **events/**: Event bus and metrics collection
- **initialization/**: Handler initialization logic
- **responses/**: Response creation and processing
- **routing/**: Route configuration resolution
- **validation/**: Request validation utilities
- **bypass/**: Security bypass handling
- **behavioral/**: Behavioral rule processing

Benefits of Modular Architecture
--------------------------------

- **Maintainability**: Each module < 200 LOC, single responsibility
- **Testability**: Each component independently testable
- **Performance**: Better caching and optimization opportunities
- **Extensibility**: Easy to add new checks or modify behavior
- **Development Speed**: 2-3x faster feature additions (projected)

___

See Also
--------

- [Core Architecture](core-architecture.md) - Detailed internal architecture
- [SecurityConfig](../tutorial/configuration/security-config.md) - Configuration options
- [Decorators](decorators.md) - Route-level security
- [API Overview](overview.md) - Complete API reference
