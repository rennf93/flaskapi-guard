---

title: Core Architecture - FlaskAPI Guard
description: Internal architecture documentation for FlaskAPI Guard's modular core system
keywords: core architecture, modular design, security checks, extension internals

---

Core Architecture (Internal)
=============================

!!! warning "Internal Implementation Details"
    The `flaskapi_guard/core/` modules documented here are **internal implementation details** and should NOT be imported directly in user code. Always use the public API from `flaskapi_guard.extension`, `flaskapi_guard.models`, and `flaskapi_guard.decorators`.

    This documentation is provided for contributors and advanced users who want to understand the internal architecture.

___

Overview
--------

FlaskAPI Guard uses a modular core architecture that separates security concerns into specialized, independently testable modules. This transformation improved maintainability while maintaining 100% backward compatibility.

Architecture Principles
------------------------

1. **Single Responsibility**: Each module has one clear purpose
2. **Dependency Injection**: Clean dependencies via context objects
3. **Chain of Responsibility**: Security checks execute in a pipeline
4. **Testability**: Each component independently testable
5. **Performance**: Better caching and optimization opportunities

Module Overview
----------------

```text
flaskapi_guard/core/
├── checks/              # Security check pipeline (Chain of Responsibility)
├── events/              # Event bus and metrics collection
├── initialization/      # Handler initialization logic
├── responses/           # Response creation and processing
├── routing/             # Route configuration resolution
├── validation/          # Request validation utilities
├── bypass/              # Security bypass handling
└── behavioral/          # Behavioral rule processing
```

___

Module: flaskapi_guard/core/checks/
--------------------------

**Purpose**: Security check implementations using the Chain of Responsibility pattern

**Pattern**: Pipeline-based execution where each check can block or pass the request

Key Components
--------------

SecurityCheck (Base Class)
--------------------------

Abstract base class for all security checks.

**Location**: `flaskapi_guard/core/checks/base.py`

**Key Methods**:

```python
class SecurityCheck:
    check_name: str  # Unique identifier for the check

    def check(self, request: Request) -> Response | None:
        """Execute the security check. Return Response to block, None to pass."""
        ...

    def create_error_response(
        self, status_code: int, default_message: str
    ) -> Response:
        """Create standardized error response."""
        ...
```

**Usage**: All security checks inherit from this base class.

SecurityCheckPipeline
---------------------

Orchestrates the execution of multiple security checks in sequence.

**Location**: `flaskapi_guard/core/checks/pipeline.py`

**Key Methods**:

```python
class SecurityCheckPipeline:
    def __init__(self, checks: list[SecurityCheck]):
        """Initialize pipeline with ordered list of checks."""
        ...

    def execute(self, request: Request) -> Response | None:
        """Execute all checks. Returns first blocking response or None."""
        ...

    def get_check_names(self) -> list[str]:
        """Get names of all checks in execution order."""
        ...
```

**Features**:
- Sequential execution with early termination
- Error handling with fail-secure option
- Logging of blocking checks
- Dynamic check addition/removal

Check Implementations
---------------------

**Location**: `flaskapi_guard/core/checks/implementations/`

Execution Order
---------------

Checks execute in this order (defined in `extension.py._build_security_pipeline()`):

1. **RouteConfigCheck** - Extract route config and client IP
2. **EmergencyModeCheck** - Emergency mode (highest priority)
3. **HttpsEnforcementCheck** - HTTPS enforcement (can redirect)
4. **RequestLoggingCheck** - Log request
5. **RequestSizeContentCheck** - Validate size/content
6. **RequiredHeadersCheck** - Check required headers
7. **AuthenticationCheck** - Verify authentication
8. **ReferrerCheck** - Check referrer
9. **CustomValidatorsCheck** - Custom validators
10. **TimeWindowCheck** - Time-based access
11. **CloudIpRefreshCheck** - Periodic maintenance
12. **IpSecurityCheck** - IP whitelist/blacklist
13. **CloudProviderCheck** - Cloud provider blocking
14. **UserAgentCheck** - User agent filtering
15. **RateLimitCheck** - Rate limiting
16. **SuspiciousActivityCheck** - Threat detection
17. **CustomRequestCheck** - Custom checks

Implementation Details
----------------------

Each check is self-contained and follows this pattern:

```python
from flaskapi_guard.core.checks.base import SecurityCheck

class ExampleCheck(SecurityCheck):
    check_name = "example_check"

    def __init__(self, extension: "FlaskAPIGuard"):
        self.extension = extension
        self.config = extension.config
        self.logger = extension.logger

    def check(self, request: Request) -> Response | None:
        # Get context from flask.g (set by RouteConfigCheck)
        client_ip = g.client_ip
        route_config = g.route_config

        # Perform check logic
        if should_block:
            return self.create_error_response(403, "Check failed")

        return None  # Check passed
```

Helper Functions
----------------

**Location**: `flaskapi_guard/core/checks/helpers.py`

Common utilities shared across check implementations:

- `check_route_ip_access()` - IP whitelist/blacklist validation
- `check_user_agent_allowed()` - User agent validation
- `get_client_country()` - Country lookup
- Other shared validation logic

___

Module: flaskapi_guard/core/events/
--------------------------

**Purpose**: Event system for extension actions and metrics collection

SecurityEventBus
----------------

Centralized event dispatching for security-related events.

**Location**: `flaskapi_guard/core/events/extension_events.py`

**Key Methods**:

```python
class SecurityEventBus:
    def send_extension_event(
        self,
        event_type: str,
        request: Request,
        action_taken: str,
        reason: str,
        **kwargs
    ) -> None:
        """Send extension-specific events to agent."""
        ...

    def send_https_violation_event(
        self, request: Request, route_config: RouteConfig | None
    ) -> None:
        """Send HTTPS violation event."""
        ...

    def send_cloud_detection_events(
        self,
        request: Request,
        client_ip: str,
        cloud_providers: list[str],
        route_config: RouteConfig | None,
        cloud_handler: Any,
        passive_mode: bool,
    ) -> None:
        """Send cloud provider detection events."""
        ...
```

**Usage**: Sends events to optional monitoring agent for observability.

MetricsCollector
-----------------

Collects and reports request metrics.

**Location**: `flaskapi_guard/core/events/metrics.py`

**Key Methods**:

```python
class MetricsCollector:
    def send_security_metric(
        self, metric_name: str, value: float, tags: dict[str, str] | None = None
    ) -> None:
        """Send individual security metric."""
        ...

    def collect_request_metrics(
        self,
        request: Request,
        response: Response,
        response_time: float,
        client_ip: str,
    ) -> None:
        """Collect comprehensive request metrics."""
        ...
```

___

Module: flaskapi_guard/core/initialization/
----------------------------------

**Purpose**: Centralized handler initialization logic

HandlerInitializer
-------------------

Manages initialization of Redis, Agent, and other handlers.

**Location**: `flaskapi_guard/core/initialization/handler_initializer.py`

**Key Methods**:

```python
class HandlerInitializer:
    def initialize_redis_handlers(self) -> None:
        """Initialize Redis for all handlers."""
        ...

    def initialize_agent_for_handlers(self) -> None:
        """Initialize agent in all handlers."""
        ...

    def initialize_agent_integrations(self) -> None:
        """Initialize agent and its integrations."""
        ...

    def initialize_dynamic_rule_manager(self) -> None:
        """Initialize dynamic rule manager if configured."""
        ...
```

**Usage**: Called from `FlaskAPIGuard.initialize()` to set up all handlers.

___

Module: flaskapi_guard/core/responses/
-----------------------------

**Purpose**: Response creation and processing

ErrorResponseFactory
---------------------

Centralized response creation, error handling, and header application.

**Location**: `flaskapi_guard/core/responses/factory.py`

**Key Methods**:

```python
class ErrorResponseFactory:
    def create_error_response(
        self, status_code: int, default_message: str
    ) -> Response:
        """Create standardized error response with custom message."""
        ...

    def create_https_redirect(self, request: Request) -> Response:
        """Create HTTPS redirect response."""
        ...

    def process_response(
        self,
        request: Request,
        response: Response,
        response_time: float,
        route_config: RouteConfig | None,
        process_behavioral_rules: Callable | None = None,
    ) -> Response:
        """Process response with metrics, headers, and behavioral rules."""
        ...
```

**Features**:
- Custom error message support
- Security header application
- CORS header handling
- Metrics collection
- Behavioral rule processing

ResponseContext
----------------

Dependency injection container for response factory.

**Location**: `flaskapi_guard/core/responses/context.py`

___

Module: flaskapi_guard/core/routing/
-------------------------

**Purpose**: Route configuration and decorator resolution

RouteConfigResolver
--------------------

Resolves route-specific security configuration from decorators.

**Location**: `flaskapi_guard/core/routing/resolver.py`

**Key Methods**:

```python
class RouteConfigResolver:
    def get_route_config(self, request: Request) -> RouteConfig | None:
        """Get route-specific security configuration."""
        ...

    def should_bypass_check(
        self, check_name: str, route_config: RouteConfig | None
    ) -> bool:
        """Check if security check should be bypassed."""
        ...

    def get_cloud_providers_to_check(
        self, route_config: RouteConfig | None
    ) -> list[str] | None:
        """Get cloud providers to check (route-specific or global)."""
        ...
```

**Usage**: Resolves decorator configurations for route-level security overrides.

RoutingContext
---------------

Dependency injection container for route resolver.

**Location**: `flaskapi_guard/core/routing/context.py`

___

Module: flaskapi_guard/core/validation/
-----------------------------

**Purpose**: Request validation utilities

RequestValidator
----------------

Provides request validation logic for HTTPS, proxies, time windows, and path exclusions.

**Location**: `flaskapi_guard/core/validation/validator.py`

**Key Methods**:

```python
class RequestValidator:
    def is_request_https(self, request: Request) -> bool:
        """Check if request uses HTTPS."""
        ...

    def is_trusted_proxy(self, client_ip: str) -> bool:
        """Validate if IP is a trusted proxy."""
        ...

    def check_time_window(
        self, time_restrictions: dict[str, str]
    ) -> bool:
        """Validate time window restrictions."""
        ...

    def is_path_excluded(self, path: str) -> bool:
        """Check if path is excluded from security checks."""
        ...
```

ValidationContext
------------------

Dependency injection container for validator.

**Location**: `flaskapi_guard/core/validation/context.py`

___

Module: flaskapi_guard/core/bypass/
--------------------------

**Purpose**: Handle security bypass cases

BypassHandler
-------------

Handles passthrough cases and decorator-based security bypasses.

**Location**: `flaskapi_guard/core/bypass/handler.py`

**Key Methods**:

```python
class BypassHandler:
    def handle_passthrough(
        self, request: Request
    ) -> Response | None:
        """Handle cases that should pass through immediately."""
        ...

    def handle_security_bypass(
        self,
        request: Request,
        route_config: RouteConfig | None,
    ) -> Response | None:
        """Handle decorator-based security bypasses."""
        ...
```

**Features**:
- No client IP detection (passthrough)
- Excluded path handling
- Decorator bypass support
- Early exit optimization

BypassContext
--------------

Dependency injection container for bypass handler.

**Location**: `flaskapi_guard/core/bypass/context.py`

___

Module: flaskapi_guard/core/behavioral/
-----------------------------

**Purpose**: Behavioral rule processing

BehavioralProcessor
--------------------

Processes decorator-based behavioral rules for usage and return monitoring.

**Location**: `flaskapi_guard/core/behavioral/processor.py`

**Key Methods**:

```python
class BehavioralProcessor:
    def process_usage_rules(
        self, request: Request, client_ip: str, route_config: RouteConfig
    ) -> None:
        """Process behavioral usage rules (pre-request)."""
        ...

    def process_return_rules(
        self,
        request: Request,
        response: Response,
        client_ip: str,
        route_config: RouteConfig,
    ) -> None:
        """Process behavioral return rules (post-request)."""
        ...

    def get_endpoint_id(self, request: Request) -> str:
        """Generate unique endpoint identifier."""
        ...
```

BehavioralContext
------------------

Dependency injection container for behavioral processor.

**Location**: `flaskapi_guard/core/behavioral/context.py`

___

Dependency Injection Pattern
----------------------------

All core modules use **Context objects** for clean dependency injection:

```python
# Example: ResponseContext
@dataclass
class ResponseContext:
    config: SecurityConfig
    logger: logging.Logger
    metrics_collector: MetricsCollector
    agent_handler: Any
    guard_decorator: BaseSecurityDecorator | None
```

**Benefits**:
- Explicit dependencies
- Easy testing with mocks
- Prevents tight coupling
- Type-safe dependency passing

___

Adding New Security Checks
--------------------------

To add a custom security check:

1. Create Implementation

**File**: `flaskapi_guard/core/checks/implementations/my_custom_check.py`

```python
from flask import Request, Response, g
from flaskapi_guard.core.checks.base import SecurityCheck

class MyCustomCheck(SecurityCheck):
    """Description of what this check does."""

    check_name = "my_custom_check"

    def __init__(self, extension: "FlaskAPIGuard"):
        self.extension = extension
        self.config = extension.config
        self.logger = extension.logger

    def check(self, request: Request) -> Response | None:
        # Get context from flask.g
        client_ip = g.client_ip
        route_config = g.route_config

        # Your check logic
        if condition_fails:
            self.logger.warning(f"Check failed for {client_ip}")
            return self.create_error_response(
                403, "Custom check failed"
            )

        return None  # Check passed
```

2. Register in Pipeline

**File**: `flaskapi_guard/extension.py` in `_build_security_pipeline()` method

```python
from flaskapi_guard.core.checks.implementations.my_custom_check import MyCustomCheck

def _build_security_pipeline(self) -> None:
    checks = [
        # ... existing checks
        MyCustomCheck(self),  # Add your check
    ]
    self.security_pipeline = SecurityCheckPipeline(checks)
```

3. Export (Optional)

**File**: `flaskapi_guard/core/checks/__init__.py`

```python
from flaskapi_guard.core.checks.implementations.my_custom_check import MyCustomCheck

__all__ = [
    # ... existing exports
    "MyCustomCheck",
]
```

4. Test

```python
import pytest
from flaskapi_guard.core.checks.implementations.my_custom_check import MyCustomCheck

def test_my_custom_check(test_extension, test_request):
    check = MyCustomCheck(test_extension)
    response = check.check(test_request)
    assert response is None  # or assert response.status_code == 403
```

___

Testing Core Modules
--------------------

Each module is independently testable:

```python
# Test a specific check
from flaskapi_guard.core.checks.implementations import IpSecurityCheck

def test_ip_security():
    extension = create_test_extension()
    check = IpSecurityCheck(extension)

    request = create_test_request(client_ip="10.0.0.1")
    response = check.check(request)

    assert response is None  # IP allowed
```

```python
# Test the pipeline
from flaskapi_guard.core.checks import SecurityCheckPipeline

def test_pipeline():
    checks = [Check1(extension), Check2(extension)]
    pipeline = SecurityCheckPipeline(checks)

    response = pipeline.execute(request)
    assert response is None  # All checks passed
```

___

Performance Considerations
--------------------------

Pipeline Optimization
----------------------

- **Early Termination**: Pipeline stops at first blocking check
- **Conditional Checks**: Some checks skip execution based on config
- **Cached Results**: Some checks cache results per request

Modular Benefits
----------------

- **Independent Caching**: Each module can cache independently
- **Targeted Optimization**: Identify and optimize specific bottlenecks
- **Profiling**: Easy to profile individual checks

___

Migration from Monolithic Architecture
--------------------------------------

The modular architecture provides several improvements over a monolithic design:

| Aspect | Monolithic | Modular |
|--------|------------------|---------------|
| **File Size** | Large single file | Small focused modules |
| **Maintainability** | Low | High |
| **Complexity** | High avg | Low avg |
| **Testability** | Hard (coupled) | Easy (isolated) |
| **Extensibility** | Difficult | Simple |

**For Contributors**: All new features should follow the modular pattern.

___

See Also
--------

- [FlaskAPIGuard](security-middleware.md) - Main extension documentation
- [API Overview](overview.md) - Complete API reference
- [Decorators](decorators.md) - Route-level security decorators
