<p align="center">
    <a href="https://rennf93.github.io/flaskapi-guard/latest/">
        <img src="https://rennf93.github.io/flaskapi-guard/latest/assets/logo.svg" alt="FlaskAPI Guard">
    </a>
</p>

---

<p align="center">
    <strong>flaskapi-guard is a security library for Flask that provides an extension to control IPs, log requests, detect penetration attempts and more. It integrates seamlessly with Flask to offer robust protection against various security threats.</strong>
</p>

<p align="center">
    <a href="https://badge.fury.io/py/flaskapi-guard">
        <img src="https://badge.fury.io/py/flaskapi-guard.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4" alt="PyPiVersion">
    </a>
    <a href="https://github.com/rennf93/flaskapi-guard/actions/workflows/release.yml">
        <img src="https://github.com/rennf93/flaskapi-guard/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/rennf93/flaskapi-guard/actions/workflows/ci.yml">
        <img src="https://github.com/rennf93/flaskapi-guard/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/rennf93/flaskapi-guard/actions/workflows/code-ql.yml">
        <img src="https://github.com/rennf93/flaskapi-guard/actions/workflows/code-ql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/rennf93/flaskapi-guard/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/rennf93/flaskapi-guard/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/rennf93/flaskapi-guard/actions/workflows/docs.yml">
        <img src="https://github.com/rennf93/flaskapi-guard/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/rennf93/flaskapi-guard?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/Python-3776AB.svg?style=flat&amp;logo=Python&amp;logoColor=white" alt="Python">
    <img src="https://img.shields.io/badge/Flask-000000.svg?style=flat&amp;logo=Flask&amp;logoColor=white" alt="Flask">
    <img src="https://img.shields.io/badge/Redis-FF4438.svg?style=flat&amp;logo=Redis&amp;logoColor=white" alt="Redis">
    <a href="https://pepy.tech/project/flaskapi-guard">
        <img src="https://pepy.tech/badge/flaskapi-guard" alt="Downloads">
    </a>
</p>

---

Documentation
=============

📚 **[Documentation](https://rennf93.github.io/flaskapi-guard)** - Full technical documentation and deep dive into its inner workings.

___

Features
--------

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Limit the number of requests from a single IP.
- **Automatic IP Banning**: Automatically ban IPs after a certain number of suspicious requests.
- **Penetration Attempt Detection**: Detect and log potential penetration attempts.
- **HTTP Security Headers**: Comprehensive security headers management (CSP, HSTS, X-Frame-Options, etc.)
- **Custom Logging**: Log security events to a custom file.
- **CORS Configuration**: Configure CORS settings for your Flask application.
- **Cloud Provider IP Blocking**: Block requests from cloud provider IPs (AWS, GCP, Azure).
- **IP Geolocation**: Use a service like IPInfo.io API to determine the country of an IP address.
- **Distributed State Management**: (Optional) Redis integration for shared security state across instances.
- **Flexible Storage**: Redis-enabled distributed storage or in-memory storage for single instance deployments.
- **Route-Level Security Decorators**: Fine-grained security controls per route.
- **Behavioral Analysis**: Endpoint usage tracking and anomaly detection.
- **Time-Based Access Control**: Restrict endpoint access to specific time windows.
- **Emergency Mode**: Block all traffic except whitelisted IPs.

___

Installation
------------

To install `flaskapi-guard`, use pip:

```bash
pip install flaskapi-guard
```

___

Usage
-----------

Basic Setup
-----------

To use `flaskapi-guard`, you need to configure the extension in your Flask application. Here's a basic example:

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager

app = Flask(__name__)

# Define your security configuration
config = SecurityConfig(
    ipinfo_token="your_ipinfo_token_here",  # Optional: IPInfo token required for IP geolocation
    ipinfo_db_path="custom/ipinfo.db",  # Optional custom database path
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
    blocked_countries=["AR", "IT"],
    blocked_user_agents=["curl", "wget"],
    auto_ban_threshold=5,
    auto_ban_duration=86400,
    custom_log_file="security.log",
    rate_limit=100,
    enforce_https=True,
    enable_cors=True,
    cors_allow_origins=["*"],
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Custom-Header"],
    cors_max_age=600,
    block_cloud_providers={"AWS", "GCP", "Azure"},
)

# Add the security extension
FlaskAPIGuard(app, config=config)

@app.route("/")
def read_root():
    return {"message": "Hello, World!"}
```

You can also use the **app factory pattern**:

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig

guard = FlaskAPIGuard()

def create_app():
    app = Flask(__name__)
    config = SecurityConfig(
        rate_limit=100,
        enable_cors=True,
    )
    guard.init_app(app, config=config)
    return app
```

IP Whitelisting and Blacklisting
---------------------------------

You can control access based on IP addresses using the `whitelist` and `blacklist` options in the `SecurityConfig`.

```python
config = SecurityConfig(
    whitelist=["192.168.1.1", "2001:db8::1"],
    blacklist=["10.0.0.1", "2001:db8::2"],
)
```

User Agent Filtering
--------------------

Block requests from specific user agents by adding patterns to the `blocked_user_agents` list.

```python
config = SecurityConfig(
    blocked_user_agents=["curl", "wget"],
)
```

Rate Limiting
-------------

Limit the number of requests from a single IP using the `rate_limit` option.

```python
config = SecurityConfig(
    rate_limit=100,  # Maximum 100 requests per minute
)
```

Automatic IP Banning
--------------------

Automatically ban IPs after a certain number of suspicious requests using the `auto_ban_threshold` and `auto_ban_duration` options.

```python
config = SecurityConfig(
    auto_ban_threshold=5,  # Ban IP after 5 suspicious requests
    auto_ban_duration=86400,  # Ban duration in seconds (1 day)
)
```

Penetration Attempt Detection
-----------------------------

Enable penetration attempt detection using the `enable_penetration_detection` option.

```python
config = SecurityConfig(
    enable_penetration_detection=True,  # True by default
)
```

Optional: Enable `passive mode` to log suspicious activity without blocking requests.

```python
config = SecurityConfig(
    passive_mode=True,  # False by default
)
```

Custom Penetration Detection
----------------------------

Detect and log potential penetration attempts using the `detect_penetration_attempt` function.

```python
from flask import request, jsonify
from flaskapi_guard.utils import detect_penetration_attempt

@app.route("/submit", methods=["POST"])
def submit_data():
    is_suspicious, trigger_info = detect_penetration_attempt(request)
    if is_suspicious:
        return jsonify(
            {"error": f"Suspicious activity detected: {trigger_info}"}
        ), 400
    return jsonify({"message": "Data submitted successfully"})
```

Custom Logging
--------------

Log security events with console output (always enabled) and optional file logging:

```python
config = SecurityConfig(
    custom_log_file="security.log",  # Optional: adds file logging
    # custom_log_file=None,  # Default: console output only
)
```

**Note:** Console output is always enabled for visibility. File logging is only activated when `custom_log_file` is provided.

HTTP Security Headers
---------------------

Configure comprehensive security headers following OWASP best practices:

```python
config = SecurityConfig(
    security_headers={
        "enabled": True,
        "hsts": {
            "max_age": 31536000,  # 1 year
            "include_subdomains": True,
            "preload": False
        },
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://trusted.cdn.com"],
            "style-src": ["'self'", "'unsafe-inline'"],
            "img-src": ["'self'", "data:", "https:"],
            "connect-src": ["'self'", "https://api.example.com"],
            "frame-ancestors": ["'none'"],
            "base-uri": ["'self'"],
            "form-action": ["'self'"]
        },
        "frame_options": "DENY",
        "content_type_options": "nosniff",
        "xss_protection": "1; mode=block",
        "referrer_policy": "strict-origin-when-cross-origin",
        "permissions_policy": "geolocation=(), microphone=(), camera=()",
        "custom": {
            "X-Custom-Header": "CustomValue"
        }
    }
)
```

Key security headers supported:
- **Content Security Policy (CSP)**: Prevent XSS attacks by controlling resource loading
- **HTTP Strict Transport Security (HSTS)**: Force HTTPS connections
- **X-Frame-Options**: Prevent clickjacking attacks
- **X-Content-Type-Options**: Prevent MIME type sniffing
- **X-XSS-Protection**: Enable browser XSS filtering
- **Referrer-Policy**: Control referrer information
- **Permissions-Policy**: Restrict browser features
- **Cross-Origin Policies**: Control cross-origin resource access and embedding
- **Header Injection Prevention**: Automatic validation against injection attacks
- **CORS Security**: Secure wildcard and credentials handling

CORS Configuration
------------------

Configure CORS settings for your Flask application using the `enable_cors` and related options.

```python
config = SecurityConfig(
    enable_cors=True,
    cors_allow_origins=["*"],
    cors_allow_methods=["GET", "POST"],
    cors_allow_headers=["*"],
    cors_allow_credentials=True,
    cors_expose_headers=["X-Custom-Header"],
    cors_max_age=600,
)
```

Cloud Provider IP Blocking
---------------------------

Block requests from cloud provider IPs (AWS, GCP, Azure) using the `block_cloud_providers` option.

```python
config = SecurityConfig(
    block_cloud_providers={"AWS", "GCP", "Azure"},
)
```

IP Geolocation and Country Blocking
------------------------------------

If you want to use `flaskapi-guard`'s built-in country filtering features, you'll need to obtain an IPInfo token:

1. Visit [IPInfo's website](https://ipinfo.io/signup) to create a free account
2. After signing up, you'll receive an API token
3. The free tier includes:
   - Up to 50,000 requests per month
   - Access to IP to Country database
   - Daily database updates
   - IPv4 & IPv6 support

Note: This is only required if you use country filtering (`blocked_countries`, `whitelist_countries`). You can also provide your own handler that uses any other service.

___

Route-Level Security with Decorators
------------------------------------

FlaskAPI Guard provides powerful decorators that allow you to apply security controls to individual routes, giving you fine-grained control over your API endpoints.

. Basic Decorator Usage
--------------------

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig, SecurityDecorator

app = Flask(__name__)
config = SecurityConfig()

# Create decorator instance
guard_deco = SecurityDecorator(config)

# Initialize extension and connect decorator handler
guard = FlaskAPIGuard(app, config=config)
guard.set_decorator_handler(guard_deco)

# Apply decorators to specific routes
@app.route("/api/public")
def public_endpoint():
    return {"data": "public"}

@app.route("/api/limited")
@guard_deco.rate_limit(requests=10, window=300)  # 10 requests per 5 minutes
def limited_endpoint():
    return {"data": "limited"}

@app.route("/api/restricted")
@guard_deco.require_ip(whitelist=["192.168.1.0/24"])
@guard_deco.block_countries(["CN", "RU"])
def restricted_endpoint():
    return {"data": "restricted"}
```

. Available Decorators
-------------------

Access Control
- `@guard_deco.require_ip(whitelist=[], blacklist=[])` - IP address filtering
- `@guard_deco.block_countries(["CN", "RU"])` - Block specific countries
- `@guard_deco.allow_countries(["US", "CA"])` - Allow only specific countries
- `@guard_deco.block_clouds(["AWS", "GCP"])` - Block cloud provider IPs

Rate Limiting
- `@guard_deco.rate_limit(requests=10, window=60)` - Basic rate limiting
- `@guard_deco.geo_rate_limit(limits={"US": 100, "default": 50})` - Geographic rate limiting

Authentication & Headers
- `@guard_deco.require_https()` - Force HTTPS
- `@guard_deco.require_auth(type="bearer")` - Require authentication
- `@guard_deco.api_key_auth(header_name="X-API-Key")` - API key authentication
- `@guard_deco.require_headers({"X-Custom": "required"})` - Require specific headers

Content Filtering
- `@guard_deco.block_user_agents(["curl", "wget"])` - Block user agent patterns
- `@guard_deco.content_type_filter(["application/json"])` - Filter content types
- `@guard_deco.max_request_size(1048576)` - Limit request size (1MB)
- `@guard_deco.require_referrer(["myapp.com"])` - Require specific referrers

Behavioral Analysis
- `@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")` - Monitor endpoint usage
- `@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="alert")` - Monitor return patterns
- `@guard_deco.suspicious_frequency(max_frequency=0.1, window=300, action="log")` - Detect suspicious frequency

Advanced Controls
- `@guard_deco.time_window("09:00", "17:00", "UTC")` - Time-based access control
- `@guard_deco.honeypot_detection(trap_fields=["hidden_field"])` - Detect bots using honeypot fields
- `@guard_deco.bypass(checks=["rate_limit"])` - Bypass specific security checks

. Complex Route Protection
-----------------------

Combine multiple decorators for comprehensive protection:

```python
@app.route("/api/admin/sensitive", methods=["POST"])
@guard_deco.require_https()                        # Security requirement
@guard_deco.require_auth(type="bearer")            # Authentication
@guard_deco.require_ip(whitelist=["10.0.0.0/8"])   # Access control
@guard_deco.rate_limit(requests=5, window=3600)    # Rate limiting
@guard_deco.suspicious_detection(enabled=True)     # Monitoring
def admin_endpoint():
    return {"status": "admin action"}

@app.route("/api/rewards")
@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="ban")
@guard_deco.block_countries(["CN", "RU", "KP"])
def rewards_endpoint():
    # This endpoint is protected against:
    # - Excessive usage (>50 calls/hour results in ban)
    # - Suspicious return patterns (>3 rare items/day results in ban)
    # - Geographic restrictions
    return {"reward": "rare_item", "value": 1000}
```

. Decorator Configuration Priority
-------------------------------

Security settings are applied in the following priority order:

1. Decorator Settings (highest priority)
2. Global Extension Settings
3. Default Settings (lowest priority)

This allows routes to override global settings while maintaining sensible defaults.

___

Advanced Usage
--------------

. Secure Proxy Configuration
---------------------------

Configure trusted proxies to securely handle X-Forwarded-For headers:

```python
config = SecurityConfig(
    trusted_proxies=["10.0.0.1", "192.168.1.0/24"],  # List of trusted proxy IPs or CIDR ranges
    trusted_proxy_depth=1,                           # How many proxies to expect in chain
    trust_x_forwarded_proto=True,                    # Whether to trust X-Forwarded-Proto for HTTPS detection (default: True)
)
```

When `trusted_proxies` is configured, FlaskAPI Guard will:
1. Only trust X-Forwarded-For headers from these IPs
2. Extract the appropriate client IP based on proxy depth
3. Prevent IP spoofing attacks through header manipulation

. Custom Geolocation Handler
---------------------------

The library implements a handler that uses IPInfo's [IP to Country database](https://ipinfo.io/products/free-ip-database), which provides:

- Full accuracy IP to country mapping
- Daily updates
- Support for both IPv4 and IPv6
- Country and continent information
- ASN details

To use the geolocation feature with this handler:

```python
from flaskapi_guard.protocols.geo_ip_protocol import GeoIPHandler

config = SecurityConfig(
    geo_ip_handler=GeoIPHandler,
    blocked_countries=["AR", "IT"],   # Block specific countries using ISO 3166-1 alpha-2 codes
    whitelist_countries=["US", "CA"]  # Optional: Only allow specific countries
)
```

The database is automatically downloaded and cached locally when the extension starts, if required, and it's updated daily to ensure accuracy.

You can also use a service other than IPInfo, as long as you implement the same protocol:

```python
# Implement the required methods of flaskapi_guard.protocols.geo_ip_protocol.GeoIPHandler protocol

class GeoIPHandler:
    """
    Your custom class.
    """

    @property
    def is_initialized(self) -> bool:
        # your implementation
        ...

    def initialize(self) -> None:
        # your implementation
        ...

    def initialize_redis(self, redis_handler: "RedisManager") -> None:
        # your implementation
        ...

    def get_country(self, ip: str) -> str | None:
        # your implementation
        ...


config = SecurityConfig(
    geo_ip_handler=GeoIPHandler,
    blocked_countries=["AR", "IT"],  # Block specific countries using ISO 3166-1 alpha-2 codes
    whitelist_countries=["US", "CA"]  # Optional: Only allow specific countries
)
```

. Custom Request Check
--------------------

You can define a custom function to perform additional checks on the request using the `custom_request_check` option.

```python
from flask import Response
from typing import Optional

def custom_check(req) -> Optional[Response]:
    if "X-Custom-Header" not in req.headers:
        return Response("Missing custom header", status=400)
    return None

config = SecurityConfig(
    custom_request_check=custom_check,
)
```

. Custom Response Modifier
------------------------

You can define a custom function to modify the response before it's sent using the `custom_response_modifier` option.

```python
from flask import Response, jsonify

def custom_modifier(response: Response) -> Response:
    # Add custom headers
    response.headers["X-Custom-Header"] = "CustomValue"

    # Convert text responses to JSON responses
    if response.status_code >= 400 and response.content_type != "application/json":
        try:
            content = response.get_data(as_text=True)
            json_response = jsonify({"detail": content})
            json_response.status_code = response.status_code
            return json_response
        except Exception:
            pass

    return response

config = SecurityConfig(
    custom_response_modifier=custom_modifier,
)
```

The example above shows how to:
1. Add custom headers to all responses
2. Convert plain text error responses to JSON format with a "detail" field

___

Redis Configuration
-------------------

Enable distributed state management across multiple instances:

```python
config = SecurityConfig(
    enable_redis=True,
    redis_url="redis://prod-redis:6379/1",
    redis_prefix="myapp:security:",
)
```

The Redis integration provides:
- Atomic increment operations for rate limiting
- Distributed IP ban tracking
- Cloud provider IP range caching
- Pattern storage for penetration detection

___

Emergency Mode
--------------

Block all incoming traffic except from explicitly whitelisted IPs. Useful during active attacks or maintenance windows:

```python
config = SecurityConfig(
    emergency_mode=True,
    emergency_whitelist=["10.0.0.1", "192.168.1.0/24"],
)
```

___

Behavioral Analysis
-------------------

FlaskAPI Guard includes a behavioral analysis engine for detecting anomalous usage patterns. This works both at the global level and per-route via decorators:

```python
from flaskapi_guard import SecurityConfig, BehaviorRule

config = SecurityConfig(
    # Global behavioral rules can be defined in config
)

# Per-route behavioral monitoring via decorators
@app.route("/api/rewards")
@guard_deco.usage_monitor(max_calls=50, window=3600, action="ban")
@guard_deco.return_monitor("rare_item", max_occurrences=3, window=86400, action="ban")
def rewards_endpoint():
    return {"reward": "rare_item", "value": 1000}
```

Behavioral actions include:
- `"log"` - Log the anomaly
- `"alert"` - Generate an alert event
- `"ban"` - Automatically ban the offending IP

___

Detailed Configuration Options
------------------------------

. SecurityConfig
--------------

The `SecurityConfig` class defines the structure for security configuration, including IP whitelists and blacklists, blocked countries, blocked user agents, rate limiting, automatic IP banning, HTTPS enforcement, custom hooks, CORS settings, and blocking of cloud provider IPs.

. Attributes
----------

- **geo_ip_handler**: ```GeoIPHandler``` - Protocol that allows for IP geolocation functionality.
- **enable_redis**: ```bool``` - Enable Redis for distributed state (default: True). When disabled, uses in-memory storage.
- **redis_url**: ```str | None``` - Redis connection URL (default: "redis://localhost:6379").
- **redis_prefix**: ```str``` - Prefix for Redis keys (default: "flaskapi_guard:").
- **trusted_proxies**: ```list[str] | None``` - List of trusted proxy IPs or CIDR ranges.
- **trusted_proxy_depth**: ```int``` - How many proxies to expect in chain.
- **trust_x_forwarded_proto**: ```bool``` - Whether to trust X-Forwarded-Proto for HTTPS detection.
- **whitelist**: ```list[str] | None``` - A list of IP addresses or ranges that are always allowed. If set to None, no whitelist is applied.
- **blacklist**: ```list[str]``` - A list of IP addresses or ranges that are always blocked.
- **blocked_countries**: ```list[str]``` - A list of country codes whose IP addresses should be blocked.
- **blocked_user_agents**: ```list[str]``` - A list of user agent strings or patterns that should be blocked.
- **auto_ban_threshold**: ```int``` - The threshold for auto-banning an IP address after a certain number of requests.
- **auto_ban_duration**: ```int``` - The duration in seconds for which an IP address should be banned after reaching the auto-ban threshold.
- **custom_log_file**: ```str | None``` - Optional path to a log file. When provided, enables file logging in addition to console output (which is always enabled). Default: `None` (console only).
- **custom_error_responses**: ```dict[int, str]``` - A dictionary of custom error responses for specific HTTP status codes.
- **rate_limit**: ```int``` - The maximum number of requests allowed per minute from a single IP.
- **rate_limit_window**: ```int``` - The time window in seconds for rate limiting (default: 60).
- **enforce_https**: ```bool``` - Whether to enforce HTTPS connections. If True, all HTTP requests will be redirected to HTTPS.
- **custom_request_check**: ```Callable[[Request], Response | None] | None``` - A custom synchronous function to perform additional checks on the request. If it returns a Response, that response will be sent instead of continuing the extension chain.
- **custom_response_modifier**: ```Callable[[Response], Response] | None``` - A custom synchronous function to modify the response before it's sent.
- **enable_cors**: ```bool``` - Whether to enable CORS.
- **cors_allow_origins**: ```list[str]``` - A list of origins that are allowed to access the API.
- **cors_allow_methods**: ```list[str]``` - A list of methods that are allowed to access the API.
- **cors_allow_headers**: ```list[str]``` - A list of headers that are allowed in CORS requests.
- **cors_allow_credentials**: ```bool``` - Whether to allow credentials in CORS requests.
- **cors_expose_headers**: ```list[str]``` - A list of headers that are exposed in CORS responses.
- **cors_max_age**: ```int``` - The maximum age in seconds that the results of a preflight request can be cached.
- **block_cloud_providers**: ```set[str]``` - Case-sensitive cloud provider names to block. Valid values: 'AWS', 'GCP', 'Azure'. Invalid entries are silently ignored.
- **passive_mode**: ```bool``` - When enabled, logs suspicious activity without blocking requests (default: False).
- **enable_ip_banning**: ```bool``` - Enable or disable IP banning functionality (default: True).
- **enable_rate_limiting**: ```bool``` - Enable or disable rate limiting (default: True).
- **enable_penetration_detection**: ```bool``` - Enable or disable penetration attempt detection (default: True).
- **emergency_mode**: ```bool``` - Block all traffic except whitelisted IPs (default: False).
- **emergency_whitelist**: ```list[str]``` - IPs allowed during emergency mode.
- **exclude_paths**: ```list[str]``` - Paths excluded from security checks (default: ["/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static"]).
- **security_headers**: ```dict[str, Any] | None``` - Security headers configuration following OWASP best practices.
- **endpoint_rate_limits**: ```dict[str, tuple[int, int]]``` - Per-endpoint rate limits as {endpoint: (limit, window)}.
- **log_suspicious_level**: ```Literal["INFO","DEBUG","WARNING","ERROR","CRITICAL"] | None``` - Log level for suspicious activity (default: "WARNING").
- **log_request_level**: ```Literal["INFO","DEBUG","WARNING","ERROR","CRITICAL"] | None``` - Log level for request logging (default: None).

___

Detection Engine
----------------

FlaskAPI Guard includes a comprehensive detection engine for identifying penetration attempts. It uses pattern matching, semantic analysis, and anomaly detection to catch a wide range of attack vectors.

### Attack Categories Detected

| Category | Examples |
|----------|----------|
| **XSS** | Script tags, event handlers, JavaScript protocol, cookie manipulation |
| **SQL Injection** | UNION queries, logic-based (OR/AND), time-based (SLEEP/BENCHMARK), file ops |
| **Command Injection** | Shell commands, command substitution/chaining, PHP functions |
| **Path Traversal** | `../` sequences, `/etc/passwd`, `/proc/self/environ`, Windows system files |
| **File Inclusion** | `php://`, `data://`, `file://`, `zip://`, `expect://` protocols |
| **LDAP Injection** | Wildcard patterns, attribute matching, logic ops |
| **XML Injection** | XXE, CDATA sections, XML declarations |
| **SSRF** | localhost, `127.0.0.1`, `169.254.*`, private ranges |
| **Code Injection** | Python `eval`/`exec`/`__import__`, obfuscation, high-entropy payloads |

### Detection Configuration

| Config Field | Default | Range | Purpose |
|-------------|---------|-------|---------|
| `detection_compiler_timeout` | `2.0` | 0.1-10.0 | Pattern compilation timeout (seconds) |
| `detection_max_content_length` | `10000` | 1000-100000 | Max content length to analyze |
| `detection_preserve_attack_patterns` | `True` | - | Preserve attack signatures during preprocessing |
| `detection_semantic_threshold` | `0.7` | 0.0-1.0 | Semantic analysis confidence threshold |
| `detection_anomaly_threshold` | `3.0` | 1.0-10.0 | Anomaly detection threshold (std devs) |
| `detection_slow_pattern_threshold` | `0.1` | 0.01-1.0 | Slow pattern detection threshold (seconds) |
| `detection_monitor_history_size` | `1000` | 100-10000 | Performance monitor history size |
| `detection_max_tracked_patterns` | `1000` | 100-5000 | Max tracked patterns |

___

Key Differences from FastAPI Guard
-----------------------------------

FlaskAPI Guard is a direct port of [FastAPI Guard](https://github.com/rennf93/fastapi-guard) to the Flask/WSGI ecosystem. The security logic is identical, but adapted for Flask's synchronous model:

| Aspect | FastAPI Guard | FlaskAPI Guard |
|--------|--------------|----------------|
| **Entry point** | `SecurityMiddleware` (ASGI middleware) | `FlaskAPIGuard` (Flask extension) |
| **Hook mechanism** | ASGI `dispatch(request, call_next)` | `before_request` / `after_request` |
| **Execution model** | `async`/`await` throughout | Fully synchronous |
| **Server model** | ASGI (uvicorn) | WSGI (gunicorn, waitress) |
| **Package name** | `guard` | `flaskapi_guard` |
| **Request state** | `request.state` | `flask.g` |
| **Redis client** | `redis.asyncio.Redis` | `redis.Redis` (sync) |
| **HTTP client** | `httpx.AsyncClient` | `httpx.Client` (sync) |
| **Request object** | `starlette.requests.Request` | `flask.request` (Werkzeug) |
| **Response object** | `starlette.responses.Response` | `flask.Response` (Werkzeug) |
| **IP extraction** | `request.client.host` | `request.remote_addr` / `request.access_route` |
| **Custom callables** | `async def check(request) -> Response \| None` | `def check(request) -> Response \| None` |

___

Contributing
------------

Contributions are welcome! Please open an issue or submit a pull request on GitHub.

___

License
-------

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

___

Author
------

Renzo Franceschini - [rennf93@users.noreply.github.com](mailto:rennf93@users.noreply.github.com) .

___

Acknowledgements
----------------

- [Flask](https://flask.palletsprojects.com/)
- [Werkzeug](https://werkzeug.palletsprojects.com/)
- [FastAPI Guard](https://github.com/rennf93/fastapi-guard)
- [IPInfo](https://ipinfo.io/)
- [cachetools](https://cachetools.readthedocs.io/)
- [Redis](https://redis.io/)
- [gunicorn](https://gunicorn.org/)
- [Pydantic](https://docs.pydantic.dev/)
