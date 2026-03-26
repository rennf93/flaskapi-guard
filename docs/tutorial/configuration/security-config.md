---

title: Security Configuration - FlaskAPI Guard
description: Complete guide to FlaskAPI Guard's SecurityConfig model and configuration options
keywords: security config, configuration, settings, pydantic model
---

Security Configuration
=====================

FlaskAPI Guard uses Pydantic models for configuration and data structures.

___

SecurityConfig
--------------

The main configuration model for FlaskAPI Guard extension.

```python
class SecurityConfig(BaseModel):
    """
    Main configuration model for FlaskAPI Guard.
    Uses Pydantic v2 BaseModel for validation.
    """
```

Core Security Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `passive_mode` | bool | False | If True, only log without blocking |
| `enable_penetration_detection` | bool | True | Enable penetration attempt detection |
| `enable_ip_banning` | bool | True | Enable IP banning functionality |
| `enable_rate_limiting` | bool | True | Enable rate limiting functionality |
| `enforce_https` | bool | False | Enforce HTTPS connections |
| `auto_ban_threshold` | int | 10 | Number of suspicious requests before auto-ban |
| `auto_ban_duration` | int | 3600 | Auto-ban duration in seconds |
| `exclude_paths` | list[str] | ["/docs", "/redoc", "/openapi.json", "/openapi.yaml", "/favicon.ico", "/static"] | Paths excluded from security checks |

Detection Engine Settings
-------------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `detection_compiler_timeout` | float | 2.0 | Timeout for pattern compilation and execution (seconds, 0.1-10.0) |
| `detection_max_content_length` | int | 10000 | Maximum content length to analyze (1000-100000) |
| `detection_preserve_attack_patterns` | bool | True | Preserve attack patterns during content truncation |
| `detection_semantic_threshold` | float | 0.7 | Minimum threat score for semantic detection (0.0-1.0) |
| `detection_anomaly_threshold` | float | 3.0 | Standard deviations to consider performance anomaly (1.0-10.0) |
| `detection_slow_pattern_threshold` | float | 0.1 | Execution time to consider pattern slow in seconds (0.01-1.0) |
| `detection_monitor_history_size` | int | 1000 | Number of performance metrics to keep in history (100-10000) |
| `detection_max_tracked_patterns` | int | 1000 | Maximum patterns to track for performance (100-5000) |

IP Management Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `whitelist` | list[str] \| None | None | Allowed IP addresses or CIDR ranges |
| `blacklist` | list[str] | [] | Blocked IP addresses or CIDR ranges |
| `whitelist_countries` | list[str] | [] | Country codes that are always allowed |
| `blocked_countries` | list[str] | [] | Country codes that are always blocked |
| `blocked_user_agents` | list[str] | [] | Blocked user agent patterns |
| `geo_ip_handler` | GeoIPHandler \| None | None | Handler for IP geolocation lookups |

Proxy & Trust Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `trusted_proxies` | list[str] | [] | Trusted proxy IPs or CIDR ranges for X-Forwarded-For |
| `trusted_proxy_depth` | int | 1 | How many proxies to expect in the X-Forwarded-For chain |
| `trust_x_forwarded_proto` | bool | False | Trust X-Forwarded-Proto header for HTTPS detection |

Redis Settings
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_redis` | bool | True | Enable Redis for distributed state management |
| `redis_url` | str \| None | "redis://localhost:6379" | Redis connection URL |
| `redis_prefix` | str | "guard_core:" | Prefix for Redis keys to avoid collisions |

Rate Limiting Settings
----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `rate_limit` | int | 10 | Maximum requests per rate_limit_window |
| `rate_limit_window` | int | 60 | Rate limiting time window in seconds |
| `endpoint_rate_limits` | dict[str, tuple[int, int]] | {} | Per-endpoint rate limits {endpoint: (requests, window)} |

Agent Settings
--------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_agent` | bool | False | Enable Guard Agent telemetry and monitoring |
| `agent_api_key` | str \| None | None | API key for agent authentication |
| `agent_endpoint` | str | "https://api.fastapi-guard.com" | Guard Agent SaaS platform endpoint |
| `agent_project_id` | str \| None | None | Project ID for organizing telemetry data |
| `agent_buffer_size` | int | 100 | Number of events to buffer before auto-flush |
| `agent_flush_interval` | int | 30 | Interval in seconds between automatic buffer flushes |
| `agent_enable_events` | bool | True | Send security events to SaaS platform |
| `agent_enable_metrics` | bool | True | Send performance metrics to SaaS platform |
| `agent_timeout` | int | 30 | Timeout in seconds for agent HTTP requests |
| `agent_retry_attempts` | int | 3 | Number of retry attempts for failed requests |

Cloud Provider Settings
-----------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `block_cloud_providers` | set[str] \| None | None | Cloud providers to block (valid: "AWS", "GCP", "Azure") |
| `cloud_ip_refresh_interval` | int | 3600 | Interval in seconds between cloud IP range refreshes (60-86400) |
| `ipinfo_token` | str \| None | None | IPInfo API token for geolocation (**deprecated** — use `geo_ip_handler` instead) |
| `ipinfo_db_path` | Path \| None | Path("data/ipinfo/country_asn.mmdb") | Path to IPInfo database (**deprecated** — use `geo_ip_handler` instead) |

Security Headers Settings
------------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `security_headers` | dict[str, Any] \| None | See below | Security headers configuration |

Default security_headers configuration:

```python
{
    "enabled": True,
    "hsts": {
        "max_age": 31536000,
        "include_subdomains": True,
        "preload": False
    },
    "csp": None,
    "frame_options": "SAMEORIGIN",
    "content_type_options": "nosniff",
    "xss_protection": "1; mode=block",
    "referrer_policy": "strict-origin-when-cross-origin",
    "permissions_policy": "geolocation=(), microphone=(), camera=()",
    "custom": None
}
```

The following additional security headers are now included by default:

- `X-Permitted-Cross-Domain-Policies: none`
- `X-Download-Options: noopen`
- `Cross-Origin-Embedder-Policy: require-corp`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`

Security Headers Sub-fields
----------------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | True | Enable security headers |
| `hsts.max_age` | int | 31536000 | HSTS max-age in seconds |
| `hsts.include_subdomains` | bool | True | Include subdomains in HSTS |
| `hsts.preload` | bool | False | Enable HSTS preload |
| `csp` | dict[str, list[str]] | None | Content Security Policy directives |
| `frame_options` | str | "SAMEORIGIN" | X-Frame-Options value (DENY, SAMEORIGIN) |
| `content_type_options` | str | "nosniff" | X-Content-Type-Options value |
| `xss_protection` | str | "1; mode=block" | X-XSS-Protection value |
| `referrer_policy` | str | "strict-origin-when-cross-origin" | Referrer-Policy value |
| `permissions_policy` | str | See default | Permissions-Policy value |
| `custom` | dict[str, str] | None | Additional custom headers |

CORS Settings
-------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_cors` | bool | False | Enable CORS handling |
| `cors_allow_origins` | list[str] | ["*"] | Allowed origins |
| `cors_allow_methods` | list[str] | ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] | Allowed methods |
| `cors_allow_headers` | list[str] | ["*"] | Allowed headers |
| `cors_allow_credentials` | bool | False | Allow credentials |
| `cors_expose_headers` | list[str] | [] | Headers exposed in CORS responses |
| `cors_max_age` | int | 600 | Preflight cache duration |

Logging Settings
----------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `custom_log_file` | str \| None | None | Custom log file path |
| `log_format` | Literal["text", "json"] | "text" | Log output format |
| `log_suspicious_level` | Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] \| None | "WARNING" | Log level for suspicious activity |
| `log_request_level` | Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] \| None | None | Log level for requests |
| `custom_error_responses` | dict[int, str] | {} | Custom error messages for specific HTTP status codes |

Custom Hooks
------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `custom_request_check` | Callable[[Request], Response \| None] \| None | None | Custom request validation function (sync) |
| `custom_response_modifier` | Callable[[Response], Response] \| None | None | Custom response modification function (sync) |

Dynamic Rules & Emergency Mode
-------------------------------

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enable_dynamic_rules` | bool | False | Enable dynamic rule updates from SaaS platform |
| `dynamic_rule_interval` | int | 300 | Interval in seconds between dynamic rule updates |
| `emergency_mode` | bool | False | Emergency lockdown mode |
| `emergency_whitelist` | list[str] | [] | IPs allowed during emergency mode |

Usage Example
-------------

```python
from flaskapi_guard import SecurityConfig

config = SecurityConfig(
    enable_penetration_detection=True,
    auto_ban_threshold=10,
    detection_semantic_threshold=0.7,
)

config = SecurityConfig(
    passive_mode=False,

    enable_penetration_detection=True,
    detection_compiler_timeout=2.0,
    detection_max_content_length=10000,
    detection_preserve_attack_patterns=True,
    detection_semantic_threshold=0.7,
    detection_anomaly_threshold=3.0,
    detection_slow_pattern_threshold=0.1,
    detection_monitor_history_size=1000,
    detection_max_tracked_patterns=1000,

    security_headers={
        "enabled": True,
        "hsts": {
            "max_age": 31536000,
            "include_subdomains": True,
            "preload": False
        },
        "csp": {
            "default-src": ["'self'"],
            "script-src": ["'self'", "https://cdn.example.com"],
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
        "referrer_policy": "no-referrer",
        "permissions_policy": "geolocation=(), microphone=(), camera=()",
        "custom": {
            "X-Custom-Header": "CustomValue"
        }
    },

    enable_redis=True,
    redis_url="redis://localhost:6379",

    enable_agent=True,
    agent_api_key="your-api-key",

    custom_log_file="security.log",
    log_format="json",

    cloud_ip_refresh_interval=1800,
)
```

___

Configuration Validation
------------------------

The SecurityConfig model validates settings on initialization:

```python
try:
    config = SecurityConfig(
        detection_compiler_timeout=0.05
    )
except ValidationError as e:
    print(f"Configuration error: {e}")

config = SecurityConfig(
    detection_compiler_timeout=2.0,
    detection_semantic_threshold=0.7,
    detection_anomaly_threshold=3.0,
    auto_ban_threshold=10,
    auto_ban_duration=3600,
)
```

___

Model Serialization
-------------------

All models support standard Pydantic v2 serialization:

```python
config_dict = config.model_dump(exclude_unset=True)
config_json = config.model_dump_json(indent=2)

config = SecurityConfig.model_validate(config_dict)
config = SecurityConfig.model_validate_json(config_json)

schema = SecurityConfig.model_json_schema()
```

___

Custom Validators
-----------------

The models include custom validators for complex fields:

```python
@field_validator("whitelist", "blacklist")
def validate_ip_lists(cls, v):
    if v is None:
        return None
    for entry in v:
        if "/" in entry:
            ip_network(entry, strict=False)
        else:
            ip_address(entry)
    return v

@field_validator("block_cloud_providers", mode="before")
def validate_cloud_providers(cls, v):
    valid_providers = {"AWS", "GCP", "Azure"}
    if v is None:
        return set()
    return {p for p in v if p in valid_providers}
```

___

See Also
--------

- [Security Extension](../../api/security-middleware.md) - Using SecurityConfig with the extension
- [Detection Engine Configuration](../security/detection-engine/configuration.md) - Detailed configuration guide
- [Logging Configuration](logging.md) - Logging configuration
- [CORS Configuration](cors.md) - CORS configuration
