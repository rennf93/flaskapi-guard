---

title: FlaskAPI Guard - Security Extension for Flask
description: Comprehensive security library for Flask applications providing IP control, rate limiting, request logging, and penetration detection
keywords: flask, security, extension, python, ip control, rate limiting, penetration detection, cybersecurity, wsgi

---

# FlaskAPI Guard

[![PyPI version](https://badge.fury.io/py/flaskapi-guard.svg?cache=none&icon=si%3Apython&icon_color=%23008cb4)](https://badge.fury.io/py/flaskapi-guard)
[![Release](https://github.com/rennf93/flaskapi-guard/actions/workflows/release.yml/badge.svg)](https://github.com/rennf93/flaskapi-guard/actions/workflows/release.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/rennf93/flaskapi-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/rennf93/flaskapi-guard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/rennf93/flaskapi-guard/actions/workflows/code-ql.yml/badge.svg)](https://github.com/rennf93/flaskapi-guard/actions/workflows/code-ql.yml)

`flaskapi-guard` is a comprehensive security library for Flask applications, providing an extension to control IPs, log requests, and detect penetration attempts. It integrates seamlessly with Flask to offer robust protection against various security threats, ensuring your application remains secure and reliable. FlaskAPI Guard is a direct port of [FastAPI Guard](https://github.com/rennf93/fastapi-guard) to the Flask/WSGI ecosystem.

___

## Quick Start

### Installation

```bash
pip install flaskapi-guard
```

### Basic Usage

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig
from flaskapi_guard import IPInfoManager

app = Flask(__name__)

config = SecurityConfig(
    geo_ip_handler=IPInfoManager("your_token_here"),
    enable_redis=False,
    rate_limit=100,
    auto_ban_threshold=5,
)

guard = FlaskAPIGuard(app, config=config)
```

### App Factory Pattern

FlaskAPI Guard supports Flask's application factory pattern:

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig

guard = FlaskAPIGuard()

def create_app():
    app = Flask(__name__)

    config = SecurityConfig(
        rate_limit=100,
        rate_limit_window=60,
        enable_penetration_detection=True,
    )

    guard.init_app(app, config=config)

    @app.route("/")
    def hello():
        return {"message": "Hello, World!"}

    return app
```

___

## Example App

Inside [examples](https://github.com/rennf93/flaskapi-guard/tree/master/examples), you can find a simple example app that demonstrates how to use FlaskAPI Guard.

___

## Docker Container

You can also download the example app as a Docker container from [GitHub Container Registry](https://github.com/orgs/rennf93/packages/container/flaskapi-guard-example).

```bash
# Pull the latest version
docker pull ghcr.io/rennf93/flaskapi-guard-example:latest

# Or pull a specific version (matches library releases)
docker pull ghcr.io/rennf93/flaskapi-guard-example:v0.1.0
```

___

## Running the Example App

### Using Docker Compose (Recommended)

The easiest way to run the example app is with Docker Compose, which automatically sets up Redis:

```bash
# Clone the repository
git clone https://github.com/rennf93/flaskapi-guard.git
cd flaskapi-guard/examples

# Start the app with Redis
docker compose up
```

This will start both the FlaskAPI Guard example app and Redis service. The app will be available at <http://0.0.0.0:8000>.

### Using Docker Container Only

Alternatively, you can run just the container:

```bash
# Run with default settings
docker run -p 8000:8000 ghcr.io/rennf93/flaskapi-guard-example:latest

# Run with custom Redis connection
docker run -p 8000:8000 \
  -e REDIS_URL=redis://your-redis-host:your-redis-port \
  -e REDIS_PREFIX=your-redis-prefix \
  -e IPINFO_TOKEN=your-ipinfo-token \
  ghcr.io/rennf93/flaskapi-guard-example:latest
```

### Running Locally

You can also run the example app locally with gunicorn:

```bash
# Install dependencies
pip install flaskapi-guard gunicorn

# Run with gunicorn
gunicorn examples.main:app --bind 0.0.0.0:8000 --reload

# Or with Flask's built-in server
flask --app examples.main run --debug
```

___

## Features

- **IP Whitelisting and Blacklisting**: Control access based on IP addresses with CIDR support.
- **User Agent Filtering**: Block requests from specific user agents.
- **Rate Limiting**: Limit the number of requests from a single IP, with per-endpoint and geo-based rate limits.
- **Automatic IP Banning**: Automatically ban IPs after a configurable number of suspicious requests.
- **Penetration Attempt Detection**: Detect and log potential penetration attempts (XSS, SQL injection, command injection, path traversal, and more).
- **Custom Logging**: Log security events to a custom file with configurable log levels.
- **CORS Configuration**: Configure CORS settings for your Flask application.
- **Cloud Provider IP Blocking**: Block requests from cloud provider IPs (AWS, GCP, Azure).
- **IP Geolocation**: Use IPInfo.io API to determine the country of an IP address.
- **Security Headers**: OWASP-recommended security headers (HSTS, CSP, X-Frame-Options, etc.).
- **Route-Level Security**: Per-route security configuration via decorators.
- **Behavioral Analysis**: Endpoint usage tracking, anomaly detection, and return pattern monitoring.
- **Time-Based Access Control**: Restrict access to specific time windows.
- **Authentication Enforcement**: Require API keys, Bearer tokens, or session-based auth per route.
- **Content Filtering**: Validate content types and enforce request size limits.
- **Emergency Mode**: Block all traffic except whitelisted IPs during incidents.
- **Flexible Storage**: Choose between Redis-backed distributed state or in-memory storage.
- **Automatic Fallback**: Seamless operation with or without a Redis connection.
- **Secure Proxy Handling**: Protection against X-Forwarded-For header injection attacks.
- **Honeypot Detection**: Bot detection via hidden form fields.

___

## Architecture Overview

FlaskAPI Guard uses the standard Flask extension pattern with `before_request`/`after_request` hooks instead of WSGI middleware. This is a deliberate design choice -- WSGI middleware fires before Flask routing, so it cannot access route-specific configuration, decorator metadata, or `url_rule` information.

### Hook Execution Flow

**`before_request` (security pipeline):**

1. Handle passthrough/bypass cases
2. Get route config and client IP
3. Execute security check pipeline (17 checks)
4. Process behavioral usage rules
5. If any check fails, return an error response (short-circuits the request)

**`after_request` (response processing):**

1. Apply security headers
2. Apply CORS headers
3. Collect metrics
4. Process behavioral return rules
5. Execute custom response modifier

### Security Check Pipeline

The pipeline uses a Chain of Responsibility pattern with 17 checks executed in order:

| Order | Check | Purpose |
|-------|-------|---------|
| 1 | Route config extraction | Resolve per-route decorator config |
| 2 | Emergency mode | Block all traffic except whitelisted IPs |
| 3 | HTTPS enforcement | Redirect or reject non-HTTPS requests |
| 4 | Request logging | Log incoming requests |
| 5 | Size/content validation | Max request size, allowed content types |
| 6 | Required headers | Verify presence of required headers |
| 7 | Authentication | Verify auth requirements (API key, session) |
| 8 | Referrer validation | Validate request referrer against allowlist |
| 9 | Custom validators | Execute user-defined validator functions |
| 10 | Time windows | Enforce time-based access restrictions |
| 11 | Cloud IP refresh | Periodically refresh cloud provider IP ranges |
| 12 | IP security | Whitelist/blacklist, country-based filtering |
| 13 | Cloud provider blocking | Block requests from AWS/GCP/Azure IPs |
| 14 | User agent filtering | Block specific user agents |
| 15 | Rate limiting | Sliding window rate limits (per-IP, per-endpoint) |
| 16 | Suspicious activity | Penetration attempt detection |
| 17 | Custom request checks | Execute user-defined request check function |

___

## Route-Level Security

FlaskAPI Guard provides a decorator system for per-route security overrides:

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig, SecurityDecorator

app = Flask(__name__)
config = SecurityConfig(rate_limit=100, rate_limit_window=60)
security = SecurityDecorator(config)
guard = FlaskAPIGuard(app, config=config)
guard.set_decorator_handler(security)

@app.route("/api/limited")
@security.rate_limit(requests=5, window=60)
def rate_limited():
    return {"message": "This endpoint is rate limited", "limit": "5/minute"}

@app.route("/api/protected")
@security.require_auth(type="bearer")
def protected():
    return {"message": "Authenticated!"}

@app.route("/api/json-only", methods=["POST"])
@security.content_type_filter(["application/json"])
def json_only():
    return {"message": "JSON accepted"}

@app.route("/api/business-hours")
@security.time_window("09:00", "17:00", "UTC")
def business_hours():
    return {"message": "Available during business hours only"}

@app.route("/api/local-only")
@security.require_ip(whitelist=["127.0.0.1", "::1", "10.0.0.0/8"])
def local_only():
    return {"message": "Local access granted"}

@app.route("/api/unprotected")
@security.bypass(["all"])
def unprotected():
    return {"message": "No security checks applied"}
```

___

## Detection Engine

FlaskAPI Guard includes a detection engine for identifying penetration attempts via pattern matching, semantic analysis, and anomaly detection. Attack categories detected include:

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

___

## Configuration

FlaskAPI Guard uses a Pydantic model (`SecurityConfig`) for validated configuration. Key configuration areas include:

- **Proxy and trust settings**: Trusted proxies, proxy depth, X-Forwarded-Proto trust
- **Core security**: Passive mode, Redis integration, Redis prefix
- **IP management**: Whitelists, blacklists, country-based filtering
- **Rate limiting**: Global limits, per-endpoint limits, sliding window
- **Security headers**: OWASP defaults (HSTS, CSP, X-Frame-Options, etc.)
- **CORS**: Origins, methods, headers, credentials, max age
- **Cloud provider blocking**: AWS, GCP, Azure IP range blocking
- **Logging**: Custom log files, configurable log levels
- **Emergency mode**: Block all traffic except whitelisted IPs
- **Detection engine**: Compiler timeout, content length limits, semantic threshold, anomaly threshold
- **Custom functions**: Synchronous request checks and response modifiers
- **Path exclusions**: Skip security checks for specific paths

```python
from flask import Flask, Response
from flaskapi_guard import FlaskAPIGuard, SecurityConfig

config = SecurityConfig(
    # Rate limiting
    rate_limit=100,
    rate_limit_window=60,

    # IP management
    whitelist=["127.0.0.1", "::1"],
    blacklist=[],

    # Auto-banning
    auto_ban_threshold=10,
    auto_ban_duration=3600,

    # Redis
    enable_redis=True,
    redis_url="redis://localhost:6379",
    redis_prefix="flaskapi_guard:",

    # Penetration detection
    enable_penetration_detection=True,

    # CORS
    enable_cors=True,
    cors_allow_origins=["https://example.com"],

    # Security headers
    security_headers={
        "enabled": True,
        "csp": "default-src 'self'; script-src 'self'",
        "hsts": {"max_age": 31536000, "include_subdomains": True},
        "frame_options": "DENY",
        "content_type_options": "nosniff",
    },

    # Custom request check (sync)
    custom_request_check=lambda request: None,

    # Custom response modifier (sync)
    custom_response_modifier=lambda response: response,

    # Path exclusions
    exclude_paths=["/health", "/static", "/favicon.ico"],
)

app = Flask(__name__)
guard = FlaskAPIGuard(app, config=config)
```

___

## Key Differences from FastAPI Guard

FlaskAPI Guard is a direct port of [FastAPI Guard](https://github.com/rennf93/fastapi-guard) adapted for Flask's synchronous WSGI model:

| Aspect | FastAPI Guard | FlaskAPI Guard |
|--------|--------------|----------------|
| **Entry point** | `SecurityMiddleware` (ASGI) | `FlaskAPIGuard` (Flask extension) |
| **Hook mechanism** | ASGI `dispatch(request, call_next)` | `before_request` / `after_request` |
| **Execution model** | `async`/`await` | Fully synchronous |
| **Server model** | ASGI (uvicorn) | WSGI (gunicorn, waitress) |
| **Request object** | `starlette.requests.Request` | `flask.request` (Werkzeug) |
| **Response object** | `starlette.responses.Response` | `flask.Response` (Werkzeug) |
| **Request state** | `request.state` | `flask.g` |
| **Redis client** | `redis.asyncio.Redis` | `redis.Redis` (sync) |
| **HTTP client** | `httpx.AsyncClient` | `httpx.Client` (sync) |
| **Custom callables** | `async def check(request)` | `def check(request)` |

___

## Documentation

- [Release Notes](release-notes.md)
- [GitHub Repository](https://github.com/rennf93/flaskapi-guard)
- [PyPI Package](https://pypi.org/project/flaskapi-guard/)
- [FastAPI Guard (upstream)](https://github.com/rennf93/fastapi-guard)
