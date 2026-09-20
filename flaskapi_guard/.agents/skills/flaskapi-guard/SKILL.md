---
name: flaskapi-guard
description: FlaskAPI Guard, the Flask/WSGI security extension over guard-core. Use when securing a Flask app with IP filtering, rate limiting, penetration detection, security headers, cloud-provider blocking, route-level security decorators, or behavioral rules; when wiring FlaskAPIGuard into an app or app factory (init_app, before_request/after_request hooks); when adapting sync Werkzeug request/response types to guard-core's GuardRequest/GuardResponse protocols; or when debugging sync-callable requirements, Redis connectivity, decorator-route visibility via set_decorator_handler, or bypassed_checks token validation. Also use when porting fastapi-guard patterns to Flask or choosing the right Guard adapter for a WSGI stack.
---

# FlaskAPI Guard

Security extension for Flask: IP filtering, rate limiting, signature-based attack-pattern detection, security headers, and route-level security decorators. Import package is `flaskapi_guard` (distribution name `flaskapi_guard`). Current as of flaskapi-guard 4.3.0 over guard-core 3.15+.

FlaskAPI Guard is a thin adapter: all security logic (models, handlers, decorators, detection engine, protocols) lives in `guard_core`; this package only bridges Flask/WSGI to it through the unasync-generated `guard_core.sync` mirror. Everything is synchronous.

## Quick Reference

* Install: `uv add flaskapi-guard` (or `pip install flaskapi-guard`).
* Wire the extension: `FlaskAPIGuard(app, config=SecurityConfig(...))` or `guard.init_app(app, config=config)` with an app factory; see [Setup](#setup).
* All behavior is guard-core's `SecurityConfig`; do not mutate handlers directly.
* Route rules: `SecurityDecorator` from the sync mirror writes per-route `RouteConfig` the extension resolves at request time; see [Route-Level Security Decorators](#route-level-security-decorators).
* Register the decorator handler (`extension.set_decorator_handler`) so decorator-only checks are built into the pipeline.
* Sync only: custom callables must be plain functions, Redis uses `redis.Redis`, state lives on `flask.g`; see [Sync-Only Surface](#sync-only-surface).

## Installation

```bash
uv add flaskapi-guard          # or: pip install flaskapi-guard
```

Requires Python 3.10-3.13 and `guard-core>=3.15.0` (installed automatically). `import flaskapi_guard` pulls the `guard_core.sync` mirror, not the async tree.

## Setup

```python
from flask import Flask
from flaskapi_guard import FlaskAPIGuard, SecurityConfig

app = Flask(__name__)

config = SecurityConfig(
    rate_limit=100,
    rate_limit_window=60,
    enable_cors=True,
    cors_allow_origins=["https://example.com"],
)

guard = FlaskAPIGuard(app, config=config)
# App-factory form:
# guard = FlaskAPIGuard()
# guard.init_app(app, config=config)
```

`FlaskAPIGuard` registers `before_request` (bypass handling, route/IP resolution, the 17-check `SecurityCheckPipeline` from `guard_core.sync`, behavioral usage rules, short-circuit on block) and `after_request` (security headers, CORS, metrics, behavioral return rules, custom response modifier). Config is stored on `app.extensions["flaskapi_guard"]`. Redis, geo IP, cloud ranges, and the agent handler initialize lazily; a Redis outage yields the extension's Redis-unavailable response instead of a crash.

## Route-Level Security Decorators

```python
from flaskapi_guard import RouteConfig, SecurityDecorator

security = SecurityDecorator()

@app.route("/api/sensitive")
@security.configure(RouteConfig(
    rate_limit=5,
    rate_limit_window=60,
    require_https=True,
    blocked_countries=["XX"],
))
def sensitive_endpoint():
    return {"data": "restricted"}
```

Decorators stack top-down and each writes a per-route `RouteConfig` the extension resolves at request time. Checks that only decorators can trigger (auth, referrer, required headers, custom validators, time window, request size/content) are built into the pipeline only when the extension can see the registered route config; pass your `SecurityDecorator` via `guard.set_decorator_handler` so nothing is silently missing.

`RouteConfig.bypassed_checks` accepts only recognized tokens (`all`, `ip_ban`, `ip`, `clouds`, `rate_limit`, `penetration`); an unknown token is dropped with a warning, so a typo cannot make a check look disabled while it stays enforced.

## Sync-Only Surface

* Custom callables (`custom_request_check`, `custom_response_modifier`, route validators, `auth_verifier`) must be plain sync functions; async callables raise `TypeError` under WSGI.
* Per-request state lives on `flask.g` (guard state attributes are attached to the request object by the extension).
* IP extraction is proxy-aware via `request.remote_addr` / `request.access_route`.
* Redis (`redis.Redis`) and outbound HTTP (`httpx.Client`) are synchronous, mirroring guard-core's sync handlers.

## Footguns

* **`enable_redis` defaults to `True`** with `redis_url="redis://localhost:6379"`. Without a reachable Redis, stateful checks fail; set `enable_redis=False` in no-Redis environments or point at a real instance.
* **Async callables are rejected under WSGI.** Any `async def` custom check, validator, or modifier raises `TypeError`; convert to a sync function.
* **Decorator-only checks vanish without a decorator handler.** If the extension cannot see the registered route config (no `set_decorator_handler`), decorator-triggered checks are not built and their rules never fire; the checks are not silently enforced.
* **Unknown bypass tokens warn and are dropped** (see [Route-Level Security Decorators](#route-level-security-decorators)); do not rely on arbitrary labels appearing in the bypassed-checks event payload.
* **`passive_mode=True` logs but never blocks.** Use it to trial rules; switch to `False` once logs confirm the traffic you expect.

## Related Projects

* [guard-core](https://github.com/rennf93/guard-core): framework-agnostic security engine (async source + `guard_core.sync` mirror) this adapter wraps.
* [fastapi-guard](https://github.com/rennf93/fastapi-guard): FastAPI/Starlette adapter (async reference implementation).
* [djapi-guard](https://github.com/rennf93/djapi-guard): Django middleware adapter (sync mirror).
* [tornadoapi-guard](https://github.com/rennf93/tornadoapi-guard): Tornado handler/middleware adapter.
* [guard-agent](https://github.com/rennf93/guard-agent): telemetry client used by `enable_agent=True`.
* [guard-core-mcp](https://github.com/rennf93/guard-core-mcp): MCP server for config validation and docs search.
* [guard-core-app](https://github.com/rennf93/guard-core-app): SaaS platform the agent reports to.
