Changelog
=========

___

v2.1.0 (2026-04-24)
-------------------

Telemetry pipeline wiring fix (v2.1.0)
--------------------------------------

Adopts guard-core 1.1.0 and fixes an extension wiring bug that prevented OpenTelemetry, Logfire, and event/metric/check-log muting from seeing anything emitted by the request-path security pipeline.

- **Fixed** — `FlaskAPIGuard.init_app()` previously constructed `SecurityEventBus(agent_handler, ...)` and `MetricsCollector(agent_handler, ...)` in `_init_core_components()` using the bare `guard_agent` handler (or `None`). `_initialize_handlers()` then called `HandlerInitializer.initialize_agent_integrations()` which built a `CompositeAgentHandler` that no code path ever reached, because the event bus / metrics collector were already frozen on the bare handler. As a result, every event emitted through the request pipeline (`SecurityEventBus.send_middleware_event`) and every request metric bypassed OTel, Logfire, and the configured `muted_event_types` / `muted_metric_types` filter. This release splits construction into `_init_core_components()` (handler_initializer only), `_init_route_resolver()`, and `_build_event_bus_and_contexts()` — the last of which consults `handler_initializer.composite_handler` and uses `build_event_bus()` / `build_metrics_collector()` when the composite is available. `_initialize_handlers()` now re-invokes `_build_event_bus_and_contexts()` after `initialize_agent_integrations()` so the dependent contexts (`ResponseContext`, `ValidationContext`, `BypassContext`, `BehavioralContext`) bind to the post-init event bus.
- **Added** — `tests/test_extension/test_extension_wiring.py` — four regression tests that pin `ext.event_bus.agent_handler` and `ext.metrics_collector.agent_handler` to `CompositeAgentHandler` after `init_app` when OTel or Logfire is enabled, and confirm all dependent contexts reference the post-init event bus.
- **Dependencies** — `guard-core>=1.1.0,<2.0.0`.
- **User-visible impact** — Users already setting `enable_otel=True` or `enable_logfire=True` on `SecurityConfig` were previously getting handler-path events only (ip_banned, rate_limited from `ip_ban_manager` / `rate_limit_handler`, etc.) — but never pipeline-path events (`penetration_attempt`, `authentication_failed`, `user_agent_blocked`, `https_enforced`, etc.) or request metrics (`guard.request.duration`, `guard.request.count`, `guard.error.count`). After this release, every event and every metric flows through the composite, which means OTel spans, Logfire logs, and all mute fields (`muted_event_types`, `muted_metric_types`, `muted_check_logs`) work as documented. No `SecurityConfig` changes required; existing configurations produce strictly more telemetry, not less.
- **Tests** — `tests/test_extension/test_security_extension.py::test_request_without_client` updated: when `extract_client_ip` returns `"unknown"`, `is_ip_allowed` raises `ValueError` on the unparseable IP and the `ip_security` check correctly returns 403. The test now pins that deterministic-403 contract rather than the stale pre-1.1.0 200.

___

v2.0.0 (2026-03-26)
-------------------

Major Release (v2.0.0)
------------

- **Guard-Core migration**: FlaskAPI Guard is now a thin adapter over [guard-core](https://github.com/rennf93/guard-core), the framework-agnostic security engine. All security logic (17 checks, 8 handlers, detection engine) lives in guard-core; this package provides only the Flask integration layer.
- **Production/Stable status**: Development status upgraded from Alpha to Production/Stable.
- **Zero breaking changes to public API**: All existing imports (`from flaskapi_guard import SecurityConfig`, `from flaskapi_guard import FlaskAPIGuard`, etc.) continue to work exactly as before.
- **Shared engine across frameworks**: The same security engine now powers [fastapi-guard](https://github.com/rennf93/fastapi-guard) and [djangoapi-guard](https://github.com/rennf93/djangoapi-guard), ensuring consistent security behavior across all three frameworks.

___

v1.1.1 (2026-03-16)
-------------------

Bug Fixes (v1.1.1)
------------

- **Per-endpoint rate limit check**: Fixed rate limit check to properly evaluate endpoint-specific rate limits. Previously, the rate limit check was only evaluating global rate limits.

___

v1.1.0 (2026-03-14)
-------------------

New Features (v1.1.0)
------------

- **Configurable cloud IP refresh interval**: New `cloud_ip_refresh_interval` config field (default: 3600s, valid range: 60-86400s) allows tuning how often cloud provider IP ranges are refreshed. The interval is propagated to Redis TTL for cache consistency.
- **Change detection logging for cloud IP refreshes**: When cloud IP ranges are refreshed, additions and removals are logged per provider (e.g., `+12 added, -3 removed`), providing visibility into IP range mutations.
- **Context-aware detection engine**: Suspicious pattern rules are now tagged with applicable input contexts (`query_param`, `url_path`, `header`, `request_body`). Patterns are only evaluated against relevant input sources, reducing false positives.
- **Structured JSON logging**: New `log_format="json"` config option outputs logs as structured JSON (`{"timestamp": "...", "level": "...", "logger": "...", "message": "..."}`), enabling integration with log aggregation systems (ELK, Datadog, CloudWatch).
- **Per-provider `last_updated` timestamps**: `CloudManager` now tracks when each provider's IP ranges were last refreshed via `cloud_handler.last_updated["AWS"]`, returning `datetime | None`.

___

v1.0.0 (2026-03-13)
-------------------

Initial Release (v1.0.0)
------------

- Initial release of Flask API Guard
- IP whitelisting/blacklisting with CIDR support
- Rate limiting (global and per-endpoint)
- Automatic IP banning
- Penetration attempt detection
- User agent filtering
- Content type filtering
- Request size limiting
- Time-based access control
- Behavioral analysis and monitoring
- Custom authentication schemes
- Honeypot detection
- Redis integration for distributed environments
- Security headers management
- CORS configuration
- Emergency mode

___
