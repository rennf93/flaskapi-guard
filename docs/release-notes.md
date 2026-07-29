Release Notes
=============

___

v4.1.0 (2026-07-29)
-------------------

Unmatched requests are reported to guard-core (v4.1.0)
-------------------------------------------------------

- **Added** — `_populate_guard_state()` returned silently when Flask matched no rule, which is indistinguishable from a view that simply carries no decorators. guard-core reads both as "nothing to enforce", so a resolution failure silently skips every per-route check — the fail-open half of [GHSA-f2vm-w8gq-h378](https://github.com/rennf93/fastapi-guard/security/advisories/GHSA-f2vm-w8gq-h378), reported against the Starlette adapter. Flask routes requests itself, so this adapter has no equivalent matching bug, but it now reports the failure by setting `request.state.guard_route_unresolved` when `request.endpoint` is unset or its view function is missing. A matched view without `_guard_route_id` is left alone, since an undecorated view legitimately has no per-route config. With guard-core >= 3.7.0 and `SecurityConfig.route_resolution_strict=True`, unmatched requests are logged, emit a `route_unresolved` event, and are blocked with `500`. Behaviour is unchanged by default and on older guard-core, which ignores the attribute.
- **Fixed (tests)** — The IPv6 and mixed IPv4/IPv6 allow-list tests still encoded pre-3.2.0 guard-core semantics, where the blacklist was evaluated before the whitelist. Since guard-core 3.2.0 an explicit whitelist match overrides the blacklist, so an address inside both a whitelist CIDR and a blacklist entry is now served rather than blocked. `test_multiple_decorators` likewise predated guard-core 3.5.0, where a route `@require_ip` match grants the IP aspect only, so a route-blocked country still denies the request. CI floats guard-core to the latest release and had not run here since 2026-05-28, so these only surfaced now; the adapter itself was correct throughout.
- **Fixed (CI)** — The greetings workflow passed `issue-message`/`pr-message` to `actions/first-interaction@v3`, which expects `issue_message`/`pr_message`, so the job failed on every first-time issue and pull request.

___

v4.0.1 (2026-05-27)
-------------------

guard-core 3.1.0 compatibility + PEP 639 license metadata (v4.0.1)
------------------------------------------------------------------

- **Fixed** — guard-core 3.1.0 narrowed `block_cloud_providers` to `set[Literal["AWS", "GCP", "Azure"]]`; `refresh_cloud_ip_ranges()` now normalizes it to `set[str]` before calling `cloud_handler.refresh_async`, resolving a `set`-invariance mypy error. Runtime behavior is unchanged.
- **Packaging** — Migrated license metadata to PEP 639: `license = "MIT"` (SPDX expression) plus `license-files = ["LICENSE"]`, and dropped the deprecated MIT license classifier.
- **Build** — Removed the unused `setup.py`; the release workflow now builds via `python -m build` (hatchling backend) instead of `python setup.py sdist bdist_wheel`.

___

v4.0.0 (2026-04-29)
-------------------

Fail-secure by default (upstream), agent-stats surface, version reporting (v4.0.0)
----------------------------------------------------------------------------------

- **Breaking (upstream)** — `SecurityConfig.fail_secure` now defaults to `True` (inherited from `guard-core >= 3.0.0`). When any security check raises an unhandled exception, the request is now blocked with HTTP 500 instead of logging and falling through. Bugs in checks that previously slipped past as silent fail-open responses now surface immediately. Restore the old behavior on deployments that depend on it via `SecurityConfig(fail_secure=False)`. Recommended migration: keep the new default, surface any check exceptions in your monitoring, and fix them — the previous default could mask serious bugs. The flaskapi-guard major bump tracks this upstream change so deployments see a clear signal.
- **Added** — `FlaskAPIGuard.agent_stats` read-only `@property` returning the agent's telemetry buffer state. Returns `{"enabled": False}` when no agent is wired; otherwise returns `{"enabled": True, **agent_handler.get_stats()}` exposing `events_dropped`, `metrics_dropped`, `circuit_breaker_state`, and other agent counters. No caching — fresh on each call. Access the property on the extension instance returned by `FlaskAPIGuard(app, config=...)` or via `app.extensions["flaskapi_guard"]["guard"].agent_stats`. Lets app teams build Flask health endpoints that surface agent-side drops and circuit-breaker trips without scraping the agent directly.
- **Added** — `from flaskapi_guard import __version__` — package version is now exported via `importlib.metadata.version("flaskapi_guard")` with a `"0.0.0+unknown"` fallback if the package is not installed (development from source). Pairs with `guard-core >= 3.0.0`'s `SecurityConfig.agent_guard_version` so application code can wire the flaskapi-guard version through to the agent for SaaS-side telemetry attribution: `SecurityConfig(agent_guard_version=__version__)`.
- **Fixed (latent)** — `FlaskAPIGuard.refresh_cloud_ip_ranges` was calling `cloud_handler.refresh(...)` directly. When Redis was enabled, that method raises `RuntimeError("Use refresh_async() when Redis is enabled")` — the cloud-IP refresh check would surface as an exception inside the security pipeline. Under the old `fail_secure=False` default the exception was logged and the request fell through, so the bug stayed invisible. Under the new `fail_secure=True` default it would block every request with HTTP 500 in any deployment that combines `enable_redis=True` with `block_cloud_providers`. Switched to `cloud_handler.refresh_async(...)` which dispatches Redis-aware vs non-Redis paths internally (matches djangoapi-guard's v3.0.0 fix and tornadoapi-guard's existing dispatch). Same fix shape; pre-existing bug.
- **Compatibility** — `FlaskAPIGuard.agent_stats` is purely additive; no existing API was changed. `__version__` was previously absent; reading it before this release returned `None` via missing-attribute fallback in some integrations.

___

v3.0.0 (2026-04-26)
-------------------

Pipeline-first CORS via guard_core.cors_handler (v3.0.0)
--------------------------------------------------------

- **Breaking** — Preflight `OPTIONS` requests are now subject to the security pipeline (previously short-circuited inside the extension). Banned IPs and rate-limited clients can no longer preflight freely.
- **Breaking** — CORS is now configured exclusively via `SecurityConfig.cors_*` fields. The extension wires `_before_request` / `_after_request` automatically; no separate `configure_cors` entry point.
- **Fixed** — Cross-origin preflight requests to passthrough paths (e.g. `exclude_paths=["/health"]`) now receive a valid CORS response. Preflight handling runs ahead of the passthrough/bypass short-circuit so the browser permission check works for excluded paths.
- **Fixed** — Cross-origin GETs to passthrough/bypass paths now carry CORS headers on their responses, matching the previous outer-CORSMiddleware semantics.
- **Internal** — Both lifecycle hooks delegate to the new shared `guard_core.sync.handlers.cors_handler.CorsHandler`. Removed all `[[tool.mypy.overrides]] ignore_missing_imports = true` / `follow_imports = "skip"` blocks; replaced with proper inline-typed packages and `django-stubs`. Stripped `[tool.uv.sources] guard-core` local-path block from committed pyproject.toml. Added `guard-agent` to dev dependencies (was previously declared only in deptry's per-rule-ignores).
- **Requires** — `guard-core>=2.2.0`.

___

v2.2.0 (2026-04-25)
-------------------

guard-core 2.0.0 protocol-shape adjustment (v2.2.0)
---------------------------------------------------

- **Requires** — guard-core 2.0.0 or newer. guard-core's major bump migrates `suspicious_request_counts` to a per-category nested dict, replaces `detect_penetration_attempt` / `detect_penetration_patterns` 2-tuple returns with `DetectionResult`, and migrates the cloud-IP cache namespace.
- **Updated** — `FlaskAPIGuard.suspicious_request_counts` is now typed `dict[str, dict[str, int]]` to match guard-core's per-category counter shape.
- **User-visible impact** — User code that didn't reach into those internals continues to work unchanged.

___

v2.1.1 (2026-04-25)
-------------------

Integration fixes for OTel + enrichment pipeline (v2.1.1)
---------------------------------------------------------

- **Fixed** — After composite construction, `self.agent_handler` is rebound from the bare `guard-agent` client to the composite. Downstream callers that receive `extension.agent_handler` (most notably `guard_core.utils.extract_client_ip → send_agent_event`) now route through the composite, so enrichment and OTel see every event.
- **Fixed** — `BehavioralContext` now receives `handler_initializer.behavior_tracker`, matching the guard-core 1.2.1 wiring. This closes the architectural gap so `guard.behavior.recent_event_count` populates end-to-end when `enable_enrichment=True`.
- **Added** — `tests/test_extension_lifecycle.py` — regression tests pinning the agent_handler rebind and behavior_tracker threading.
- **Requires** — `guard-core>=1.2.1` for the matching OTLP endpoint normalization and `BehaviorTracker` wiring fixes. Install the latest with `uv add flaskapi-guard guard-core` or `pip install -U flaskapi-guard guard-core`.
- **User-visible impact** — Users with `enable_otel=True`, `enable_logfire=True`, or `enable_enrichment=True` previously saw silent drops on a portion of events because callers using `extension.agent_handler` directly bypassed the composite handler. After this release every downstream caller routes through the composite, so all events flow through telemetry and enrichment as configured.

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
