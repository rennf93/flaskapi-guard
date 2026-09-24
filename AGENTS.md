# AGENTS.md

Guidance for AI agents (including Claude Code) working in this repository.

## Project Overview

FlaskAPI Guard is a production-ready security library for Flask applications that provides:

- IP control and rate limiting
- Request logging and monitoring
- Penetration attempt detection
- Security headers management
- Redis-based distributed caching
- Route-level security decorators
- Behavioral analysis and anomaly detection

It is a direct port of [FastAPI Guard](https://github.com/rennf93/fastapi-guard) to the Flask/WSGI ecosystem, with the same feature set adapted for Flask's synchronous WSGI model.

- **PyPI Package**: `flaskapi_guard`
- **Import Name**: `flaskapi_guard`
- **Python Support**: 3.10, 3.11, 3.12, 3.13
- **Package Manager**: uv
- **Build System**: Docker + Make

## Ecosystem Position

FlaskAPI Guard is a **thin adapter** over [guard-core](https://github.com/rennf93/guard-core). All security logic (models, handlers, decorators, detection engine, protocols, utilities) lives in the `guard_core` package; this repo contains only the Flask/WSGI integration layer.

```text
guard-core (engine, PyPI dependency >=3.15.0)   <- all security logic
└── flaskapi-guard (this repo)                  <- Flask extension adapter
    ├── fastapi-guard                           <- sibling adapter (ASGI middleware)
    ├── djapi-guard                             <- sibling adapter (Django middleware)
    └── tornadoapi-guard                        <- sibling adapter (Tornado handler/middleware)
```

Because Flask is synchronous, this adapter imports the unasync-generated sync mirror `guard_core.sync.*` (not the async `guard_core.*` tree): the pipeline (`guard_core.sync.core.checks.pipeline.SecurityCheckPipeline`), handlers, decorators, protocols, and utilities all come from `guard_core.sync`. This adapter implements guard-core's `SyncGuardMiddlewareProtocol`.

### Package Components

- **`flaskapi_guard/extension.py`** - `FlaskAPIGuard`, the Flask extension. `init_app(app, config)` stores config on `app.extensions`, initializes handlers lazily, builds the `SecurityCheckPipeline` from the config, and registers the `before_request` / `after_request` hooks. Also exposes `set_decorator_handler` so the pipeline can be derived from registered route config, plus `guard_response_factory` and `agent_stats`.
- **`flaskapi_guard/adapters.py`** - Protocol adapters bridging Werkzeug/Flask types to guard-core protocols: `FlaskGuardRequest` (wraps `flask.request`), `FlaskGuardResponse` (wraps `flask.Response`), `FlaskResponseFactory` (creates blocked/redirect responses).
- **`flaskapi_guard/__init__.py`** - Public exports: `FlaskAPIGuard` plus re-exports from `guard_core` and `guard_core.sync` so users never import guard-core directly.

### Hook Execution Flow

`before_request` (security pipeline):

1. Handle passthrough/bypass cases
2. Resolve route config and client IP
3. Execute the security check pipeline (17 checks)
4. Process behavioral usage rules
5. If any check fails, return an error response (short-circuits the request)

`after_request` (response processing):

1. Apply security headers
2. Apply CORS headers
3. Collect metrics
4. Process behavioral return rules
5. Execute the custom response modifier

### Design Choice: Extension, Not WSGI Middleware

FlaskAPI Guard uses the Flask extension pattern with `before_request`/`after_request` hooks instead of WSGI middleware. WSGI middleware fires before Flask routing, so it cannot access route-specific configuration, decorator metadata, or `url_rule` information.

## Boundary Rules

- **This repo MUST NOT** contain security logic (checks, handlers, models, detection patterns, `SecurityConfig`). Those belong in [guard-core](https://github.com/rennf93/guard-core); a security fix belongs upstream, not here.
- **This repo MUST** bridge Flask/Werkzeug native types to guard-core's `GuardRequest` / `GuardResponse` / response-factory protocols through `flaskapi_guard/adapters.py`, and use the `guard_core.sync.*` mirror (never the async tree) because Flask is synchronous.
- **This repo MUST** keep `FlaskAPIGuard` a thin orchestrator that delegates to `SecurityCheckPipeline`; do not fork or reimplement pipeline behavior.
- **This repo MUST** re-export new guard-core public surface from `flaskapi_guard/__init__.py` when it becomes part of the adapter's user-facing API.
- This repo should only change when:
  - The Flask adapter layer needs updates
  - New guard-core exports need to be re-exported from `flaskapi_guard/__init__.py`
  - Flask-specific extension orchestration changes

## Quick Start

```bash
# Install dependencies
make install-dev

# Run tests locally
make local-test

# Start example application
make start-example

# Run linting and formatting
make fix
```

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
# Or with an app factory:
# guard = FlaskAPIGuard()
# guard.init_app(app, config=config)
```

## Development Commands

### Package Management (uv)

- `make install` - Install core dependencies
- `make install-dev` - Install with dev dependencies
- `make lock` - Update lock file
- `make upgrade` - Upgrade lock dependencies and install

### Testing

- `make test` - Run tests in Docker (Python 3.10)
- `make test-all` - Test all Python versions (3.10-3.13)
- `make test-3.12` - Test specific Python version
- `make local-test` - Run tests locally with uv

### Code Quality

- `make lint` - Run all linters in Docker (ruff, mypy)
- `make fix` - Auto-fix formatting with ruff
- `make vulture` - Find dead code
- `make bandit` - Security scan
- `make safety` - Check dependency vulnerabilities
- `make pip-audit` - Audit dependencies
- `make radon` - Analyze code complexity
- `make xenon` - Check complexity thresholds
- `make deptry` - Analyze dependencies
- `make security` - Run all security checks (bandit, safety, pip-audit)
- `make quality` - Run all quality checks (lint, vulture, radon, xenon)
- `make analysis` - Run analysis tools (deptry)
- `make check-all` - Run everything (lint, security, quality, analysis)

### Documentation

- `make serve-docs` - Serve MkDocs locally

### Docker Operations

- `make start-example` - Start example app with Docker
- `make run-example` - Build and run example
- `make stop` - Stop all containers
- `make restart` - Restart services
- `make prune` - Clean Docker resources
- `make clean` - Clean Python cache files and containers

Environment variables:

- `PYTHON_VERSION` - Python version (3.10-3.13)
- `REDIS_URL` - Redis connection string
- `REDIS_PREFIX` - Key prefix for Redis
- `IPINFO_TOKEN` - IPInfo API token

### Version Management

- `make bump-version VERSION=x.y.z` - Bump package version

## Project Structure

```text
flaskapi-guard/
├── flaskapi_guard/            # Adapter package (thin layer over guard-core)
│   ├── __init__.py            # Public exports + guard_core/guard_core.sync re-exports
│   ├── extension.py           # FlaskAPIGuard (Flask extension, before/after_request hooks)
│   ├── adapters.py            # FlaskGuardRequest / FlaskGuardResponse / FlaskResponseFactory
│   └── py.typed               # PEP 561 marker
├── tests/                     # Test suite
│   ├── test_adapters.py
│   ├── test_extension/        # Extension lifecycle and wiring
│   ├── test_decorators/       # Route-level decorator behaviors
│   ├── test_cors_through_pipeline.py
│   └── test_reexports.py      # Public API surface contract
├── examples/                  # Example Flask applications
├── docs/                      # MkDocs documentation
├── Makefile                   # Build automation
├── compose.yml                # Docker Compose config
├── Dockerfile                 # Docker image definition
├── pyproject.toml             # Project metadata & config
├── uv.lock                    # Locked dependencies
└── vulture_whitelist.py       # Vulture false positive suppressions
```

### Configuration Files

- **pyproject.toml** - Project metadata and dependencies; tool configurations for ruff, mypy, pytest, vulture, bandit, radon, xenon, deptry
- **uv.lock** - Locked dependency versions, updated with `make lock`
- **compose.yml / Dockerfile** - Multi-version Python support (3.10-3.13) and a Redis service for testing
- **.pre-commit-config.yaml** - ruff format, ruff check, mypy, vulture, bandit, safety, radon, xenon, deptry

## Technology Stack

### Core Dependencies

- **Flask** - WSGI web framework
- **Werkzeug** - WSGI toolkit (Flask's foundation)
- **guard-core** - Framework-agnostic security engine (all security logic, `>=3.15.0`)
- **gunicorn** - WSGI server

### Development Tools

- **uv** - Fast Python package manager
- **pytest** - Testing framework
- **pytest-cov** - Coverage reporting
- **pytest-mock** - Mock fixtures
- **ruff** - Fast Python linter/formatter
- **mypy** - Static type checker
- **vulture** - Dead code detection
- **bandit** - Security linter
- **radon/xenon** - Complexity analysis
- **deptry** - Dependency analysis
- **pre-commit** - Git hooks
- **mkdocs** / **mkdocs-material** - Documentation

## Testing Guidelines

### Running Tests

```bash
# Local testing with coverage
make local-test

# Docker testing (default Python 3.10)
make test

# Test all Python versions
make test-all

# Specific Python version
make test-3.12
```

### Test Configuration (pyproject.toml)

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
addopts = "--cov=flaskapi_guard --cov-report=term-missing --ignore=tests/test_agent"
```

Tests need a reachable Redis at `localhost:6379` (or set `REDIS_URL`).

### Run Specific Tests

```bash
# Run specific test file
REDIS_URL=redis://localhost:6379 uv run pytest tests/test_adapters.py -v

# Run with pattern matching
REDIS_URL=redis://localhost:6379 uv run pytest -k "extension" -v
```

## Code Quality Standards

### Ruff Configuration

- Target Python 3.10+
- Selected rules: E, F, UP, B, I
- Auto-fixable issues

### MyPy Configuration

- Strict type checking enabled
- No implicit Optional
- Warn on unused configs
- Check untyped definitions

### Pre-commit Workflow

1. Automatic formatting with ruff
2. Linting checks with ruff
3. Type checking with mypy
4. Dead code detection with vulture
5. Security scanning with bandit
6. Dependency vulnerability checking with safety
7. Complexity analysis with radon/xenon
8. Dependency analysis with deptry

## Best Practices

1. **Always use uv** for package management
2. **Run tests** before committing
3. **Use Make commands** for consistency
4. **Test multiple Python versions** for compatibility
5. **Keep dependencies updated** with `make upgrade`
6. **Use type hints** and run mypy
7. **Follow ruff** formatting standards
8. **Document changes** in appropriate docs/

### Sync-Only Code

- All custom callables (`custom_request_check`, `custom_response_modifier`, route validators, `auth_verifier`) are **synchronous**; the adapter runs on the `guard_core.sync` mirror
- Per-request state lives on `flask.g`, not `request.state`
- IP extraction uses `request.remote_addr` / `request.access_route`, proxy-aware
- Redis and outbound HTTP use synchronous clients (`redis.Redis`, `httpx.Client`)

### Security Considerations

- This is a security library - all code must be defensive
- Validate all inputs with Pydantic
- Use Redis for distributed rate limiting
- Implement proper error handling
- Log security events appropriately
- Never expose sensitive data in logs
- All regex patterns must be ReDoS-safe (guard-core's `PatternCompiler` validates this)

## Related Projects

- **guard-core** - Framework-agnostic security engine (the engine this adapter wraps): <https://github.com/rennf93/guard-core>
- **fastapi-guard** - FastAPI/Starlette adapter (async reference implementation): <https://github.com/rennf93/fastapi-guard>
- **djapi-guard** - Django middleware adapter (sync mirror): <https://github.com/rennf93/djapi-guard>
- **tornadoapi-guard** - Tornado handler/middleware adapter: <https://github.com/rennf93/tornadoapi-guard>
- **guard-agent** - Telemetry and monitoring agent: <https://github.com/rennf93/guard-agent>
- **guard-core-mcp** - MCP server for config validation and docs search: <https://github.com/rennf93/guard-core-mcp>
- **guard-core-app** - SaaS platform (API, dashboard, playground): <https://github.com/rennf93/guard-core-app>
