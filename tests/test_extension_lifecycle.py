from unittest.mock import patch

import pytest
from flask import Flask
from guard_core.exceptions import GuardRedisError
from guard_core.models import SecurityConfig
from guard_core.sync.handlers.redis_handler import RedisManager

from flaskapi_guard import FlaskAPIGuard


def test_init_rebinds_agent_handler_to_composite() -> None:
    config = SecurityConfig(
        enable_otel=True,
        otel_service_name="guard-test",
        otel_exporter_endpoint="http://localhost:4318",
        enable_redis=False,
    )
    app = Flask(__name__)
    extension = FlaskAPIGuard(app, config=config)
    extension._ensure_initialized()

    assert extension.handler_initializer is not None
    assert extension.handler_initializer.composite_handler is not None
    assert extension.agent_handler is extension.handler_initializer.composite_handler


def test_no_telemetry_leaves_agent_handler_bare() -> None:
    app = Flask(__name__)
    extension = FlaskAPIGuard(app, config=SecurityConfig(enable_redis=False))

    assert extension.handler_initializer is not None
    assert extension.handler_initializer.composite_handler is None
    assert extension.agent_handler is None


def test_behavior_tracker_threaded_through_behavioral_context() -> None:
    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="k" * 10,
        agent_project_id="p",
        enable_enrichment=True,
        enable_otel=True,
        otel_exporter_endpoint="http://localhost:4318",
        enable_redis=False,
    )
    app = Flask(__name__)
    extension = FlaskAPIGuard(app, config=config)
    extension._ensure_initialized()

    assert extension.handler_initializer is not None
    assert extension.handler_initializer.behavior_tracker is not None
    assert extension.behavioral_processor is not None
    assert (
        extension.behavioral_processor.context.behavior_tracker
        is extension.handler_initializer.behavior_tracker
    )


def test_resolve_config_uses_preset_config_when_arg_is_none() -> None:
    preset = SecurityConfig(enable_redis=False)
    extension = FlaskAPIGuard(config=preset)
    app = Flask(__name__)

    extension.init_app(app)

    assert extension.config is preset


def test_resolve_config_raises_when_no_config_available() -> None:
    extension = FlaskAPIGuard()
    app = Flask(__name__)

    with pytest.raises(ValueError, match="SecurityConfig must be provided"):
        extension.init_app(app)


def test_set_decorator_handler_is_safe_before_init_app() -> None:
    extension = FlaskAPIGuard()

    extension.set_decorator_handler(None)

    assert extension.guard_decorator is None
    assert extension.route_resolver is None
    assert extension.behavioral_processor is None
    assert extension.response_factory is None
    assert extension.handler_initializer is None
    assert extension._app is None


def test_execute_security_pipeline_returns_none_when_pipeline_absent() -> None:
    from flaskapi_guard.adapters import FlaskGuardRequest

    extension = FlaskAPIGuard()
    app = Flask(__name__)
    with app.test_request_context("/"):
        from flask import request

        guard_request = FlaskGuardRequest(request)
        assert extension._execute_security_pipeline(guard_request) is None


def test_set_decorator_handler_skips_app_extension_when_entry_not_dict() -> None:
    config = SecurityConfig(enable_redis=False, enable_penetration_detection=False)
    app = Flask(__name__)
    extension = FlaskAPIGuard(app, config=config)

    app.extensions["flaskapi_guard"] = "not-a-dict"

    extension.set_decorator_handler(None)

    assert app.extensions["flaskapi_guard"] == "not-a-dict"


def test_redis_unavailable_at_first_request_returns_503_and_retries() -> None:
    config = SecurityConfig(enable_penetration_detection=False)
    app = Flask(__name__)

    @app.route("/")
    def read_root() -> dict[str, str]:
        return {"message": "Hello World"}

    guard = FlaskAPIGuard(app, config=config)

    original_initialize = RedisManager.initialize
    calls = {"count": 0}

    def flaky_initialize(self: RedisManager) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise GuardRedisError(503, "Redis connection failed")
        original_initialize(self)

    with patch.object(RedisManager, "initialize", flaky_initialize):
        with app.test_client() as client:
            response = client.get("/")
            assert response.status_code == 503
            assert response.headers["Retry-After"] == "5"
            assert guard._initialized is False

            response = client.get("/")
            assert response.status_code == 200
            assert response.get_json() == {"message": "Hello World"}
            assert guard._initialized is True
