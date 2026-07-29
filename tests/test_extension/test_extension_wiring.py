from flask import Flask
from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

from flaskapi_guard import FlaskAPIGuard, SecurityConfig


def test_event_bus_routes_through_composite_when_otel_enabled() -> None:
    config = SecurityConfig(enable_otel=True, otel_service_name="wire-test")
    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=config)

    assert ext.event_bus is not None
    assert ext.metrics_collector is not None
    assert isinstance(ext.event_bus.agent_handler, CompositeAgentHandler)
    assert isinstance(ext.metrics_collector.agent_handler, CompositeAgentHandler)


def test_event_bus_routes_through_composite_when_logfire_enabled() -> None:
    config = SecurityConfig(enable_logfire=True, logfire_service_name="wire-test")
    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=config)

    assert ext.event_bus is not None
    assert ext.metrics_collector is not None
    assert isinstance(ext.event_bus.agent_handler, CompositeAgentHandler)
    assert isinstance(ext.metrics_collector.agent_handler, CompositeAgentHandler)


def test_event_bus_stays_bare_when_no_telemetry_configured() -> None:
    config = SecurityConfig()
    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=config)

    assert ext.event_bus is not None
    assert ext.metrics_collector is not None
    assert not isinstance(ext.event_bus.agent_handler, CompositeAgentHandler)
    assert not isinstance(ext.metrics_collector.agent_handler, CompositeAgentHandler)


def test_contexts_use_the_post_initialize_event_bus() -> None:
    config = SecurityConfig(enable_otel=True, otel_service_name="wire-test")
    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=config)

    assert ext.validator is not None
    assert ext.bypass_handler is not None
    assert ext.behavioral_processor is not None
    assert ext.response_factory is not None
    assert ext.validator.context.event_bus is ext.event_bus
    assert ext.bypass_handler.context.event_bus is ext.event_bus
    assert ext.behavioral_processor.context.event_bus is ext.event_bus
    assert ext.response_factory.context.metrics_collector is ext.metrics_collector


def test_populate_guard_state_marks_unmatched_request() -> None:
    from flask import request as flask_request

    from flaskapi_guard.adapters import FlaskGuardRequest

    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=SecurityConfig())

    @app.get("/known")
    def known() -> str:
        return "ok"

    with app.test_request_context("/no-such-path"):
        guard_request = FlaskGuardRequest(flask_request)
        ext._populate_guard_state(guard_request)
        assert guard_request.state.guard_route_unresolved is True

    with app.test_request_context("/known"):
        guard_request = FlaskGuardRequest(flask_request)
        ext._populate_guard_state(guard_request)
        assert not hasattr(guard_request.state, "guard_route_unresolved")
        assert not hasattr(guard_request.state, "guard_route_id")


def test_populate_guard_state_marks_endpoint_without_view_function() -> None:
    from flask import request as flask_request

    from flaskapi_guard.adapters import FlaskGuardRequest

    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=SecurityConfig())

    @app.get("/known")
    def known() -> str:
        return "ok"

    with app.test_request_context("/known"):
        app.view_functions.pop("known")
        guard_request = FlaskGuardRequest(flask_request)
        ext._populate_guard_state(guard_request)
        assert guard_request.state.guard_route_unresolved is True
