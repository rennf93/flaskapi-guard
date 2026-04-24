from flask import Flask
from guard_core.sync.core.events.composite_handler import CompositeAgentHandler

from flaskapi_guard import FlaskAPIGuard, SecurityConfig


def test_event_bus_routes_through_composite_when_otel_enabled() -> None:
    config = SecurityConfig(enable_otel=True, otel_service_name="wire-test")
    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=config)

    assert isinstance(ext.event_bus.agent_handler, CompositeAgentHandler)
    assert isinstance(ext.metrics_collector.agent_handler, CompositeAgentHandler)


def test_event_bus_routes_through_composite_when_logfire_enabled() -> None:
    config = SecurityConfig(enable_logfire=True, logfire_service_name="wire-test")
    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=config)

    assert isinstance(ext.event_bus.agent_handler, CompositeAgentHandler)
    assert isinstance(ext.metrics_collector.agent_handler, CompositeAgentHandler)


def test_event_bus_stays_bare_when_no_telemetry_configured() -> None:
    config = SecurityConfig()
    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=config)

    assert not isinstance(ext.event_bus.agent_handler, CompositeAgentHandler)
    assert not isinstance(ext.metrics_collector.agent_handler, CompositeAgentHandler)


def test_contexts_use_the_post_initialize_event_bus() -> None:
    config = SecurityConfig(enable_otel=True, otel_service_name="wire-test")
    app = Flask(__name__)
    ext = FlaskAPIGuard(app, config=config)

    assert ext.validator.context.event_bus is ext.event_bus
    assert ext.bypass_handler.context.event_bus is ext.event_bus
    assert ext.behavioral_processor.context.event_bus is ext.event_bus
    assert ext.response_factory.context.metrics_collector is ext.metrics_collector
