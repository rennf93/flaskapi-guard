from unittest.mock import MagicMock

from flask import Flask
from guard_core.models import SecurityConfig

from flaskapi_guard import FlaskAPIGuard


def test_agent_stats_returns_disabled_when_agent_handler_unset() -> None:
    app = Flask(__name__)
    config = SecurityConfig(enable_agent=False)
    guard = FlaskAPIGuard(app, config=config)

    assert guard.agent_handler is None
    assert guard.agent_stats == {"enabled": False}


def test_agent_stats_returns_enabled_with_agent_handler_stats() -> None:
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    fake_handler = MagicMock()
    fake_handler.get_stats.return_value = {
        "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0},
        "transport_stats": {"circuit_breaker_state": "CLOSED"},
    }
    guard.agent_handler = fake_handler

    stats = guard.agent_stats
    assert stats["enabled"] is True
    assert stats["buffer_stats"] == {"events_dropped": 0, "metrics_dropped": 0}
    assert stats["transport_stats"] == {"circuit_breaker_state": "CLOSED"}
    fake_handler.get_stats.assert_called_once()


def test_agent_stats_reflects_live_drop_counter_increments() -> None:
    app = Flask(__name__)
    config = SecurityConfig()
    guard = FlaskAPIGuard(app, config=config)

    fake_handler = MagicMock()
    fake_handler.get_stats.return_value = {
        "buffer_stats": {"events_dropped": 0, "metrics_dropped": 0},
        "transport_stats": {"circuit_breaker_state": "CLOSED"},
    }
    guard.agent_handler = fake_handler

    first = guard.agent_stats
    assert first["buffer_stats"]["events_dropped"] == 0

    fake_handler.get_stats.return_value = {
        "buffer_stats": {"events_dropped": 7, "metrics_dropped": 3},
        "transport_stats": {"circuit_breaker_state": "OPEN"},
    }

    second = guard.agent_stats
    assert second["buffer_stats"]["events_dropped"] == 7
    assert second["buffer_stats"]["metrics_dropped"] == 3
    assert second["transport_stats"]["circuit_breaker_state"] == "OPEN"
    assert fake_handler.get_stats.call_count == 2
