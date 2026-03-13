"""Tests for flaskapi_guard/core/events/metrics.py — MetricsCollector."""

import sys
import types
from unittest.mock import MagicMock

import pytest
from flask import Flask

from flaskapi_guard.core.events.metrics import MetricsCollector
from flaskapi_guard.models import SecurityConfig


class MockSecurityMetric:
    def __init__(self, **kwargs: object) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


@pytest.fixture(autouse=True)
def _mock_guard_agent_module() -> types.ModuleType:
    """Ensure guard_agent mock module is in sys.modules for every test."""
    mock_mod = types.ModuleType("guard_agent")
    mock_mod.SecurityMetric = MockSecurityMetric  # type: ignore[attr-defined]
    original = sys.modules.get("guard_agent")
    sys.modules["guard_agent"] = mock_mod
    yield mock_mod
    if original is not None:
        sys.modules["guard_agent"] = original
    else:
        sys.modules.pop("guard_agent", None)


def _make_config(**overrides: object) -> SecurityConfig:
    defaults: dict[str, object] = {
        "enable_redis": False,
        "redis_url": None,
        "agent_enable_metrics": True,
    }
    defaults.update(overrides)
    return SecurityConfig(**defaults)  # type: ignore[arg-type]


class TestMetricsCollector:
    """Tests for MetricsCollector.send_metric and collect_request_metrics."""

    def setup_method(self) -> None:
        self.config = _make_config()
        self.agent_handler = MagicMock()
        self.collector = MetricsCollector(self.agent_handler, self.config)
        self.app = Flask(__name__)

    def test_send_metric(self) -> None:
        """send_metric constructs SecurityMetric and calls agent_handler.send_metric."""
        self.collector.send_metric("response_time", 0.123, {"endpoint": "/api"})
        self.agent_handler.send_metric.assert_called_once()
        metric = self.agent_handler.send_metric.call_args[0][0]
        assert metric.metric_type == "response_time"
        assert metric.value == 0.123
        assert metric.tags == {"endpoint": "/api"}
        assert hasattr(metric, "timestamp")

    def test_send_metric_no_agent(self) -> None:
        """send_metric returns early when no agent_handler is set."""
        collector = MetricsCollector(None, self.config)
        collector.send_metric("response_time", 0.5)

    def test_send_metric_exception(self) -> None:
        """send_metric logs error but does not raise on exception."""
        self.agent_handler.send_metric.side_effect = Exception("agent down")
        self.collector.send_metric("response_time", 0.5)

    def test_collect_request_metrics_success(self) -> None:
        """collect_request_metrics sends response_time and request_count metrics."""
        with self.app.test_request_context("/api/data", method="GET"):
            from flask import request

            self.collector.collect_request_metrics(request, 0.250, 200)

        assert self.agent_handler.send_metric.call_count == 2
        calls = self.agent_handler.send_metric.call_args_list
        metric_types = [c[0][0].metric_type for c in calls]
        assert "response_time" in metric_types
        assert "request_count" in metric_types

    def test_collect_request_metrics_error_status(self) -> None:
        """collect_request_metrics additionally sends error_rate for 4xx/5xx."""
        with self.app.test_request_context("/api/fail", method="POST"):
            from flask import request

            self.collector.collect_request_metrics(request, 0.100, 500)

        assert self.agent_handler.send_metric.call_count == 3
        calls = self.agent_handler.send_metric.call_args_list
        metric_types = [c[0][0].metric_type for c in calls]
        assert "response_time" in metric_types
        assert "request_count" in metric_types
        assert "error_rate" in metric_types
