"""Tests for BaseSecurityDecorator event methods."""

import sys
import types
from unittest.mock import Mock

import pytest
from flask import Flask

from flaskapi_guard.decorators.base import BaseSecurityDecorator
from flaskapi_guard.models import SecurityConfig


def _install_mock_guard_agent() -> types.ModuleType:
    mock_module = types.ModuleType("guard_agent")

    class MockSecurityEvent:
        def __init__(self, **kwargs: object) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    mock_module.SecurityEvent = MockSecurityEvent  # type: ignore[attr-defined]
    sys.modules["guard_agent"] = mock_module
    return mock_module


def _uninstall_mock_guard_agent() -> None:
    sys.modules.pop("guard_agent", None)


@pytest.fixture(autouse=True)
def _mock_guard_agent():  # type: ignore[no-untyped-def]
    _install_mock_guard_agent()
    yield
    _uninstall_mock_guard_agent()


@pytest.fixture()
def app() -> Flask:
    app = Flask(__name__)
    app.config["TESTING"] = True
    return app


@pytest.fixture()
def decorator() -> BaseSecurityDecorator:
    config = SecurityConfig(enable_redis=False)
    return BaseSecurityDecorator(config)


class TestDecoratorEvents:
    """Tests for BaseSecurityDecorator event helper methods."""

    def test_send_decorator_event(
        self, app: Flask, decorator: BaseSecurityDecorator
    ) -> None:
        """send_decorator_event constructs SecurityEvent with correct fields."""
        agent = Mock()
        decorator.agent_handler = agent

        with app.test_request_context(
            "/api/test", method="POST", headers={"User-Agent": "TestAgent"}
        ):
            from flask import request

            decorator.send_decorator_event(
                event_type="test_event",
                request=request,
                action_taken="blocked",
                reason="test reason",
                decorator_type="test_decorator",
                extra_key="extra_val",
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "test_event"
        assert event.action_taken == "blocked"
        assert event.reason == "test reason"
        assert event.endpoint == "/api/test"
        assert event.method == "POST"
        assert event.decorator_type == "test_decorator"
        assert event.user_agent == "TestAgent"
        assert event.metadata["extra_key"] == "extra_val"

    def test_send_decorator_event_no_agent(
        self, app: Flask, decorator: BaseSecurityDecorator
    ) -> None:
        """send_decorator_event returns early when no agent_handler is set."""
        decorator.agent_handler = None

        with app.test_request_context("/test"):
            from flask import request

            decorator.send_decorator_event(
                event_type="test",
                request=request,
                action_taken="blocked",
                reason="test",
                decorator_type="test",
            )

    def test_send_decorator_event_exception(
        self, app: Flask, decorator: BaseSecurityDecorator
    ) -> None:
        """send_decorator_event logs error on exception without crashing."""
        agent = Mock()
        agent.send_event.side_effect = RuntimeError("agent down")
        decorator.agent_handler = agent

        with app.test_request_context("/test"):
            from flask import request

            decorator.send_decorator_event(
                event_type="test",
                request=request,
                action_taken="blocked",
                reason="test",
                decorator_type="test",
            )

    def test_send_access_denied_event(
        self, app: Flask, decorator: BaseSecurityDecorator
    ) -> None:
        """send_access_denied_event calls send_decorator_event with 'access_denied'."""
        agent = Mock()
        decorator.agent_handler = agent

        with app.test_request_context("/secure"):
            from flask import request

            decorator.send_access_denied_event(
                request=request,
                reason="IP blocked",
                decorator_type="access_control",
                source_ip="1.2.3.4",
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "access_denied"
        assert event.action_taken == "blocked"
        assert event.reason == "IP blocked"
        assert event.decorator_type == "access_control"

    def test_send_authentication_failed_event(
        self, app: Flask, decorator: BaseSecurityDecorator
    ) -> None:
        """send_authentication_failed_event calls with 'authentication_failed'."""
        agent = Mock()
        decorator.agent_handler = agent

        with app.test_request_context("/auth"):
            from flask import request

            decorator.send_authentication_failed_event(
                request=request,
                reason="Invalid API key",
                auth_type="api_key",
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "authentication_failed"
        assert event.action_taken == "blocked"
        assert event.decorator_type == "authentication"
        assert event.metadata["auth_type"] == "api_key"

    def test_send_rate_limit_event(
        self, app: Flask, decorator: BaseSecurityDecorator
    ) -> None:
        """send_rate_limit_event calls with 'rate_limited'."""
        agent = Mock()
        decorator.agent_handler = agent

        with app.test_request_context("/api/data"):
            from flask import request

            decorator.send_rate_limit_event(
                request=request,
                limit=100,
                window=60,
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "rate_limited"
        assert event.action_taken == "blocked"
        assert event.reason == "Rate limit exceeded: 100 requests per 60s"
        assert event.decorator_type == "rate_limiting"
        assert event.metadata["limit"] == 100
        assert event.metadata["window"] == 60

    def test_send_decorator_violation_event(
        self, app: Flask, decorator: BaseSecurityDecorator
    ) -> None:
        """send_decorator_violation_event calls with 'decorator_violation'."""
        agent = Mock()
        decorator.agent_handler = agent

        with app.test_request_context("/admin"):
            from flask import request

            decorator.send_decorator_violation_event(
                request=request,
                violation_type="content_filter",
                reason="Invalid content type",
            )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.action_taken == "blocked"
        assert event.reason == "Invalid content type"
        assert event.decorator_type == "content_filter"
