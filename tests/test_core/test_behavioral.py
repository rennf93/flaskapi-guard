from typing import Literal
from unittest.mock import MagicMock, Mock

import pytest
from flask import Request, Response

import flaskapi_guard.core.behavioral.processor as proc_module
from flaskapi_guard.core.behavioral.context import BehavioralContext
from flaskapi_guard.core.behavioral.processor import BehavioralProcessor
from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.handlers.behavior_handler import BehaviorRule


def create_route_config_with_rules(rules: list[BehaviorRule]) -> RouteConfig:
    """Helper to create RouteConfig with behavior rules."""
    config = RouteConfig()
    config.behavior_rules = rules
    return config


@pytest.fixture
def mock_event_bus() -> Mock:
    """Create mock event bus."""
    event_bus = Mock()
    event_bus.send_middleware_event = MagicMock()
    return event_bus


@pytest.fixture
def mock_guard_decorator() -> Mock:
    """Create mock guard decorator with behavior tracker."""
    decorator = Mock()
    decorator.behavior_tracker = Mock()
    decorator.behavior_tracker.track_endpoint_usage = MagicMock(return_value=False)
    decorator.behavior_tracker.track_return_pattern = MagicMock(return_value=False)
    decorator.behavior_tracker.apply_action = MagicMock()
    return decorator


@pytest.fixture
def behavioral_context(
    mock_event_bus: Mock, mock_guard_decorator: Mock
) -> BehavioralContext:
    """Create behavioral context."""
    context = BehavioralContext(
        config=Mock(),
        logger=Mock(),
        event_bus=mock_event_bus,
        guard_decorator=mock_guard_decorator,
    )
    return context


@pytest.fixture
def processor(behavioral_context: Mock) -> BehavioralProcessor:
    """Create BehavioralProcessor instance."""
    return BehavioralProcessor(behavioral_context)


@pytest.fixture
def mock_request() -> Mock:
    """Create mock request."""
    request = Mock(spec=Request)
    request.method = "GET"
    request.path = "/test"
    request.endpoint = "test_function"
    return request


@pytest.fixture
def mock_response() -> Mock:
    """Create mock response."""
    response = Mock(spec=Response)
    response.status_code = 200
    return response


@pytest.fixture(autouse=True)
def _mock_current_app(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mock current_app.view_functions for all tests in this module."""
    mock_app = Mock()
    mock_app.view_functions = {}
    monkeypatch.setattr(proc_module, "current_app", mock_app)


class TestBehavioralProcessor:
    """Test BehavioralProcessor class."""

    def test_init(self, behavioral_context: Mock) -> None:
        """Test processor initialization."""
        processor = BehavioralProcessor(behavioral_context)
        assert processor.context == behavioral_context

    def test_process_usage_rules_no_decorator(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test process_usage_rules when guard_decorator is None."""
        processor.context.guard_decorator = None
        route_config = RouteConfig()

        processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

    def test_process_usage_rules_no_threshold_exceeded(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test process_usage_rules when threshold not exceeded."""
        rule = BehaviorRule(rule_type="usage", threshold=10, window=60, action="log")
        route_config = create_route_config_with_rules([rule])

        processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called_once()
        processor.context.guard_decorator.behavior_tracker.apply_action.assert_not_called()

    def test_process_usage_rules_threshold_exceeded(
        self, processor: Mock, mock_request: Mock, mock_event_bus: Mock
    ) -> None:
        """Test process_usage_rules when usage threshold exceeded."""
        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage = (
            MagicMock(return_value=True)
        )

        rule = BehaviorRule(rule_type="usage", threshold=5, window=60, action="ban")
        route_config = create_route_config_with_rules([rule])

        processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

        mock_event_bus.send_middleware_event.assert_called_once()
        call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
        assert call_kwargs["event_type"] == "decorator_violation"
        assert call_kwargs["action_taken"] == "behavioral_action_triggered"
        assert "threshold exceeded" in call_kwargs["reason"]
        assert call_kwargs["threshold"] == 5
        assert call_kwargs["window"] == 60

        processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()

    def test_process_usage_rules_frequency_type(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test process_usage_rules with frequency rule type."""
        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage = (
            MagicMock(return_value=True)
        )

        rule = BehaviorRule(rule_type="frequency", threshold=3, window=30, action="log")
        route_config = create_route_config_with_rules([rule])

        processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

        processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called_once()
        processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()

    def test_process_usage_rules_multiple_rules(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test process_usage_rules with multiple rules."""
        rule1 = BehaviorRule(rule_type="usage", threshold=5, window=60, action="log")
        rule2 = BehaviorRule(
            rule_type="frequency", threshold=10, window=30, action="ban"
        )
        route_config = create_route_config_with_rules([rule1, rule2])

        processor.process_usage_rules(mock_request, "1.2.3.4", route_config)

        assert (
            processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.call_count
            == 2
        )

    def test_process_return_rules_no_decorator(
        self, processor: Mock, mock_request: Mock, mock_response: Mock
    ) -> None:
        """Test process_return_rules when guard_decorator is None."""
        processor.context.guard_decorator = None
        route_config = create_route_config_with_rules([])

        processor.process_return_rules(
            mock_request, mock_response, "1.2.3.4", route_config
        )

    def test_process_return_rules_no_pattern_detected(
        self, processor: Mock, mock_request: Mock, mock_response: Mock
    ) -> None:
        """Test process_return_rules when pattern not detected."""
        rule = BehaviorRule(
            rule_type="return_pattern",
            pattern="error",
            threshold=3,
            window=60,
            action="log",
        )
        route_config = create_route_config_with_rules([rule])

        processor.process_return_rules(
            mock_request, mock_response, "1.2.3.4", route_config
        )

        processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_called_once()
        processor.context.guard_decorator.behavior_tracker.apply_action.assert_not_called()

    def test_process_return_rules_pattern_detected(
        self,
        processor: Mock,
        mock_request: Mock,
        mock_response: Mock,
        mock_event_bus: Mock,
    ) -> None:
        """Test process_return_rules when return pattern threshold exceeded."""
        processor.context.guard_decorator.behavior_tracker.track_return_pattern = (
            MagicMock(return_value=True)
        )

        rule = BehaviorRule(
            rule_type="return_pattern",
            pattern="error",
            threshold=3,
            window=60,
            action="ban",
        )
        route_config = create_route_config_with_rules([rule])

        processor.process_return_rules(
            mock_request, mock_response, "1.2.3.4", route_config
        )

        mock_event_bus.send_middleware_event.assert_called_once()
        call_kwargs = mock_event_bus.send_middleware_event.call_args[1]
        assert call_kwargs["event_type"] == "decorator_violation"
        assert call_kwargs["violation_type"] == "return_pattern"
        assert call_kwargs["pattern"] == "error"
        assert "Return pattern threshold exceeded" in call_kwargs["reason"]

        processor.context.guard_decorator.behavior_tracker.apply_action.assert_called_once()

    def test_process_return_rules_ignores_non_return_pattern(
        self, processor: Mock, mock_request: Mock, mock_response: Mock
    ) -> None:
        """Test process_return_rules ignores non-return_pattern rules."""
        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            window=60,
            action="log",
        )
        route_config = create_route_config_with_rules([rule])

        processor.process_return_rules(
            mock_request, mock_response, "1.2.3.4", route_config
        )

        processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_not_called()

    def test_get_endpoint_id_with_route(
        self, processor: Mock, mock_request: Mock
    ) -> None:
        """Test get_endpoint_id with route information."""
        mock_view_func = Mock()
        mock_view_func.__module__ = "test_module"
        mock_view_func.__qualname__ = "test_function"

        mock_app = Mock()
        mock_app.view_functions = {"test_function": mock_view_func}

        with pytest.MonkeyPatch.context() as m:
            import flaskapi_guard.core.behavioral.processor as proc_module

            m.setattr(proc_module, "current_app", mock_app)
            endpoint_id = processor.get_endpoint_id(mock_request)
        assert endpoint_id == "test_module.test_function"

    def test_get_endpoint_id_no_route(self, processor: BehavioralProcessor) -> None:
        """Test get_endpoint_id fallback when no route."""
        request = Mock(spec=Request)
        request.method = "POST"
        request.path = "/api/test"
        request.endpoint = "nonexistent_endpoint"

        mock_app = Mock()
        mock_app.view_functions = {}

        with pytest.MonkeyPatch.context() as m:
            import flaskapi_guard.core.behavioral.processor as proc_module

            m.setattr(proc_module, "current_app", mock_app)
            endpoint_id = processor.get_endpoint_id(request)
        assert endpoint_id == "POST:/api/test"

    def test_get_endpoint_id_no_endpoint_attr(self, processor: Mock) -> None:
        """Test get_endpoint_id when route has no endpoint."""
        request = Mock(spec=Request)
        request.method = "GET"
        request.path = "/test"
        request.endpoint = "missing_endpoint"

        mock_app = Mock()
        mock_app.view_functions = {}

        with pytest.MonkeyPatch.context() as m:
            import flaskapi_guard.core.behavioral.processor as proc_module

            m.setattr(proc_module, "current_app", mock_app)
            endpoint_id = processor.get_endpoint_id(request)
        assert endpoint_id == "GET:/test"

    @pytest.mark.parametrize(
        "rule_type,pattern,threshold,window,action",
        [
            ("usage", None, 5, 60, "log"),
            ("frequency", None, 10, 30, "ban"),
            ("return_pattern", "error", 3, 120, "alert"),
        ],
    )
    def test_process_rules_with_various_configs(
        self,
        processor: Mock,
        mock_request: Mock,
        mock_response: Mock,
        rule_type: Literal["usage", "return_pattern", "frequency"],
        pattern: str | None,
        threshold: int,
        window: int,
        action: Literal["ban", "log", "throttle", "alert"],
    ) -> None:
        """Test processing rules with various configurations."""
        rule = BehaviorRule(
            rule_type=rule_type,
            pattern=pattern,
            threshold=threshold,
            window=window,
            action=action,
        )
        route_config = create_route_config_with_rules([rule])

        if rule_type in ["usage", "frequency"]:
            processor.process_usage_rules(mock_request, "1.2.3.4", route_config)
            processor.context.guard_decorator.behavior_tracker.track_endpoint_usage.assert_called()
        else:
            processor.process_return_rules(
                mock_request, mock_response, "1.2.3.4", route_config
            )
            processor.context.guard_decorator.behavior_tracker.track_return_pattern.assert_called()
