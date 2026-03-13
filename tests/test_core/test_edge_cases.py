import re
from unittest.mock import MagicMock, Mock, patch

from flask import Request, Response

from flaskapi_guard.core.events.extension_events import SecurityEventBus
from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.dynamic_rule_handler import DynamicRuleManager
from flaskapi_guard.handlers.ratelimit_handler import RateLimitManager
from flaskapi_guard.handlers.security_headers_handler import SecurityHeadersManager
from flaskapi_guard.handlers.suspatterns_handler import SusPatternsManager
from flaskapi_guard.models import SecurityConfig


class TestDynamicRuleHandler:
    """Test DynamicRuleHandler edge cases."""

    def test_send_rule_received_event_no_agent(self) -> None:
        """Test _send_rule_received_event when no agent handler exists."""
        from datetime import datetime, timezone

        config = SecurityConfig()
        config.enable_dynamic_rules = False
        manager = DynamicRuleManager(config)
        manager.agent_handler = None  # No agent

        # Create fake rules
        from flaskapi_guard.models import DynamicRules

        rules = DynamicRules(
            rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
        )

        # Should return early without error
        manager._send_rule_received_event(rules)

        # Verify no exception was raised
        assert True


class TestRateLimitHandler:
    """Test RateLimitHandler edge cases."""

    def test_get_redis_request_count_no_redis_handler(self) -> None:
        """Test _get_redis_request_count when no redis handler exists."""
        config = SecurityConfig()
        config.enable_redis = False
        manager = RateLimitManager(config)
        manager.redis_handler = None  # No Redis handler

        # Should return None early
        result = manager._get_redis_request_count(
            client_ip="127.0.0.1", current_time=1000.0, window_start=900.0
        )

        assert result is None


class TestSecurityHeadersHandler:
    """Test SecurityHeadersHandler edge cases."""

    def test_get_validated_cors_config_no_cors_config(self) -> None:
        """Test _get_validated_cors_config when cors_config is None."""
        manager = SecurityHeadersManager()
        manager.cors_config = None

        # Should return defaults
        allow_methods, allow_headers = manager._get_validated_cors_config()

        assert allow_methods == ["GET", "POST"]
        assert allow_headers == ["*"]


class TestSusPatternsHandler:
    """Test SusPatternsHandler edge cases."""

    def test_remove_default_pattern_not_found(self) -> None:
        """Test _remove_default_pattern when pattern doesn't exist."""
        # Get singleton instance
        handler = SusPatternsManager()

        # Save original state
        original_patterns = handler.patterns.copy()
        original_compiled = handler.compiled_patterns.copy()

        try:
            # Try to remove non-existent pattern
            result = handler._remove_default_pattern("nonexistent_pattern_xyz")

            assert result is False
        finally:
            # Restore original state
            handler.patterns = original_patterns
            handler.compiled_patterns = original_compiled

    def test_remove_default_pattern_invalid_index(self) -> None:
        """Test _remove_default_pattern with index out of range."""
        # Get singleton instance
        handler = SusPatternsManager()

        # Save original state
        original_patterns = handler.patterns.copy()
        original_compiled = handler.compiled_patterns.copy()

        try:
            # Add a pattern to default list
            test_pattern = "test_pattern_xyz_123_unique_edge"
            handler.patterns.append(test_pattern)
            compiled = re.compile(test_pattern)
            handler.compiled_patterns.append(compiled)

            # Manually break the sync between patterns and compiled_patterns
            # to test the fallback
            handler.compiled_patterns = []  # Empty compiled list

            result = handler._remove_default_pattern(test_pattern)

            # Pattern was found and removed from patterns list,
            # but not from compiled list (out of range)
            assert result is False
        finally:
            # Restore original state
            handler.patterns = original_patterns
            handler.compiled_patterns = original_compiled


class TestExtension:
    """Test Extension edge cases."""

    def test_create_https_redirect(self) -> None:
        """Test _create_https_redirect method."""
        from flask import Flask

        app = Flask(__name__)
        config = SecurityConfig()
        guard = FlaskAPIGuard(app, config=config)

        with app.test_request_context("/test", base_url="http://example.com"):
            # Mock response factory
            guard.response_factory = Mock()
            guard.response_factory.create_https_redirect = MagicMock(
                return_value=Response("", status=307)
            )

            # Call the method
            from flask import request as flask_request

            response = guard._create_https_redirect(flask_request)

            assert response.status_code == 307
            guard.response_factory.create_https_redirect.assert_called_once()


class TestUtilsEdgeCases:
    """Test utils.py edge cases."""

    def test_fallback_pattern_check_with_exception(self) -> None:
        """Test _fallback_pattern_check when pattern.search raises exception."""
        from flaskapi_guard.utils import _fallback_pattern_check

        # Mock pattern that raises exception
        with patch(
            "flaskapi_guard.handlers.suspatterns_handler.sus_patterns_handler"
        ) as mock_handler:
            mock_pattern = Mock()
            mock_pattern.search = Mock(side_effect=Exception("Pattern error"))
            mock_handler.get_all_compiled_patterns = MagicMock(
                return_value=[mock_pattern]
            )

            # Should handle exception and continue
            result = _fallback_pattern_check("test_value")

            # Should return False since no patterns matched
            assert result == (False, "")

    def test_check_value_enhanced_empty_threats_list(self) -> None:
        """Test empty threats list."""
        from flaskapi_guard.utils import _check_value_enhanced

        # Mock at the module level where it's imported
        with patch("flaskapi_guard.utils.sus_patterns_handler") as mock_handler:
            # Simulate a threat detected but no threat details available
            mock_handler.detect = MagicMock(
                return_value={"is_threat": True, "threats": []}
            )

            # Call _check_value_enhanced
            result = _check_value_enhanced(
                value="test_value",
                context="test_context",
                client_ip="127.0.0.1",
                correlation_id="test-123",
            )

            # Should return True with generic message
            assert result == (True, "Threat detected")

    def test_detect_penetration_attempt_real_path(self) -> None:
        """Test detect_penetration_attempt with real detection."""
        from flaskapi_guard.utils import detect_penetration_attempt

        mock_request = Mock(spec=Request)
        mock_request.remote_addr = "127.0.0.1"
        mock_request.args = {}
        mock_request.path = "/test"
        mock_request.headers = {}
        mock_request.get_data = MagicMock(return_value=b"")

        # Don't mock the handler - use real detection
        # This will exercise the actual check_value function
        result = detect_penetration_attempt(mock_request)

        # Should return False, "" for clean request
        assert isinstance(result, tuple)
        assert len(result) == 2
        assert isinstance(result[0], bool)
        assert isinstance(result[1], str)


class TestSecurityEventBusHttpsAndCloud:
    """Test SecurityEventBus HTTPS violation and cloud detection events."""

    def test_send_https_violation_event_route_specific(self) -> None:
        """Test send_https_violation_event with route-specific HTTPS requirement."""
        config = SecurityConfig()
        config.agent_enable_events = True

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        event_bus = SecurityEventBus(mock_agent, config)

        mock_request = Mock(spec=Request)
        mock_request.url = "http://example.com/test"
        mock_request.scheme = "http"
        mock_request.remote_addr = "127.0.0.1"
        mock_request.path = "/test"
        mock_request.method = "GET"
        mock_request.headers = {}

        route_config = RouteConfig()
        route_config.require_https = True

        import sys

        mock_guard_agent = MagicMock()
        mock_event_class = MagicMock()
        mock_guard_agent.SecurityEvent = mock_event_class
        sys.modules["guard_agent"] = mock_guard_agent

        try:
            event_bus.send_https_violation_event(mock_request, route_config)
            assert mock_agent.send_event.call_count == 1
        finally:
            if "guard_agent" in sys.modules:
                del sys.modules["guard_agent"]

    def test_send_https_violation_event_global(self) -> None:
        """Test send_https_violation_event with global HTTPS enforcement."""
        config = SecurityConfig()
        config.agent_enable_events = True

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        event_bus = SecurityEventBus(mock_agent, config)

        mock_request = Mock(spec=Request)
        mock_request.url = "http://example.com/test"
        mock_request.scheme = "http"
        mock_request.remote_addr = "127.0.0.1"
        mock_request.path = "/test"
        mock_request.method = "GET"
        mock_request.headers = {}

        import sys

        mock_guard_agent = MagicMock()
        mock_event_class = MagicMock()
        mock_guard_agent.SecurityEvent = mock_event_class
        sys.modules["guard_agent"] = mock_guard_agent

        try:
            # No route_config → global HTTPS enforcement
            event_bus.send_https_violation_event(mock_request, None)
            assert mock_agent.send_event.call_count == 1
        finally:
            if "guard_agent" in sys.modules:
                del sys.modules["guard_agent"]

    def test_send_cloud_detection_events(self) -> None:
        """Test send_cloud_detection_events sends events correctly."""
        config = SecurityConfig()
        config.agent_enable_events = True

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        event_bus = SecurityEventBus(mock_agent, config)

        mock_request = Mock(spec=Request)
        mock_request.remote_addr = "1.2.3.4"
        mock_request.path = "/test"
        mock_request.method = "GET"
        mock_request.headers = {}

        mock_cloud = Mock()
        mock_cloud.get_cloud_provider_details = Mock(return_value=("AWS", "1.0.0.0/8"))
        mock_cloud.agent_handler = mock_agent
        mock_cloud.send_cloud_detection_event = MagicMock()

        route_config = RouteConfig()
        route_config.block_cloud_providers = {"AWS"}

        import sys

        mock_guard_agent = MagicMock()
        mock_event_class = MagicMock()
        mock_guard_agent.SecurityEvent = mock_event_class
        sys.modules["guard_agent"] = mock_guard_agent

        try:
            event_bus.send_cloud_detection_events(
                mock_request,
                "1.2.3.4",
                ["AWS"],
                route_config,
                mock_cloud,
                passive_mode=False,
            )
            # Cloud handler should have been called
            mock_cloud.send_cloud_detection_event.assert_called_once()
            # Middleware event also sent for route-specific block
            assert mock_agent.send_event.call_count >= 1
        finally:
            if "guard_agent" in sys.modules:
                del sys.modules["guard_agent"]


class TestSecurityCheckBase:
    """Test SecurityCheck base class uncovered lines."""

    def test_send_event_no_event_bus(self) -> None:
        """Test send_event when event_bus is None."""
        guard = Mock()
        guard.config = Mock()
        guard.config.passive_mode = False
        guard.logger = Mock()
        guard.event_bus = None  # No event bus

        from flaskapi_guard.core.checks.base import SecurityCheck

        class TestCheck(SecurityCheck):
            def check(self, request: Request) -> Response | None:
                return None

            @property
            def check_name(self) -> str:
                return "test"

        check = TestCheck(guard)
        mock_request = Mock(spec=Request)
        # Should not raise - just return early
        check.send_event("test", mock_request, "blocked", "reason")


class TestBehavioralProcessorEndpointId:
    """Test BehavioralProcessor endpoint ID generation."""

    def test_get_endpoint_id_no_endpoint(self) -> None:
        """Test get_endpoint_id when request.endpoint is None."""
        from flaskapi_guard.core.behavioral.context import BehavioralContext
        from flaskapi_guard.core.behavioral.processor import BehavioralProcessor

        context = BehavioralContext(
            config=Mock(),
            logger=Mock(),
            event_bus=Mock(),
            guard_decorator=Mock(),
        )
        processor = BehavioralProcessor(context)

        request = Mock(spec=Request)
        request.method = "GET"
        request.path = "/api/test"
        request.endpoint = None

        endpoint_id = processor.get_endpoint_id(request)
        assert endpoint_id == "GET:/api/test"


class TestEventBusGeoIPException:
    """Test SecurityEventBus geo IP exception handling."""

    def test_send_middleware_event_with_geo_ip_exception(self) -> None:
        """Test middleware event when geo IP lookup raises exception."""
        import sys

        config = SecurityConfig()
        config.agent_enable_events = True

        mock_agent = Mock()
        mock_agent.send_event = MagicMock()

        mock_geo_ip = Mock()
        geo_exception = Exception("GeoIP failure")
        mock_geo_ip.get_country = Mock(side_effect=geo_exception)

        event_bus = SecurityEventBus(mock_agent, config, mock_geo_ip)

        mock_request = Mock(spec=Request)
        mock_request.remote_addr = "192.168.1.1"
        mock_request.path = "/test"
        mock_request.method = "GET"
        mock_request.headers = {"User-Agent": "TestAgent"}

        # Mock the guard_agent module so SecurityEvent import succeeds
        mock_guard_agent = MagicMock()
        mock_event_class = MagicMock()
        mock_guard_agent.SecurityEvent = mock_event_class
        sys.modules["guard_agent"] = mock_guard_agent

        try:
            # Should not raise exception, just log and continue
            # Use a valid event_type from the SecurityEvent enum
            event_bus.send_middleware_event(
                event_type="suspicious_request",  # Valid event type
                request=mock_request,
                action_taken="logged",
                reason="test reason",
            )

            # Verify event was still sent without country
            assert mock_agent.send_event.call_count == 1
        finally:
            if "guard_agent" in sys.modules:
                del sys.modules["guard_agent"]


def test_integration_all_edge_cases() -> None:
    """Integration test to ensure all edge cases work together."""
    from datetime import datetime, timezone

    # This test ensures that the combination of all edge cases doesn't cause issues
    config = SecurityConfig()
    config.enable_redis = False
    config.enable_agent = False
    config.enable_dynamic_rules = False

    # Test DynamicRuleManager
    drm = DynamicRuleManager(config)
    from flaskapi_guard.models import DynamicRules

    rules = DynamicRules(
        rule_id="test", version=1, timestamp=datetime.now(timezone.utc)
    )
    drm._send_rule_received_event(rules)

    # Test RateLimitManager
    rlm = RateLimitManager(config)
    rlm.redis_handler = None  # Ensure no Redis handler for this test
    result = rlm._get_redis_request_count("127.0.0.1", 1000.0, 900.0)
    assert result is None

    # Test SecurityHeadersManager
    shm = SecurityHeadersManager()
    shm.cors_config = None
    methods, headers = shm._get_validated_cors_config()
    assert methods == ["GET", "POST"]
    assert headers == ["*"]

    # Test SusPatternsManager
    spm = SusPatternsManager()
    result = spm._remove_default_pattern("nonexistent")
    assert result is False
