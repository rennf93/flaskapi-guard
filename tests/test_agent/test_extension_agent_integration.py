# tests/test_agent/test_extension_agent_integration.py
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, Request, Response

from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.models import SecurityConfig


class TestExtensionAgentIntegration:
    """Test agent integration within FlaskAPIGuard."""

    def test_agent_initialization_success(self, config: SecurityConfig) -> None:
        """Test successful agent initialization in extension."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)

        assert guard.agent_handler is not None

    def test_agent_initialization_import_error(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        """Test agent initialization when guard_agent not installed."""
        caplog.set_level("INFO", logger="flaskapi_guard")

        # Temporarily remove guard_agent from sys.modules
        import sys

        guard_agent_backup = sys.modules.pop("guard_agent", None)
        guard_models_backup = sys.modules.pop("guard_agent.models", None)

        try:
            # Mock the import to raise ImportError when guard_agent is imported
            import builtins

            original_import = builtins.__import__

            def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
                if name == "guard_agent":
                    raise ImportError("No module named 'guard_agent'")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                app = Flask(__name__)
                guard = FlaskAPIGuard(app, config=config)

                # Verify warning logged and agent_handler is None
                assert guard.agent_handler is None
                # The ImportError happens in to_agent_config() which returns None
                # So the extension logs "invalid configuration"
                assert "Agent enabled but configuration is invalid" in caplog.text
        finally:
            # Restore modules
            if guard_agent_backup:
                sys.modules["guard_agent"] = guard_agent_backup
            if guard_models_backup:
                sys.modules["guard_agent.models"] = guard_models_backup

    def test_extension_import_error_handler(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        """Test extension's own ImportError handler when guard_agent import fails."""
        caplog.set_level("INFO", logger="flaskapi_guard")

        # AgentConfig object to bypass to_agent_config's ImportError handling
        mock_agent_config = MagicMock()

        # Patch to_agent_config at the class level to return a valid AgentConfig object
        # This ensures we reach the extension's try-except block
        with patch.object(
            SecurityConfig, "to_agent_config", return_value=mock_agent_config
        ):
            # Now mock the import to fail when extension tries to import guard_agent
            import builtins

            original_import = builtins.__import__

            def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
                if name == "guard_agent":
                    raise ImportError("No module named 'guard_agent'")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                app = Flask(__name__)
                guard = FlaskAPIGuard(app, config=config)

                # Verify the extension's ImportError handler was triggered
                assert guard.agent_handler is None
                warning_msg = "Agent enabled but guard_agent package not installed"
                assert warning_msg in caplog.text
                assert "Install with: pip install fastapi-guard-agent" in caplog.text

    def test_agent_initialization_exception(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        """Test agent initialization with general exception."""
        caplog.set_level("INFO", logger="flaskapi_guard")

        # Mock the guard_agent function to raise an exception
        mock_guard_agent = MagicMock(side_effect=Exception("Connection failed"))

        with patch.dict(
            "sys.modules",
            {"guard_agent": MagicMock(guard_agent=mock_guard_agent)},
        ):
            app = Flask(__name__)
            guard = FlaskAPIGuard(app, config=config)

            # Verify error logged and agent_handler is None
            assert guard.agent_handler is None
            assert "Failed to initialize Guard Agent" in caplog.text

    def test_agent_initialization_invalid_config(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test agent initialization with invalid config."""
        # Create config with agent disabled (simulates invalid config)
        invalid_config = SecurityConfig(enable_agent=False)

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=invalid_config)

        # Should not initialize agent when disabled
        assert guard.agent_handler is None

    def test_agent_disabled(self, config: SecurityConfig) -> None:
        """Test that agent is not initialized when disabled."""
        config = SecurityConfig(enable_agent=False)

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)

        # Agent should not be initialized
        assert guard.agent_handler is None

    def test_send_middleware_event_success(self, config: SecurityConfig) -> None:
        """Test successful event sending."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        # Mock request
        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-agent"}
        request.remote_addr = "192.168.1.100"

        # Mock extract_client_ip
        with patch(
            "flaskapi_guard.extension.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            guard.event_bus.send_middleware_event(
                "decorator_violation", request, "blocked", "test reason", extra="data"
            )

            # Verify event was sent to agent handler
            guard.agent_handler.send_event.assert_called_once()

    def test_send_middleware_event_disabled(self) -> None:
        """Test event not sent when disabled."""
        # Create config with events disabled
        config = SecurityConfig(
            enable_agent=True, agent_api_key="test-api-key", agent_enable_events=False
        )

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        request = MagicMock(spec=Request)

        guard.event_bus.send_middleware_event(
            "decorator_violation", request, "blocked", "test reason"
        )

        # Should not send event
        guard.agent_handler.send_event.assert_not_called()

    def test_send_middleware_event_no_agent(self, config: SecurityConfig) -> None:
        """Test event sending without agent handler."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = None  # No agent

        request = MagicMock(spec=Request)

        # Should not raise any errors
        guard.event_bus.send_middleware_event(
            "decorator_violation", request, "blocked", "test reason"
        )

    def test_send_middleware_event_with_geo_handler(
        self, config: SecurityConfig
    ) -> None:
        """Test event sending with geo IP handler."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        # Mock geo IP handler
        mock_geo_handler = MagicMock()
        mock_geo_handler.get_country.return_value = "US"
        guard.geo_ip_handler = mock_geo_handler
        # Update event_bus geo_ip_handler reference
        guard.event_bus.geo_ip_handler = mock_geo_handler

        # Mock request
        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "POST"
        request.headers = {"User-Agent": "test-agent"}
        request.remote_addr = "192.168.1.100"

        # Mock extract_client_ip
        with patch(
            "flaskapi_guard.extension.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            guard.event_bus.send_middleware_event(
                "country_blocked", request, "allowed", "from US"
            )

            # Verify event was sent to agent handler
            guard.agent_handler.send_event.assert_called_once()

            # Verify the event was created with the correct data
            sent_event = guard.agent_handler.send_event.call_args[0][0]
            assert sent_event.country == "US"
            assert sent_event.ip_address == "192.168.1.100"

    def test_send_middleware_event_geo_handler_failure(
        self, config: SecurityConfig
    ) -> None:
        """Test event sending when geo handler fails."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        # Mock geo IP handler that raises exception
        mock_geo_handler = MagicMock()
        mock_geo_handler.get_country.side_effect = Exception("Geo lookup failed")
        guard.geo_ip_handler = mock_geo_handler

        # Mock request
        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-agent"}
        request.remote_addr = "192.168.1.100"

        # Mock extract_client_ip
        with patch(
            "flaskapi_guard.extension.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            guard.event_bus.send_middleware_event(
                "decorator_violation", request, "blocked", "test reason"
            )

            # Verify event was sent to agent handler
            guard.agent_handler.send_event.assert_called_once()

            # Verify the event was created without country
            sent_event = guard.agent_handler.send_event.call_args[0][0]
            assert sent_event.country is None
            assert sent_event.ip_address == "192.168.1.100"

    def test_send_middleware_event_agent_failure(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        """Test event sending when agent fails."""
        caplog.set_level("INFO", logger="flaskapi_guard")

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.agent_handler.send_event.side_effect = Exception("Network error")

        # Mock request
        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-agent"}

        # Mock extract_client_ip
        with patch(
            "flaskapi_guard.extension.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            guard.event_bus.send_middleware_event(
                "decorator_violation", request, "blocked", "test reason"
            )

            # Should log error but not raise
            assert "Failed to send security event to agent" in caplog.text

    def test_send_security_metric_success(self, config: SecurityConfig) -> None:
        """Test successful metric sending."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        guard.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        # Verify metric was sent to agent handler
        guard.agent_handler.send_metric.assert_called_once()

        # Verify the metric was created with the correct data
        sent_metric = guard.agent_handler.send_metric.call_args[0][0]
        assert sent_metric.metric_type == "response_time"
        assert sent_metric.value == 123.45
        assert sent_metric.tags == {"endpoint": "/api/test"}

    def test_send_security_metric_disabled(self) -> None:
        """Test metric not sent when disabled."""
        # Create config with metrics disabled
        config = SecurityConfig(
            enable_agent=True, agent_api_key="test-api-key", agent_enable_metrics=False
        )

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        guard.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        # Should not send metric
        guard.agent_handler.send_metric.assert_not_called()

    def test_send_security_metric_no_agent(self, config: SecurityConfig) -> None:
        """Test metric sending without agent."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = None  # No agent

        # Should not raise any errors
        guard.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

    def test_send_security_metric_agent_failure(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        """Test metric sending when agent fails."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler
        guard.agent_handler.send_metric.side_effect = Exception("Network error")

        guard.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        # Should log error but not raise
        assert "Failed to send metric to agent" in caplog.text

    def test_send_security_metric_no_tags(self, config: SecurityConfig) -> None:
        """Test metric sending without tags."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        guard.metrics_collector.send_metric("request_count", 1.0)

        # Verify metric was sent to agent handler
        guard.agent_handler.send_metric.assert_called_once()

        # Verify the metric was created with empty tags
        sent_metric = guard.agent_handler.send_metric.call_args[0][0]
        assert sent_metric.tags == {}

    def test_collect_request_metrics(self, config: SecurityConfig) -> None:
        """Test request metrics collection."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"

        # Mock send_metric
        with patch.object(
            guard.metrics_collector, "send_metric", MagicMock()
        ) as mock_send:
            guard.metrics_collector.collect_request_metrics(request, 50.5, 200)

            # Should send response_time and request_count metrics
            assert mock_send.call_count == 2

            # Check response_time metric
            mock_send.assert_any_call(
                "response_time",
                50.5,
                {"endpoint": "/api/test", "method": "GET", "status": "200"},
            )

            # Check request_count metric
            mock_send.assert_any_call(
                "request_count", 1.0, {"endpoint": "/api/test", "method": "GET"}
            )

    def test_collect_request_metrics_disabled(self) -> None:
        """Test request metrics not collected when disabled."""
        # Create config with metrics disabled
        config = SecurityConfig(
            enable_agent=True, agent_api_key="test-api-key", agent_enable_metrics=False
        )

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"

        # Should return early without sending metrics
        guard.metrics_collector.collect_request_metrics(request, 50.5, 200)

        # No metrics should be sent
        guard.agent_handler.send_metric.assert_not_called()

    def test_collect_request_metrics_no_agent(self, config: SecurityConfig) -> None:
        """Test request metrics collection without agent."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = None  # No agent

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"

        # Should not raise any errors
        guard.metrics_collector.collect_request_metrics(request, 50.5, 200)

    def test_collect_request_metrics_different_status_codes(
        self, config: SecurityConfig
    ) -> None:
        """Test request metrics with different status codes."""
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        request = MagicMock(spec=Request)
        request.path = "/api/secure"
        request.method = "POST"

        # Mock send_metric
        with patch.object(
            guard.metrics_collector, "send_metric", MagicMock()
        ) as mock_send:
            # Test with 403 status
            guard.metrics_collector.collect_request_metrics(request, 25.3, 403)

            # Check response_time metric with 403 status
            mock_send.assert_any_call(
                "response_time",
                25.3,
                {"endpoint": "/api/secure", "method": "POST", "status": "403"},
            )

            # Test with 500 status
            guard.metrics_collector.collect_request_metrics(request, 100.2, 500)

            # Check response_time metric with 500 status
            mock_send.assert_any_call(
                "response_time",
                100.2,
                {"endpoint": "/api/secure", "method": "POST", "status": "500"},
            )

    def test_agent_init_invalid_config_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Test warning when agent enabled but config is invalid"""
        caplog.set_level("INFO", logger="flaskapi_guard")

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",  # Valid key to pass validation
        )

        # Mock to_agent_config to return None to simulate invalid config
        with patch.object(SecurityConfig, "to_agent_config", return_value=None):
            app = Flask(__name__)
            guard = FlaskAPIGuard(app, config=config)

        # Check warning was logged
        assert "Agent enabled but configuration is invalid" in caplog.text
        assert guard.agent_handler is None

    def test_emergency_mode_block_with_event(self, config: SecurityConfig) -> None:
        """Test emergency mode blocks non-whitelisted IPs and sends event"""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            emergency_mode=True,
            emergency_whitelist=["192.168.1.1"],
        )

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        with app.test_client() as client:
            response = client.get("/test", environ_base={"REMOTE_ADDR": "10.0.0.1"})

        assert response.status_code == 503
        guard.agent_handler.send_event.assert_called_once()
        event = guard.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "emergency_mode_block"
        assert event.action_taken == "request_blocked"

    def test_emergency_mode_allow_whitelist_with_logging(
        self,
    ) -> None:
        """Test emergency mode allows whitelisted IPs with logging"""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            emergency_mode=True,
            emergency_whitelist=["192.168.1.1"],
        )

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"

        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        with (
            patch("flaskapi_guard.utils.log_activity", MagicMock()),
            patch(
                "flaskapi_guard.core.checks.helpers.detect_penetration_attempt",
                MagicMock(return_value=(False, "")),
            ),
        ):
            with app.test_client() as client:
                response = client.get(
                    "/test", environ_base={"REMOTE_ADDR": "192.168.1.1"}
                )

        # Verify request was allowed (not blocked)
        assert response.status_code == 200

    def test_generic_auth_requirement_failure(self) -> None:
        """Test generic auth requirement without header"""

        route_config = RouteConfig()
        route_config.auth_required = "custom"

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        with patch.object(
            guard.route_resolver, "get_route_config", return_value=route_config
        ):
            with app.test_client() as client:
                response = client.get("/test")

        assert response.status_code == 401
        guard.agent_handler.send_event.assert_called_once()
        event = guard.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert "Missing custom authentication" in event.reason

    def test_missing_referrer_with_event(self) -> None:
        """Test missing referrer header sends decorator violation event"""

        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        with patch.object(
            guard.route_resolver, "get_route_config", return_value=route_config
        ):
            with app.test_client() as client:
                response = client.get("/test")

        assert response.status_code == 403
        guard.agent_handler.send_event.assert_called_once()
        event = guard.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "require_referrer"

    def test_referrer_parsing_exception(self) -> None:
        """Test referrer parsing exception handling"""

        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        guard.agent_handler = MagicMock()

        with patch.object(
            guard.route_resolver, "get_route_config", return_value=route_config
        ):
            with patch("urllib.parse.urlparse", side_effect=Exception("Parse error")):
                with app.test_client() as client:
                    response = client.get("/test", headers={"Referer": "invalid://url"})

        assert response.status_code == 403

    def test_invalid_referrer_domain_with_event(self) -> None:
        """Test invalid referrer domain sends decorator violation event"""

        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        with patch.object(
            guard.route_resolver, "get_route_config", return_value=route_config
        ):
            with app.test_client() as client:
                response = client.get(
                    "/test", headers={"Referer": "https://evil.com/page"}
                )

        assert response.status_code == 403
        guard.agent_handler.send_event.assert_called_once()
        event = guard.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert "not in allowed domains" in event.reason

    def test_route_specific_user_agent_block_event(self) -> None:
        """Test route-specific user agent block sends decorator violation event"""

        route_config = RouteConfig()
        route_config.blocked_user_agents = ["BadBot"]

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(
            app, config=SecurityConfig(enable_agent=True, agent_api_key="test-key")
        )
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        with patch.object(
            guard.route_resolver, "get_route_config", return_value=route_config
        ):
            with app.test_client() as client:
                response = client.get("/test", headers={"User-Agent": "BadBot/1.0"})

        assert response.status_code == 403
        # Should send decorator violation event for route-specific block
        calls = guard.agent_handler.send_event.call_args_list
        assert len(calls) >= 1
        event = calls[0][0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "user_agent"

    def test_suspicious_detection_disabled_by_decorator(
        self, config: SecurityConfig
    ) -> None:
        """Test suspicious detection disabled by decorator sends event"""

        route_config = RouteConfig()
        route_config.enable_suspicious_detection = False

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_penetration_detection=True,  # Globally enabled
        )

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"

        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        with patch.object(
            guard.route_resolver, "get_route_config", return_value=route_config
        ):
            with app.test_client() as client:
                client.get("/test?cmd=rm%20-rf")

        # Should send decorator violation event for disabling detection
        guard.agent_handler.send_event.assert_called_once()
        event = guard.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "suspicious_detection_disabled"

    def test_dynamic_endpoint_rate_limiting(self) -> None:
        """Test dynamic endpoint-specific rate limiting"""
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
            endpoint_rate_limits={"/api/sensitive": (10, 60)},  # 10 req/60s
        )

        app = Flask(__name__)

        @app.route("/api/sensitive")
        def sensitive_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        # Mock redis_handler
        mock_redis_handler = MagicMock()
        guard.redis_handler = mock_redis_handler

        # Mock rate limit handler to simulate rate limit exceeded
        mock_rate_handler = MagicMock()
        mock_rate_handler.check_rate_limit = MagicMock(
            return_value=Response("Rate limit exceeded", status=429)
        )
        mock_rate_handler.initialize_redis = MagicMock()

        with (
            patch(
                "flaskapi_guard.core.checks.implementations.rate_limit.RateLimitManager",
                return_value=mock_rate_handler,
            ),
            patch(
                "flaskapi_guard.utils.extract_client_ip",
                MagicMock(return_value="127.0.0.1"),
            ),
            patch("flaskapi_guard.utils.log_activity", MagicMock()),
            patch(
                "flaskapi_guard.core.checks.helpers.detect_penetration_attempt",
                MagicMock(return_value=(False, "")),
            ),
        ):
            with app.test_client() as client:
                response = client.get("/api/sensitive")

        assert response.status_code == 429
        # Verify dynamic rule violation event was sent
        guard.agent_handler.send_event.assert_called_once()
        event = guard.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "dynamic_rule_violation"
        assert event.metadata["rule_type"] == "endpoint_rate_limit"
        assert event.metadata["endpoint"] == "/api/sensitive"
        assert event.metadata["rate_limit"] == 10
        assert event.metadata["window"] == 60

    def test_route_specific_rate_limit_exceeded_event(self) -> None:
        """Test route-specific rate limit exceeded sends event"""
        route_config = RouteConfig()
        route_config.rate_limit = 5
        route_config.rate_limit_window = 30

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
        )

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        # Mock redis_handler
        mock_redis_handler = MagicMock()
        guard.redis_handler = mock_redis_handler

        # Mock rate limit handler to simulate rate limit exceeded
        mock_rate_handler = MagicMock()
        mock_rate_handler.check_rate_limit = MagicMock(
            return_value=Response("Rate limit exceeded", status=429)
        )
        mock_rate_handler.initialize_redis = MagicMock()

        with (
            patch.object(
                guard.route_resolver, "get_route_config", return_value=route_config
            ),
            patch(
                "flaskapi_guard.core.checks.implementations.rate_limit.RateLimitManager",
                return_value=mock_rate_handler,
            ),
            patch(
                "flaskapi_guard.utils.extract_client_ip",
                MagicMock(return_value="127.0.0.1"),
            ),
            patch("flaskapi_guard.utils.log_activity", MagicMock()),
            patch(
                "flaskapi_guard.core.checks.helpers.detect_penetration_attempt",
                MagicMock(return_value=(False, "")),
            ),
        ):
            with app.test_client() as client:
                response = client.get("/test")

        assert response.status_code == 429
        # Verify decorator violation event was sent
        guard.agent_handler.send_event.assert_called_once()
        event = guard.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["decorator_type"] == "rate_limiting"
        assert event.metadata["violation_type"] == "rate_limit"
        assert event.metadata["rate_limit"] == 5
        assert event.metadata["window"] == 30

    def test_cloud_provider_detection_with_agent_event(
        self, config: SecurityConfig
    ) -> None:
        """Test cloud provider detection sends event through cloud handler."""
        config.block_cloud_providers = {"AWS", "GCP"}

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        # Mock cloud handler with agent support
        mock_cloud_handler = MagicMock()
        mock_cloud_handler.is_cloud_ip.return_value = True
        mock_cloud_handler.get_cloud_provider_details.return_value = (
            "aws",
            "3.0.0.0/8",
        )
        mock_cloud_handler.agent_handler = guard.agent_handler
        mock_cloud_handler.send_cloud_detection_event = MagicMock()
        mock_cloud_handler.refresh = MagicMock()

        # Mock time to trigger refresh
        mock_time = MagicMock()
        mock_time.time.return_value = 9999999999  # Far in the future

        with (
            patch(
                "flaskapi_guard.core.checks.implementations.cloud_provider.cloud_handler",
                mock_cloud_handler,
            ),
            patch(
                "flaskapi_guard.core.checks.implementations.cloud_ip_refresh.time",
                mock_time,
            ),
            patch(
                "flaskapi_guard.utils.extract_client_ip",
                MagicMock(return_value="3.3.3.3"),
            ),
            patch("flaskapi_guard.utils.log_activity", MagicMock()),
            patch(
                "flaskapi_guard.core.checks.helpers.detect_penetration_attempt",
                MagicMock(return_value=(False, "")),
            ),
        ):
            with app.test_client() as client:
                response = client.get(
                    "/test",
                    headers={"User-Agent": "Mozilla/5.0"},
                    environ_base={"REMOTE_ADDR": "3.3.3.3"},
                )

        assert response.status_code == 403
        # Verify cloud detection event was sent through cloud handler
        mock_cloud_handler.send_cloud_detection_event.assert_called_once_with(
            "3.3.3.3", "aws", "3.0.0.0/8", "request_blocked"
        )

    def test_initialize_with_agent_handler(self) -> None:
        """Test initialize() method with agent handler"""
        # Create a mock geo_ip_handler
        mock_geo_ip_handler = MagicMock()
        mock_geo_ip_handler.initialize_agent = MagicMock()
        mock_geo_ip_handler.initialize_redis = MagicMock()

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
            enable_dynamic_rules=True,
            block_cloud_providers={"AWS"},
            whitelist_countries=["US"],
            geo_ip_handler=mock_geo_ip_handler,
        )

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)

        # Create mocks for all components
        guard.agent_handler = MagicMock()
        # Update event_bus and metrics_collector agent_handler references
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler
        guard.redis_handler = MagicMock()
        # geo_ip_handler is already set from config
        guard.guard_decorator = MagicMock()
        guard.guard_decorator.initialize_agent = MagicMock()

        # Mock the entire initialize_agent_integrations to verify it's called
        mock_redis_init = MagicMock()
        mock_agent_init = MagicMock()

        with (
            patch.object(
                guard.handler_initializer,
                "initialize_redis_handlers",
                mock_redis_init,
            ),
            patch.object(
                guard.handler_initializer,
                "initialize_agent_integrations",
                mock_agent_init,
            ),
        ):
            guard.initialize()

        # Verify security pipeline was built
        assert guard.security_pipeline is not None

        # Verify Redis initialization was called
        mock_redis_init.assert_called_once()

        # Verify agent integration initialization was called
        mock_agent_init.assert_called_once()

        # Verify geo_ip_handler exists
        assert guard.geo_ip_handler is not None
