from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, Request, Response

from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.models import SecurityConfig


class TestExtensionAgentIntegration:
    def test_agent_initialization_success(self, config: SecurityConfig) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)

        assert guard.agent_handler is not None

    def test_agent_initialization_import_error(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        caplog.set_level("INFO", logger="flaskapi_guard")

        import sys

        guard_agent_backup = sys.modules.pop("guard_agent", None)
        guard_models_backup = sys.modules.pop("guard_agent.models", None)

        try:
            import builtins

            original_import = builtins.__import__

            def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
                if name == "guard_agent":
                    raise ImportError("No module named 'guard_agent'")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                app = Flask(__name__)
                guard = FlaskAPIGuard(app, config=config)

                assert guard.agent_handler is None
                assert "Agent enabled but configuration is invalid" in caplog.text
        finally:
            if guard_agent_backup:
                sys.modules["guard_agent"] = guard_agent_backup
            if guard_models_backup:
                sys.modules["guard_agent.models"] = guard_models_backup

    def test_extension_import_error_handler(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        caplog.set_level("INFO", logger="flaskapi_guard")

        mock_agent_config = MagicMock()

        with patch.object(
            SecurityConfig, "to_agent_config", return_value=mock_agent_config
        ):
            import builtins

            original_import = builtins.__import__

            def mock_import(name: str, *args: Any, **kwargs: Any) -> Any:
                if name == "guard_agent":
                    raise ImportError("No module named 'guard_agent'")
                return original_import(name, *args, **kwargs)

            with patch("builtins.__import__", side_effect=mock_import):
                app = Flask(__name__)
                guard = FlaskAPIGuard(app, config=config)

                assert guard.agent_handler is None
                warning_msg = "Agent enabled but guard_agent package not installed"
                assert warning_msg in caplog.text
                assert "Install with: pip install fastapi-guard-agent" in caplog.text

    def test_agent_initialization_exception(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        caplog.set_level("INFO", logger="flaskapi_guard")

        mock_guard_agent = MagicMock(side_effect=Exception("Connection failed"))

        with patch.dict(
            "sys.modules",
            {"guard_agent": MagicMock(guard_agent=mock_guard_agent)},
        ):
            app = Flask(__name__)
            guard = FlaskAPIGuard(app, config=config)

            assert guard.agent_handler is None
            assert "Failed to initialize Guard Agent" in caplog.text

    def test_agent_initialization_invalid_config(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        invalid_config = SecurityConfig(enable_agent=False)

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=invalid_config)

        assert guard.agent_handler is None

    def test_agent_disabled(self, config: SecurityConfig) -> None:
        config = SecurityConfig(enable_agent=False)

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)

        assert guard.agent_handler is None

    def test_send_middleware_event_success(self, config: SecurityConfig) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-agent"}
        request.remote_addr = "192.168.1.100"

        with patch(
            "flaskapi_guard.extension.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            guard.event_bus.send_middleware_event(
                "decorator_violation", request, "blocked", "test reason", extra="data"
            )

            guard.agent_handler.send_event.assert_called_once()

    def test_send_middleware_event_disabled(self) -> None:
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

        guard.agent_handler.send_event.assert_not_called()

    def test_send_middleware_event_no_agent(self, config: SecurityConfig) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = None

        request = MagicMock(spec=Request)

        guard.event_bus.send_middleware_event(
            "decorator_violation", request, "blocked", "test reason"
        )

    def test_send_middleware_event_with_geo_handler(
        self, config: SecurityConfig
    ) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        mock_geo_handler = MagicMock()
        mock_geo_handler.get_country.return_value = "US"
        guard.geo_ip_handler = mock_geo_handler
        guard.event_bus.geo_ip_handler = mock_geo_handler

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "POST"
        request.headers = {"User-Agent": "test-agent"}
        request.remote_addr = "192.168.1.100"

        with patch(
            "flaskapi_guard.extension.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            guard.event_bus.send_middleware_event(
                "country_blocked", request, "allowed", "from US"
            )

            guard.agent_handler.send_event.assert_called_once()

            sent_event = guard.agent_handler.send_event.call_args[0][0]
            assert sent_event.country == "US"
            assert sent_event.ip_address == "192.168.1.100"

    def test_send_middleware_event_geo_handler_failure(
        self, config: SecurityConfig
    ) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        mock_geo_handler = MagicMock()
        mock_geo_handler.get_country.side_effect = Exception("Geo lookup failed")
        guard.geo_ip_handler = mock_geo_handler

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-agent"}
        request.remote_addr = "192.168.1.100"

        with patch(
            "flaskapi_guard.extension.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            guard.event_bus.send_middleware_event(
                "decorator_violation", request, "blocked", "test reason"
            )

            guard.agent_handler.send_event.assert_called_once()

            sent_event = guard.agent_handler.send_event.call_args[0][0]
            assert sent_event.country is None
            assert sent_event.ip_address == "192.168.1.100"

    def test_send_middleware_event_agent_failure(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        caplog.set_level("INFO", logger="flaskapi_guard")

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.agent_handler.send_event.side_effect = Exception("Network error")

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"
        request.headers = {"User-Agent": "test-agent"}

        with patch(
            "flaskapi_guard.extension.extract_client_ip",
            MagicMock(return_value="192.168.1.100"),
        ):
            guard.event_bus.send_middleware_event(
                "decorator_violation", request, "blocked", "test reason"
            )

            assert "Failed to send security event to agent" in caplog.text

    def test_send_security_metric_success(self, config: SecurityConfig) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        guard.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        guard.agent_handler.send_metric.assert_called_once()

        sent_metric = guard.agent_handler.send_metric.call_args[0][0]
        assert sent_metric.metric_type == "response_time"
        assert sent_metric.value == 123.45
        assert sent_metric.tags == {"endpoint": "/api/test"}

    def test_send_security_metric_disabled(self) -> None:
        config = SecurityConfig(
            enable_agent=True, agent_api_key="test-api-key", agent_enable_metrics=False
        )

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        guard.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        guard.agent_handler.send_metric.assert_not_called()

    def test_send_security_metric_no_agent(self, config: SecurityConfig) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = None

        guard.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

    def test_send_security_metric_agent_failure(
        self, caplog: pytest.LogCaptureFixture, config: SecurityConfig
    ) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler
        guard.agent_handler.send_metric.side_effect = Exception("Network error")

        guard.metrics_collector.send_metric(
            "response_time", 123.45, {"endpoint": "/api/test"}
        )

        assert "Failed to send metric to agent" in caplog.text

    def test_send_security_metric_no_tags(self, config: SecurityConfig) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        guard.metrics_collector.send_metric("request_count", 1.0)

        guard.agent_handler.send_metric.assert_called_once()

        sent_metric = guard.agent_handler.send_metric.call_args[0][0]
        assert sent_metric.tags == {}

    def test_collect_request_metrics(self, config: SecurityConfig) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"

        with patch.object(
            guard.metrics_collector, "send_metric", MagicMock()
        ) as mock_send:
            guard.metrics_collector.collect_request_metrics(request, 50.5, 200)

            assert mock_send.call_count == 2

            mock_send.assert_any_call(
                "response_time",
                50.5,
                {"endpoint": "/api/test", "method": "GET", "status": "200"},
            )

            mock_send.assert_any_call(
                "request_count", 1.0, {"endpoint": "/api/test", "method": "GET"}
            )

    def test_collect_request_metrics_disabled(self) -> None:
        config = SecurityConfig(
            enable_agent=True, agent_api_key="test-api-key", agent_enable_metrics=False
        )

        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"

        guard.metrics_collector.collect_request_metrics(request, 50.5, 200)

        guard.agent_handler.send_metric.assert_not_called()

    def test_collect_request_metrics_no_agent(self, config: SecurityConfig) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = None

        request = MagicMock(spec=Request)
        request.path = "/api/test"
        request.method = "GET"

        guard.metrics_collector.collect_request_metrics(request, 50.5, 200)

    def test_collect_request_metrics_different_status_codes(
        self, config: SecurityConfig
    ) -> None:
        app = Flask(__name__)
        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()

        request = MagicMock(spec=Request)
        request.path = "/api/secure"
        request.method = "POST"

        with patch.object(
            guard.metrics_collector, "send_metric", MagicMock()
        ) as mock_send:
            guard.metrics_collector.collect_request_metrics(request, 25.3, 403)

            mock_send.assert_any_call(
                "response_time",
                25.3,
                {"endpoint": "/api/secure", "method": "POST", "status": "403"},
            )

            guard.metrics_collector.collect_request_metrics(request, 100.2, 500)

            mock_send.assert_any_call(
                "response_time",
                100.2,
                {"endpoint": "/api/secure", "method": "POST", "status": "500"},
            )

    def test_agent_init_invalid_config_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level("INFO", logger="flaskapi_guard")

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
        )

        with patch.object(SecurityConfig, "to_agent_config", return_value=None):
            app = Flask(__name__)
            guard = FlaskAPIGuard(app, config=config)

        assert "Agent enabled but configuration is invalid" in caplog.text
        assert guard.agent_handler is None

    def test_emergency_mode_block_with_event(self, config: SecurityConfig) -> None:
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

        assert response.status_code == 200

    def test_generic_auth_requirement_failure(self) -> None:
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
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        with patch.object(
            guard.route_resolver, "get_route_config", return_value=route_config
        ):
            with app.test_client() as client:
                response = client.get("/test", headers={"User-Agent": "BadBot/1.0"})

        assert response.status_code == 403
        calls = guard.agent_handler.send_event.call_args_list
        assert len(calls) >= 1
        event = calls[0][0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "user_agent"

    def test_suspicious_detection_disabled_by_decorator(
        self, config: SecurityConfig
    ) -> None:
        route_config = RouteConfig()
        route_config.enable_suspicious_detection = False

        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_penetration_detection=True,
        )

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"

        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        with patch.object(
            guard.route_resolver, "get_route_config", return_value=route_config
        ):
            with app.test_client() as client:
                client.get("/test?cmd=rm%20-rf")

        guard.agent_handler.send_event.assert_called_once()
        event = guard.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decorator_violation"
        assert event.metadata["violation_type"] == "suspicious_detection_disabled"

    def test_dynamic_endpoint_rate_limiting(self) -> None:
        config = SecurityConfig(
            enable_agent=True,
            agent_api_key="test-key",
            enable_redis=True,
            redis_url="redis://localhost:6379",
            endpoint_rate_limits={"/api/sensitive": (10, 60)},
        )

        app = Flask(__name__)

        @app.route("/api/sensitive")
        def sensitive_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        mock_redis_handler = MagicMock()
        guard.redis_handler = mock_redis_handler

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
        guard.agent_handler.send_event.assert_called_once()
        event = guard.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "dynamic_rule_violation"
        assert event.metadata["rule_type"] == "endpoint_rate_limit"
        assert event.metadata["endpoint"] == "/api/sensitive"
        assert event.metadata["rate_limit"] == 10
        assert event.metadata["window"] == 60

    def test_route_specific_rate_limit_exceeded_event(self) -> None:
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
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        mock_redis_handler = MagicMock()
        guard.redis_handler = mock_redis_handler

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
        config.block_cloud_providers = {"AWS", "GCP"}

        app = Flask(__name__)

        @app.route("/test")
        def test_route() -> str:
            return "ok"  # pragma: no cover

        guard = FlaskAPIGuard(app, config=config)
        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler

        mock_cloud_handler = MagicMock()
        mock_cloud_handler.is_cloud_ip.return_value = True
        mock_cloud_handler.get_cloud_provider_details.return_value = (
            "aws",
            "3.0.0.0/8",
        )
        mock_cloud_handler.agent_handler = guard.agent_handler
        mock_cloud_handler.send_cloud_detection_event = MagicMock()
        mock_cloud_handler.refresh = MagicMock()

        mock_time = MagicMock()
        mock_time.time.return_value = 9999999999

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
        mock_cloud_handler.send_cloud_detection_event.assert_called_once_with(
            "3.3.3.3", "aws", "3.0.0.0/8", "request_blocked"
        )

    def test_initialize_with_agent_handler(self) -> None:
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

        guard.agent_handler = MagicMock()
        guard.event_bus.agent_handler = guard.agent_handler
        guard.metrics_collector.agent_handler = guard.agent_handler
        guard.redis_handler = MagicMock()
        guard.guard_decorator = MagicMock()
        guard.guard_decorator.initialize_agent = MagicMock()

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

        assert guard.security_pipeline is not None

        mock_redis_init.assert_called_once()

        mock_agent_init.assert_called_once()

        assert guard.geo_ip_handler is not None
