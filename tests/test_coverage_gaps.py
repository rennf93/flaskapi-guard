"""Tests covering remaining uncovered lines across the flaskapi_guard package."""

import ipaddress
import logging
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

from flask import Flask, Response, g

from flaskapi_guard.core.checks.helpers import (
    validate_auth_header,
)
from flaskapi_guard.core.checks.implementations.custom_request import CustomRequestCheck
from flaskapi_guard.core.checks.implementations.https_enforcement import (
    HttpsEnforcementCheck,
)
from flaskapi_guard.core.checks.implementations.rate_limit import RateLimitCheck
from flaskapi_guard.core.checks.implementations.suspicious_activity import (
    SuspiciousActivityCheck,
)
from flaskapi_guard.core.events.extension_events import SecurityEventBus
from flaskapi_guard.core.routing.resolver import RouteConfigResolver
from flaskapi_guard.decorators.base import (
    BaseSecurityDecorator,
    RouteConfig,
    get_route_decorator_config,
)
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from flaskapi_guard.handlers.cloud_handler import CloudManager
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager
from flaskapi_guard.models import SecurityConfig

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


class TestBaseSecurityDecoratorInitializeAgent:
    def test_initialize_agent_sets_handler_and_forwards_to_tracker(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
        )
        decorator = BaseSecurityDecorator(config)
        mock_agent = MagicMock()

        decorator.initialize_agent(mock_agent)

        assert decorator.agent_handler is mock_agent
        assert decorator.behavior_tracker.agent_handler is mock_agent


class TestGetRouteDecoratorConfigNoEndpoint:
    def test_returns_none_when_endpoint_is_none(self) -> None:
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True
        FlaskAPIGuard(app, config=config)

        decorator = BaseSecurityDecorator(config)

        with app.test_request_context("/nonexistent"):
            from flask import request as flask_request

            assert flask_request.endpoint is None
            result = get_route_decorator_config(flask_request, decorator)
            assert result is None


class TestExtensionAgentInitGenericException:
    def test_agent_init_generic_exception_logs_and_continues(self) -> None:
        app = Flask(__name__)
        app.config["TESTING"] = True

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
            agent_project_id="test-project",
        )

        mock_agent_config = MagicMock()
        with patch.object(
            SecurityConfig, "to_agent_config", return_value=mock_agent_config
        ):
            mock_module = MagicMock()
            mock_module.guard_agent.side_effect = RuntimeError("init failed")
            with patch.dict("sys.modules", {"guard_agent": mock_module}):
                guard = FlaskAPIGuard(app, config=config)
                assert guard.agent_handler is None
                guard.reset()


class TestExtensionPassthroughReturnsResponse:
    def test_passthrough_returns_early_response(self) -> None:
        app = Flask(__name__)
        app.config["TESTING"] = True

        config = SecurityConfig(
            enable_redis=False,
        )
        guard = FlaskAPIGuard(app, config=config)

        @app.route("/test")
        def test_route() -> dict[str, str]:
            return {"ok": True}

        passthrough_response = Response("passthrough", status=200)
        with patch.object(
            guard.bypass_handler,
            "handle_passthrough",
            return_value=passthrough_response,
        ):
            with app.test_client() as client:
                resp = client.get("/test")
                assert resp.data == b"passthrough"

        guard.reset()


class TestExtensionSecurityBypassReturnsResponse:
    def test_security_bypass_returns_early_response(self) -> None:
        app = Flask(__name__)
        app.config["TESTING"] = True

        config = SecurityConfig(
            enable_redis=False,
        )
        guard = FlaskAPIGuard(app, config=config)

        @app.route("/test")
        def test_route() -> dict[str, str]:
            return {"ok": True}

        bypass_response = Response("bypassed", status=200)
        with patch.object(
            guard.bypass_handler,
            "handle_security_bypass",
            return_value=bypass_response,
        ):
            with app.test_client() as client:
                resp = client.get("/test")
                assert resp.data == b"bypassed"

        guard.reset()


class TestExtensionProcessResponse:
    def test_process_response_delegates_to_factory(self) -> None:
        app = Flask(__name__)
        app.config["TESTING"] = True

        config = SecurityConfig(
            enable_redis=False,
        )
        guard = FlaskAPIGuard(app, config=config)

        with app.test_request_context("/test"):
            from flask import request as flask_request

            response = Response("test", status=200)
            result = guard._process_response(flask_request, response, 0.01, None)
            assert result is not None

        guard.reset()


class TestBehaviorTrackerInitializeAgent:
    def test_initialize_agent_sets_handler(self) -> None:
        config = SecurityConfig(enable_redis=False)
        tracker = BehaviorTracker(config)
        mock_agent = MagicMock()

        tracker.initialize_agent(mock_agent)

        assert tracker.agent_handler is mock_agent


class TestBehaviorTrackerApplyActionWithAgent:
    def test_apply_action_sends_event_to_agent(self) -> None:
        config = SecurityConfig(enable_redis=False)
        tracker = BehaviorTracker(config)
        mock_agent = MagicMock()
        tracker.agent_handler = mock_agent

        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            window=60,
            action="log",
        )

        with patch.object(tracker, "_send_behavior_event") as mock_send:
            tracker.apply_action(rule, "1.2.3.4", "/api/test", "threshold exceeded")
            mock_send.assert_called_once_with(
                event_type="behavioral_violation",
                ip_address="1.2.3.4",
                action_taken="log",
                reason="Behavioral rule violated: threshold exceeded",
                endpoint="/api/test",
                rule_type="usage",
                threshold=5,
                window=60,
            )

    def test_apply_action_passive_mode_sends_logged_only(self) -> None:
        config = SecurityConfig(enable_redis=False, passive_mode=True)
        tracker = BehaviorTracker(config)
        mock_agent = MagicMock()
        tracker.agent_handler = mock_agent

        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            window=60,
            action="ban",
        )

        with patch.object(tracker, "_send_behavior_event") as mock_send:
            tracker.apply_action(rule, "1.2.3.4", "/api/test", "threshold exceeded")
            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args
            assert call_kwargs.kwargs["action_taken"] == "logged_only"


class TestCloudHandlerInitializeAgent:
    def test_initialize_agent_sets_handler(self) -> None:
        manager = CloudManager()
        mock_agent = MagicMock()

        manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent


class TestCloudHandlerGetCloudProviderDetailsMatch:
    def test_get_cloud_provider_details_returns_match(self) -> None:
        manager = CloudManager()
        network = ipaddress.ip_network("10.0.0.0/8")
        manager.ip_ranges["AWS"] = {network}

        result = manager.get_cloud_provider_details("10.1.2.3")

        assert result is not None
        assert result[0] == "AWS"
        assert result[1] == "10.0.0.0/8"


class TestCloudHandlerGetCloudProviderDetailsInvalidIP:
    def test_get_cloud_provider_details_invalid_ip_returns_none(self) -> None:
        manager = CloudManager()
        manager.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

        result = manager.get_cloud_provider_details("not-an-ip")

        assert result is None


class TestIPInfoManagerInitializeAgent:
    def test_initialize_agent_sets_handler(self) -> None:
        manager = IPInfoManager(IPINFO_TOKEN, None)
        mock_agent = MagicMock()

        manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent


class TestIPInfoManagerDownloadFailureAgentEvent:
    def test_initialize_sends_agent_event_on_download_failure(self) -> None:
        tmp_path = Path("/tmp/test_ipinfo_agent_event")
        tmp_path.mkdir(parents=True, exist_ok=True)
        db_path = tmp_path / "test.mmdb"

        manager = IPInfoManager(IPINFO_TOKEN, db_path)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        if db_path.exists():
            db_path.unlink()

        with (
            patch.object(manager, "_is_db_outdated", return_value=True),
            patch.object(
                manager,
                "_download_database",
                side_effect=RuntimeError("download failed"),
            ),
            patch.object(manager, "_send_geo_event") as mock_send,
        ):
            manager.initialize()

            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args
            assert call_kwargs.kwargs["event_type"] == "geo_lookup_failed"
            assert call_kwargs.kwargs["action_taken"] == "database_download_failed"

        if db_path.exists():
            db_path.unlink()


class TestIPInfoManagerLookupFailureAgentEvent:
    def test_get_country_sends_agent_event_on_lookup_exception(self) -> None:
        manager = IPInfoManager(IPINFO_TOKEN, None)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        mock_reader = MagicMock()
        mock_reader.get.side_effect = RuntimeError("lookup error")
        manager.reader = mock_reader

        with patch.object(manager, "_send_geo_event") as mock_send:
            result = manager.get_country("1.2.3.4")

            assert result is None
            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args
            assert call_kwargs.kwargs["event_type"] == "geo_lookup_failed"
            assert call_kwargs.kwargs["action_taken"] == "lookup_failed"

    def test_get_country_silences_agent_errors_in_lookup(self) -> None:
        manager = IPInfoManager(IPINFO_TOKEN, None)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        mock_reader = MagicMock()
        mock_reader.get.side_effect = RuntimeError("lookup error")
        manager.reader = mock_reader

        with patch.object(
            manager,
            "_send_geo_event",
            side_effect=RuntimeError("agent send failed"),
        ):
            result = manager.get_country("1.2.3.4")
            assert result is None


class TestIPInfoManagerCheckCountryAccessAllowed:
    def test_check_country_access_allowed_country(self) -> None:
        manager = IPInfoManager(IPINFO_TOKEN, None)

        with patch.object(manager, "get_country", return_value="US"):
            allowed, country = manager.check_country_access(
                "1.2.3.4",
                blocked_countries=["CN", "RU"],
            )
            assert allowed is True
            assert country == "US"

    def test_check_country_access_allowed_with_whitelist(self) -> None:
        manager = IPInfoManager(IPINFO_TOKEN, None)

        with patch.object(manager, "get_country", return_value="US"):
            allowed, country = manager.check_country_access(
                "1.2.3.4",
                blocked_countries=[],
                whitelist_countries=["US", "CA"],
            )
            assert allowed is True
            assert country == "US"


class TestValidateAuthHeaderGenericType:
    def test_generic_auth_empty_header_returns_false(self) -> None:
        valid, msg = validate_auth_header("", "api_key")
        assert valid is False
        assert msg == "Missing api_key authentication"

    def test_generic_auth_nonempty_header_returns_true(self) -> None:
        valid, msg = validate_auth_header("SomeToken abc123", "custom")
        assert valid is True
        assert msg == ""


class TestGetDetectionDisabledReason:
    def test_disabled_by_decorator_reason(self) -> None:
        from flaskapi_guard.core.checks.helpers import _get_detection_disabled_reason

        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=True,
        )
        result = _get_detection_disabled_reason(config, route_specific_detection=False)
        assert result == "disabled_by_decorator"


class TestCustomRequestCheckNoResponseFactory:
    def test_custom_check_returns_response_when_no_factory(self) -> None:
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True

        custom_response = Response("blocked", status=403)

        config.custom_request_check = lambda req: custom_response

        guard = FlaskAPIGuard(app, config=config)
        guard.response_factory = None

        check = CustomRequestCheck(guard)

        with app.test_request_context("/test"):
            from flask import request as flask_request

            result = check.check(flask_request)
            assert result is not None
            assert result.status_code == 403

        guard.reset()


class TestHttpsEnforcementFallback:
    def test_https_redirect_fallback_when_no_response_factory(self) -> None:
        config = SecurityConfig(enable_redis=False, enforce_https=True)
        app = Flask(__name__)
        app.config["TESTING"] = True

        guard = FlaskAPIGuard(app, config=config)
        guard.response_factory = None

        check = HttpsEnforcementCheck(guard)

        with app.test_request_context("http://example.com/test"):
            from flask import request as flask_request

            result = check._create_https_redirect(flask_request)
            assert result.status_code == 301
            assert "https://example.com/test" in result.headers.get("Location", "")

        guard.reset()


class TestRateLimitEventBusNone:
    def test_send_rate_limit_event_returns_when_no_event_bus(self) -> None:
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True

        guard = FlaskAPIGuard(app, config=config)
        guard.event_bus = None

        check = RateLimitCheck(guard)

        with app.test_request_context("/test"):
            from flask import request as flask_request

            check._send_rate_limit_event(flask_request, "test_event", {})

        guard.reset()


class TestRateLimitEndpointSpecific:
    def test_endpoint_rate_limit_exceeded(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            endpoint_rate_limits={"/endpoint-cov-test": (1, 60)},
            rate_limit=100,
        )
        app = Flask(__name__)
        app.config["TESTING"] = True
        guard = FlaskAPIGuard(app, config=config)

        check = RateLimitCheck(guard)

        unique_ip = "172.16.200.1"

        with app.test_request_context("/endpoint-cov-test"):
            from flask import request as flask_request

            result1 = check._check_endpoint_rate_limit(
                flask_request, unique_ip, "/endpoint-cov-test"
            )
            assert result1 is None

            result2 = check._check_endpoint_rate_limit(
                flask_request, unique_ip, "/endpoint-cov-test"
            )
            assert result2 is not None
            assert result2.status_code == 429

        guard.reset()


class TestRateLimitHandlerNone:
    def test_global_rate_limit_returns_none_when_no_handler(self) -> None:
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True

        guard = FlaskAPIGuard(app, config=config)

        check = RateLimitCheck(guard)
        original = guard.rate_limit_handler
        guard.rate_limit_handler = None

        with app.test_request_context("/test"):
            from flask import request as flask_request

            result = check._check_global_rate_limit(flask_request, "1.2.3.4")
            assert result is None

        guard.rate_limit_handler = original
        guard.reset()


class TestRateLimitRouteSpecific:
    def test_route_rate_limit_exceeded(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            rate_limit=100,
        )
        app = Flask(__name__)
        app.config["TESTING"] = True

        guard = FlaskAPIGuard(app, config=config)

        route_config = RouteConfig()
        route_config.rate_limit = 1
        route_config.rate_limit_window = 60

        check = RateLimitCheck(guard)
        unique_ip = "172.16.201.1"

        with app.test_request_context("/route-cov-test"):
            from flask import request as flask_request

            result1 = check._check_route_rate_limit(
                flask_request, unique_ip, route_config
            )
            assert result1 is None

            result2 = check._check_route_rate_limit(
                flask_request, unique_ip, route_config
            )
            assert result2 is not None
            assert result2.status_code == 429

        guard.reset()


class TestSuspiciousActivityDisabledByDecorator:
    def test_detection_disabled_by_decorator_sends_event(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=True,
        )
        app = Flask(__name__)
        app.config["TESTING"] = True

        guard = FlaskAPIGuard(app, config=config)

        mock_event_bus = MagicMock()
        guard.event_bus = mock_event_bus

        check = SuspiciousActivityCheck(guard)

        route_config = RouteConfig()
        route_config.enable_suspicious_detection = False

        with app.test_request_context(
            "/test",
            method="GET",
            headers={"User-Agent": "test-agent"},
        ):
            from flask import request as flask_request

            g.client_ip = "1.2.3.4"
            g.route_config = route_config
            g.is_whitelisted = False

            result = check.check(flask_request)
            assert result is None

            mock_event_bus.send_middleware_event.assert_called_once()
            call_kwargs = mock_event_bus.send_middleware_event.call_args
            assert call_kwargs.kwargs["event_type"] == "decorator_violation"
            assert call_kwargs.kwargs["action_taken"] == "detection_disabled"

        guard.reset()


class TestSecurityEventBusException:
    def test_send_middleware_event_logs_error_on_exception(self) -> None:
        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
            agent_project_id="test-project",
            agent_enable_events=True,
        )
        app = Flask(__name__)
        app.config["TESTING"] = True

        mock_agent = MagicMock()
        mock_agent.send_event.side_effect = RuntimeError("agent error")

        event_bus = SecurityEventBus(
            agent_handler=mock_agent,
            config=config,
            geo_ip_handler=None,
        )

        with app.test_request_context(
            "/test",
            method="GET",
            headers={"User-Agent": "test-agent"},
        ):
            from flask import request as flask_request

            mock_guard_agent = MagicMock()
            with patch.dict("sys.modules", {"guard_agent": mock_guard_agent}):
                event_bus.send_middleware_event(
                    event_type="test_event",
                    request=flask_request,
                    action_taken="test_action",
                    reason="test reason",
                )


class TestRouteConfigResolverNonDictExtension:
    def test_get_guard_decorator_from_non_dict_extension(self) -> None:
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True

        mock_ext = MagicMock()
        decorator = BaseSecurityDecorator(config)
        mock_ext.guard_decorator = decorator

        from flaskapi_guard.core.routing.context import RoutingContext

        context = RoutingContext(
            config=config,
            logger=logging.getLogger("test"),
            guard_decorator=None,
        )
        resolver = RouteConfigResolver(context)

        with app.app_context():
            app.extensions["flaskapi_guard"] = mock_ext
            result = resolver.get_guard_decorator(app)
            assert result is decorator

            del app.extensions["flaskapi_guard"]


class TestRouteConfigResolverEndpointNone:
    def test_get_route_config_returns_none_for_no_endpoint(self) -> None:
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True

        decorator = BaseSecurityDecorator(config)

        from flaskapi_guard.core.routing.context import RoutingContext

        context = RoutingContext(
            config=config,
            logger=logging.getLogger("test"),
            guard_decorator=decorator,
        )
        resolver = RouteConfigResolver(context)

        with app.app_context():
            app.extensions["flaskapi_guard"] = {"guard_decorator": decorator}

            with app.test_request_context("/nonexistent"):
                from flask import request as flask_request

                assert flask_request.endpoint is None
                result = resolver.get_route_config(flask_request)
                assert result is None

            del app.extensions["flaskapi_guard"]


class TestReferrerCheckBlocking:
    def test_missing_referrer_blocks_request(self) -> None:
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True
        guard = FlaskAPIGuard(app, config=config)

        from flaskapi_guard.core.checks.implementations.referrer import ReferrerCheck

        check = ReferrerCheck(guard)

        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        with app.test_request_context("/test", headers={}):
            from flask import request as flask_request

            g.route_config = route_config

            result = check.check(flask_request)
            assert result is not None
            assert result.status_code == 403

        guard.reset()

    def test_invalid_referrer_blocks_request(self) -> None:
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True
        guard = FlaskAPIGuard(app, config=config)

        from flaskapi_guard.core.checks.implementations.referrer import ReferrerCheck

        check = ReferrerCheck(guard)

        route_config = RouteConfig()
        route_config.require_referrer = ["example.com"]

        with app.test_request_context(
            "/test",
            headers={"Referer": "https://evil.com/page"},
        ):
            from flask import request as flask_request

            g.route_config = route_config

            result = check.check(flask_request)
            assert result is not None
            assert result.status_code == 403

        guard.reset()


class TestRateLimitCheckFlowReturns:
    def test_check_returns_endpoint_rate_limit_response(self) -> None:
        config = SecurityConfig(enable_redis=False, rate_limit=1000)
        app = Flask(__name__)
        app.config["TESTING"] = True
        guard = FlaskAPIGuard(app, config=config)

        check = RateLimitCheck(guard)
        mock_response = Response("rate limited", status=429)

        with app.test_request_context("/rl-check-flow-220"):
            from flask import request as flask_request

            g.client_ip = "172.16.220.1"
            g.route_config = None
            g.is_whitelisted = False

            with patch.object(
                check, "_check_endpoint_rate_limit", return_value=mock_response
            ):
                result = check.check(flask_request)
                assert result is mock_response
                assert result.status_code == 429

        guard.reset()

    def test_check_returns_route_rate_limit_response(self) -> None:
        config = SecurityConfig(enable_redis=False, rate_limit=1000)
        app = Flask(__name__)
        app.config["TESTING"] = True
        guard = FlaskAPIGuard(app, config=config)

        check = RateLimitCheck(guard)
        mock_response = Response("rate limited", status=429)

        with app.test_request_context("/rl-route-flow-224"):
            from flask import request as flask_request

            g.client_ip = "172.16.224.1"
            g.route_config = RouteConfig()
            g.is_whitelisted = False

            with (
                patch.object(check, "_check_endpoint_rate_limit", return_value=None),
                patch.object(
                    check, "_check_route_rate_limit", return_value=mock_response
                ),
            ):
                result = check.check(flask_request)
                assert result is mock_response
                assert result.status_code == 429

        guard.reset()
