"""Tests covering remaining uncovered lines across the flaskapi_guard package.

Targets (Phase 1):
- flaskapi_guard/decorators/base.py: lines 96-98, 223
- flaskapi_guard/extension.py: lines 126-128, 362, 375, 482-485
- flaskapi_guard/handlers/behavior_handler.py: lines 64, 358
- flaskapi_guard/handlers/cloud_handler.py: lines 138, 218-219, 221-223
- flaskapi_guard/handlers/ipinfo_handler.py: lines 52, 76, 172-181, 234

Targets (Phase 2):
- flaskapi_guard/core/checks/helpers.py: lines 224-225, 299
- flaskapi_guard/core/checks/implementations/custom_request.py: line 43
- flaskapi_guard/core/checks/implementations/https_enforcement.py: lines 60-61
- flaskapi_guard/core/checks/implementations/rate_limit.py: lines 48, 89-90, 178, 220, 224
- flaskapi_guard/core/checks/implementations/suspicious_activity.py: lines 155-164
- flaskapi_guard/core/events/extension_events.py: lines 88-90
- flaskapi_guard/core/routing/resolver.py: lines 43, 69
"""

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


# ---------------------------------------------------------------------------
# decorators/base.py — lines 96-98: initialize_agent
# ---------------------------------------------------------------------------
class TestBaseSecurityDecoratorInitializeAgent:
    def test_initialize_agent_sets_handler_and_forwards_to_tracker(self) -> None:
        """Cover lines 96-98: initialize_agent sets agent_handler and
        calls behavior_tracker.initialize_agent."""
        config = SecurityConfig(
            enable_redis=False,
        )
        decorator = BaseSecurityDecorator(config)
        mock_agent = MagicMock()

        decorator.initialize_agent(mock_agent)

        assert decorator.agent_handler is mock_agent
        assert decorator.behavior_tracker.agent_handler is mock_agent


# ---------------------------------------------------------------------------
# decorators/base.py — line 223: get_route_decorator_config returns None
# when request.endpoint is None
# ---------------------------------------------------------------------------
class TestGetRouteDecoratorConfigNoEndpoint:
    def test_returns_none_when_endpoint_is_none(self) -> None:
        """Cover line 223: early return None when request.endpoint is None."""
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True
        FlaskAPIGuard(app, config=config)

        decorator = BaseSecurityDecorator(config)

        with app.test_request_context("/nonexistent"):
            from flask import request as flask_request

            # In a test_request_context without routing, endpoint is None
            assert flask_request.endpoint is None
            result = get_route_decorator_config(flask_request, decorator)
            assert result is None


# ---------------------------------------------------------------------------
# extension.py — lines 126-128: Generic exception during agent init
# ---------------------------------------------------------------------------
class TestExtensionAgentInitGenericException:
    def test_agent_init_generic_exception_logs_and_continues(self) -> None:
        """Cover lines 126-128: except Exception during agent initialization."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        config = SecurityConfig(
            enable_redis=False,
            enable_agent=True,
            agent_api_key="test-key",
            agent_project_id="test-project",
        )

        # Mock to_agent_config to return a truthy value
        mock_agent_config = MagicMock()
        with patch.object(
            SecurityConfig, "to_agent_config", return_value=mock_agent_config
        ):
            # Mock guard_agent import to raise a generic Exception
            mock_module = MagicMock()
            mock_module.guard_agent.side_effect = RuntimeError("init failed")
            with patch.dict("sys.modules", {"guard_agent": mock_module}):
                guard = FlaskAPIGuard(app, config=config)
                # Agent handler should be None since init failed
                assert guard.agent_handler is None
                guard.reset()


# ---------------------------------------------------------------------------
# extension.py — line 362: handle_passthrough returns non-None
# ---------------------------------------------------------------------------
class TestExtensionPassthroughReturnsResponse:
    def test_passthrough_returns_early_response(self) -> None:
        """Cover line 362: passthrough returning a non-None response."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        config = SecurityConfig(
            enable_redis=False,
        )
        guard = FlaskAPIGuard(app, config=config)

        @app.route("/test")
        def test_route() -> dict[str, str]:
            return {"ok": True}

        # Patch handle_passthrough to return a response
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


# ---------------------------------------------------------------------------
# extension.py — line 375: handle_security_bypass returns non-None
# ---------------------------------------------------------------------------
class TestExtensionSecurityBypassReturnsResponse:
    def test_security_bypass_returns_early_response(self) -> None:
        """Cover line 375: bypass handler returning a non-None response."""
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


# ---------------------------------------------------------------------------
# extension.py — lines 482-485: _process_response method body
# ---------------------------------------------------------------------------
class TestExtensionProcessResponse:
    def test_process_response_delegates_to_factory(self) -> None:
        """Cover lines 482-485: _process_response asserts and delegates."""
        app = Flask(__name__)
        app.config["TESTING"] = True

        config = SecurityConfig(
            enable_redis=False,
        )
        guard = FlaskAPIGuard(app, config=config)

        with app.test_request_context("/test"):
            from flask import request as flask_request

            response = Response("test", status=200)
            result = guard._process_response(
                flask_request, response, 0.01, None
            )
            assert result is not None

        guard.reset()


# ---------------------------------------------------------------------------
# behavior_handler.py — line 64: initialize_agent
# ---------------------------------------------------------------------------
class TestBehaviorTrackerInitializeAgent:
    def test_initialize_agent_sets_handler(self) -> None:
        """Cover line 64: BehaviorTracker.initialize_agent sets agent_handler."""
        config = SecurityConfig(enable_redis=False)
        tracker = BehaviorTracker(config)
        mock_agent = MagicMock()

        tracker.initialize_agent(mock_agent)

        assert tracker.agent_handler is mock_agent


# ---------------------------------------------------------------------------
# behavior_handler.py — line 358: apply_action sends event when agent set
# ---------------------------------------------------------------------------
class TestBehaviorTrackerApplyActionWithAgent:
    def test_apply_action_sends_event_to_agent(self) -> None:
        """Cover line 358: apply_action sends behavioral violation event
        when agent_handler is set."""
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

        # Mock _send_behavior_event to verify it's called
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
        """Cover line 358 passive_mode branch: action_taken is 'logged_only'."""
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


# ---------------------------------------------------------------------------
# cloud_handler.py — line 138: initialize_agent
# ---------------------------------------------------------------------------
class TestCloudHandlerInitializeAgent:
    def test_initialize_agent_sets_handler(self) -> None:
        """Cover line 138: CloudManager.initialize_agent sets agent_handler."""
        manager = CloudManager()
        mock_agent = MagicMock()

        manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent


# ---------------------------------------------------------------------------
# cloud_handler.py — lines 218-219: is_cloud_ip match found
# ---------------------------------------------------------------------------
class TestCloudHandlerGetCloudProviderDetailsMatch:
    def test_get_cloud_provider_details_returns_match(self) -> None:
        """Cover lines 218-219: get_cloud_provider_details returns
        (provider, network) when IP matches a cloud range."""
        manager = CloudManager()
        network = ipaddress.ip_network("10.0.0.0/8")
        manager.ip_ranges["AWS"] = {network}

        result = manager.get_cloud_provider_details("10.1.2.3")

        assert result is not None
        assert result[0] == "AWS"
        assert result[1] == "10.0.0.0/8"


# ---------------------------------------------------------------------------
# cloud_handler.py — lines 221-223: ValueError for invalid IP
# ---------------------------------------------------------------------------
class TestCloudHandlerGetCloudProviderDetailsInvalidIP:
    def test_get_cloud_provider_details_invalid_ip_returns_none(self) -> None:
        """Cover lines 221-223: ValueError when checking an invalid IP address."""
        manager = CloudManager()
        manager.ip_ranges["AWS"] = {ipaddress.ip_network("10.0.0.0/8")}

        result = manager.get_cloud_provider_details("not-an-ip")

        assert result is None


# ---------------------------------------------------------------------------
# ipinfo_handler.py — line 52: initialize_agent
# ---------------------------------------------------------------------------
class TestIPInfoManagerInitializeAgent:
    def test_initialize_agent_sets_handler(self) -> None:
        """Cover line 52: IPInfoManager.initialize_agent sets agent_handler."""
        manager = IPInfoManager(IPINFO_TOKEN, None)
        mock_agent = MagicMock()

        manager.initialize_agent(mock_agent)

        assert manager.agent_handler is mock_agent


# ---------------------------------------------------------------------------
# ipinfo_handler.py — line 76: agent event for database download failure
# ---------------------------------------------------------------------------
class TestIPInfoManagerDownloadFailureAgentEvent:
    def test_initialize_sends_agent_event_on_download_failure(self) -> None:
        """Cover line 76: agent event sent for database download failure."""
        tmp_path = Path("/tmp/test_ipinfo_agent_event")
        tmp_path.mkdir(parents=True, exist_ok=True)
        db_path = tmp_path / "test.mmdb"

        manager = IPInfoManager(IPINFO_TOKEN, db_path)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        # Make _download_database raise, and ensure no cached DB exists
        if db_path.exists():
            db_path.unlink()

        with patch.object(
            manager, "_is_db_outdated", return_value=True
        ), patch.object(
            manager, "_download_database", side_effect=RuntimeError("download failed")
        ), patch.object(
            manager, "_send_geo_event"
        ) as mock_send:
            manager.initialize()

            mock_send.assert_called_once()
            call_kwargs = mock_send.call_args
            assert call_kwargs.kwargs["event_type"] == "geo_lookup_failed"
            assert call_kwargs.kwargs["action_taken"] == "database_download_failed"

        # Cleanup
        if db_path.exists():
            db_path.unlink()


# ---------------------------------------------------------------------------
# ipinfo_handler.py — lines 172-181: agent event on geo lookup failure
# ---------------------------------------------------------------------------
class TestIPInfoManagerLookupFailureAgentEvent:
    def test_get_country_sends_agent_event_on_lookup_exception(self) -> None:
        """Cover lines 172-181: agent event sent when geo lookup fails,
        including the inner try/except that silences agent errors."""
        manager = IPInfoManager(IPINFO_TOKEN, None)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        # Set up a mock reader that raises on get()
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
        """Cover lines 179-181: inner except that silences agent errors."""
        manager = IPInfoManager(IPINFO_TOKEN, None)
        mock_agent = MagicMock()
        manager.agent_handler = mock_agent

        mock_reader = MagicMock()
        mock_reader.get.side_effect = RuntimeError("lookup error")
        manager.reader = mock_reader

        # Make _send_geo_event raise to exercise lines 179-181
        with patch.object(
            manager,
            "_send_geo_event",
            side_effect=RuntimeError("agent send failed"),
        ):
            result = manager.get_country("1.2.3.4")
            # Should return None without raising
            assert result is None


# ---------------------------------------------------------------------------
# ipinfo_handler.py — line 234: check_country_access returns (True, country)
# ---------------------------------------------------------------------------
class TestIPInfoManagerCheckCountryAccessAllowed:
    def test_check_country_access_allowed_country(self) -> None:
        """Cover line 234: check_country_access returns (True, country)
        when country is not blocked."""
        manager = IPInfoManager(IPINFO_TOKEN, None)

        # Mock get_country to return a non-blocked country
        with patch.object(manager, "get_country", return_value="US"):
            allowed, country = manager.check_country_access(
                "1.2.3.4",
                blocked_countries=["CN", "RU"],
            )
            assert allowed is True
            assert country == "US"

    def test_check_country_access_allowed_with_whitelist(self) -> None:
        """check_country_access returns (True, country) when country is
        in whitelist and not in blocklist."""
        manager = IPInfoManager(IPINFO_TOKEN, None)

        with patch.object(manager, "get_country", return_value="US"):
            allowed, country = manager.check_country_access(
                "1.2.3.4",
                blocked_countries=[],
                whitelist_countries=["US", "CA"],
            )
            assert allowed is True
            assert country == "US"


# ===========================================================================
# Phase 2: Core checks, events, and routing coverage gaps
# ===========================================================================


# ---------------------------------------------------------------------------
# helpers.py — lines 224-225: Generic auth type with empty header
# ---------------------------------------------------------------------------
class TestValidateAuthHeaderGenericType:
    def test_generic_auth_empty_header_returns_false(self) -> None:
        """Cover lines 224-225: generic auth type with empty auth_header."""
        valid, msg = validate_auth_header("", "api_key")
        assert valid is False
        assert msg == "Missing api_key authentication"

    def test_generic_auth_nonempty_header_returns_true(self) -> None:
        """Cover line 227: generic auth with non-empty header returns True."""
        valid, msg = validate_auth_header("SomeToken abc123", "custom")
        assert valid is True
        assert msg == ""


# ---------------------------------------------------------------------------
# helpers.py — line 299: _get_detection_disabled_reason returns
# "disabled_by_decorator"
# ---------------------------------------------------------------------------
class TestGetDetectionDisabledReason:
    def test_disabled_by_decorator_reason(self) -> None:
        """Cover line 299: disabled_by_decorator when route disables
        detection but global enables it."""
        from flaskapi_guard.core.checks.helpers import _get_detection_disabled_reason

        config = SecurityConfig(
            enable_redis=False,
            enable_penetration_detection=True,
        )
        result = _get_detection_disabled_reason(config, route_specific_detection=False)
        assert result == "disabled_by_decorator"


# ---------------------------------------------------------------------------
# custom_request.py — line 43: fallback when response_factory is None
# ---------------------------------------------------------------------------
class TestCustomRequestCheckNoResponseFactory:
    def test_custom_check_returns_response_when_no_factory(self) -> None:
        """Cover line 43: custom_request_check returns response directly
        when response_factory is None."""
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True

        custom_response = Response("blocked", status=403)

        config.custom_request_check = lambda req: custom_response

        guard = FlaskAPIGuard(app, config=config)
        # Force response_factory to None to exercise the fallback
        guard.response_factory = None

        check = CustomRequestCheck(guard)

        with app.test_request_context("/test"):
            from flask import request as flask_request

            result = check.check(flask_request)
            assert result is not None
            assert result.status_code == 403

        guard.reset()


# ---------------------------------------------------------------------------
# https_enforcement.py — lines 60-61: fallback HTTPS redirect
# ---------------------------------------------------------------------------
class TestHttpsEnforcementFallback:
    def test_https_redirect_fallback_when_no_response_factory(self) -> None:
        """Cover lines 60-61: fallback HTTPS redirect when response_factory
        is None."""
        config = SecurityConfig(enable_redis=False, enforce_https=True)
        app = Flask(__name__)
        app.config["TESTING"] = True

        guard = FlaskAPIGuard(app, config=config)
        # Force response_factory to None
        guard.response_factory = None

        check = HttpsEnforcementCheck(guard)

        with app.test_request_context("http://example.com/test"):
            from flask import request as flask_request

            result = check._create_https_redirect(flask_request)
            assert result.status_code == 301
            assert "https://example.com/test" in result.headers.get("Location", "")

        guard.reset()


# ---------------------------------------------------------------------------
# rate_limit.py — line 48: event_bus is None early return
# ---------------------------------------------------------------------------
class TestRateLimitEventBusNone:
    def test_send_rate_limit_event_returns_when_no_event_bus(self) -> None:
        """Cover line 48: _send_rate_limit_event returns early
        when event_bus is None."""
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True

        guard = FlaskAPIGuard(app, config=config)
        guard.event_bus = None

        check = RateLimitCheck(guard)

        with app.test_request_context("/test"):
            from flask import request as flask_request

            # Should not raise — just returns early
            check._send_rate_limit_event(flask_request, "test_event", {})

        guard.reset()


# ---------------------------------------------------------------------------
# rate_limit.py — lines 89-90: endpoint-specific rate limit match
# ---------------------------------------------------------------------------
class TestRateLimitEndpointSpecific:
    def test_endpoint_rate_limit_exceeded(self) -> None:
        """Cover lines 89-90, 220: endpoint-specific rate limit triggers.
        Uses _check_endpoint_rate_limit directly to avoid singleton state."""
        config = SecurityConfig(
            enable_redis=False,
            endpoint_rate_limits={"/endpoint-cov-test": (1, 60)},
            rate_limit=100,
        )
        app = Flask(__name__)
        app.config["TESTING"] = True
        guard = FlaskAPIGuard(app, config=config)

        check = RateLimitCheck(guard)

        # Use a unique IP to avoid singleton state conflicts
        unique_ip = "172.16.200.1"

        with app.test_request_context("/endpoint-cov-test"):
            from flask import request as flask_request

            # First call passes
            result1 = check._check_endpoint_rate_limit(
                flask_request, unique_ip, "/endpoint-cov-test"
            )
            assert result1 is None

            # Second call exceeds limit=1
            result2 = check._check_endpoint_rate_limit(
                flask_request, unique_ip, "/endpoint-cov-test"
            )
            assert result2 is not None
            assert result2.status_code == 429

        guard.reset()


# ---------------------------------------------------------------------------
# rate_limit.py — line 178: rate_limit_handler is None
# ---------------------------------------------------------------------------
class TestRateLimitHandlerNone:
    def test_global_rate_limit_returns_none_when_no_handler(self) -> None:
        """Cover line 178: _check_global_rate_limit returns None when
        rate_limit_handler is None."""
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True

        guard = FlaskAPIGuard(app, config=config)

        check = RateLimitCheck(guard)
        # Temporarily set rate_limit_handler to None on middleware
        original = guard.rate_limit_handler
        guard.rate_limit_handler = None

        with app.test_request_context("/test"):
            from flask import request as flask_request

            result = check._check_global_rate_limit(flask_request, "1.2.3.4")
            assert result is None

        guard.rate_limit_handler = original
        guard.reset()


# ---------------------------------------------------------------------------
# rate_limit.py — line 224: route-specific rate limit blocks request
# ---------------------------------------------------------------------------
class TestRateLimitRouteSpecific:
    def test_route_rate_limit_exceeded(self) -> None:
        """Cover line 224: route-specific rate limit triggers.
        Uses _check_route_rate_limit directly to avoid singleton state."""
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

            # First call should pass
            result1 = check._check_route_rate_limit(
                flask_request, unique_ip, route_config
            )
            assert result1 is None

            # Second call should be rate limited
            result2 = check._check_route_rate_limit(
                flask_request, unique_ip, route_config
            )
            assert result2 is not None
            assert result2.status_code == 429

        guard.reset()


# ---------------------------------------------------------------------------
# suspicious_activity.py — lines 155-164: disabled_by_decorator event
# ---------------------------------------------------------------------------
class TestSuspiciousActivityDisabledByDecorator:
    def test_detection_disabled_by_decorator_sends_event(self) -> None:
        """Cover lines 155-164: suspicious activity detection disabled
        by route decorator sends event."""
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


# ---------------------------------------------------------------------------
# extension_events.py — lines 88-90: Exception in send_middleware_event
# ---------------------------------------------------------------------------
class TestSecurityEventBusException:
    def test_send_middleware_event_logs_error_on_exception(self) -> None:
        """Cover lines 88-90: exception during agent event sending
        is caught and logged."""
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
        # Make send_event raise
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

            # Mock the guard_agent import so SecurityEvent can be created
            mock_guard_agent = MagicMock()
            with patch.dict("sys.modules", {"guard_agent": mock_guard_agent}):
                # Should not raise — error is caught and logged
                event_bus.send_middleware_event(
                    event_type="test_event",
                    request=flask_request,
                    action_taken="test_action",
                    reason="test reason",
                )


# ---------------------------------------------------------------------------
# resolver.py — line 43: non-dict flaskapi_guard extension
# ---------------------------------------------------------------------------
class TestRouteConfigResolverNonDictExtension:
    def test_get_guard_decorator_from_non_dict_extension(self) -> None:
        """Cover line 43: getattr branch when flaskapi_guard ext is not a dict."""
        config = SecurityConfig(enable_redis=False)
        app = Flask(__name__)
        app.config["TESTING"] = True

        # Store a non-dict object in extensions
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

            # Clean up
            del app.extensions["flaskapi_guard"]


# ---------------------------------------------------------------------------
# resolver.py — line 69: request.endpoint is None
# ---------------------------------------------------------------------------
class TestRouteConfigResolverEndpointNone:
    def test_get_route_config_returns_none_for_no_endpoint(self) -> None:
        """Cover line 69: get_route_config returns None when
        request.endpoint is None."""
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

        # Store decorator in extensions as dict
        with app.app_context():
            app.extensions["flaskapi_guard"] = {"guard_decorator": decorator}

            with app.test_request_context("/nonexistent"):
                from flask import request as flask_request

                assert flask_request.endpoint is None
                result = resolver.get_route_config(flask_request)
                assert result is None

            del app.extensions["flaskapi_guard"]


# ===========================================================================
# Phase 3: Final coverage gaps — referrer check and rate limit check() flow
# ===========================================================================


# ---------------------------------------------------------------------------
# referrer.py — lines 44, 79, 96, 100: referrer validation blocking
# ---------------------------------------------------------------------------
class TestReferrerCheckBlocking:
    def test_missing_referrer_blocks_request(self) -> None:
        """Cover lines 44, 96: missing referrer returns 403."""
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
        """Cover lines 79, 100: invalid referrer domain returns 403."""
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


# ---------------------------------------------------------------------------
# rate_limit.py — lines 220, 224: check() returning endpoint/route responses
# ---------------------------------------------------------------------------
class TestRateLimitCheckFlowReturns:
    def test_check_returns_endpoint_rate_limit_response(self) -> None:
        """Cover line 220: check() returns response from endpoint rate limit.
        Uses mock to make _check_endpoint_rate_limit return a response."""
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
        """Cover line 224: check() returns response from route rate limit.
        Uses mock to make _check_route_rate_limit return a response."""
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

            with patch.object(
                check, "_check_endpoint_rate_limit", return_value=None
            ), patch.object(
                check, "_check_route_rate_limit", return_value=mock_response
            ):
                result = check.check(flask_request)
                assert result is mock_response
                assert result.status_code == 429

        guard.reset()
