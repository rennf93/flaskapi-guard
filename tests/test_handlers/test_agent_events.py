# tests/test_handlers/test_agent_events.py
"""Tests for _send_*_event methods across ALL handlers using mocked guard_agent."""

import sys
import types
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from flaskapi_guard.models import SecurityConfig


class MockSecurityEvent:
    def __init__(self, **kwargs: object) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)


@pytest.fixture(autouse=True)
def _mock_guard_agent_module() -> types.ModuleType:
    """Ensure guard_agent mock module is in sys.modules for every test."""
    mock_mod = types.ModuleType("guard_agent")
    mock_mod.SecurityEvent = MockSecurityEvent  # type: ignore[attr-defined]
    original = sys.modules.get("guard_agent")
    sys.modules["guard_agent"] = mock_mod
    # Also set guard_agent.models so nested imports don't fail
    sys.modules["guard_agent.models"] = mock_mod
    yield mock_mod
    if original is not None:
        sys.modules["guard_agent"] = original
    else:
        sys.modules.pop("guard_agent", None)
    sys.modules.pop("guard_agent.models", None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides: object) -> SecurityConfig:
    """Create a minimal SecurityConfig with redis disabled."""
    defaults: dict[str, object] = {
        "enable_redis": False,
        "redis_url": None,
        "rate_limit": 100,
        "rate_limit_window": 60,
    }
    defaults.update(overrides)
    return SecurityConfig(**defaults)  # type: ignore[arg-type]


# =========================================================================
# IPBanManager events
# =========================================================================

class TestIPBanManagerEvents:
    """Tests for IPBanManager._send_ban_event and _send_unban_event."""

    def setup_method(self) -> None:
        from flaskapi_guard.handlers.ipban_handler import IPBanManager

        IPBanManager._instance = None
        self.manager = IPBanManager()
        self.manager.agent_handler = MagicMock()

    def teardown_method(self) -> None:
        from flaskapi_guard.handlers.ipban_handler import IPBanManager

        IPBanManager._instance = None

    def test_send_ban_event_sends_correct_event(self) -> None:
        self.manager._send_ban_event("10.0.0.1", 3600, "threshold_exceeded")
        self.manager.agent_handler.send_event.assert_called_once()
        event = self.manager.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "ip_banned"
        assert event.ip_address == "10.0.0.1"
        assert event.action_taken == "banned"
        assert event.reason == "threshold_exceeded"
        assert event.metadata == {"duration": 3600}

    def test_send_ban_event_no_agent(self) -> None:
        self.manager.agent_handler = None
        # _send_ban_event is only called when agent_handler is set (from ban_ip),
        # but calling directly should not raise
        self.manager._send_ban_event("10.0.0.1", 3600, "test")

    def test_send_ban_event_exception_handled(self) -> None:
        self.manager.agent_handler.send_event.side_effect = Exception("agent down")
        # Should not raise
        self.manager._send_ban_event("10.0.0.1", 3600, "test")

    def test_send_unban_event_sends_correct_event(self) -> None:
        self.manager._send_unban_event("10.0.0.2")
        self.manager.agent_handler.send_event.assert_called_once()
        event = self.manager.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "ip_unbanned"
        assert event.ip_address == "10.0.0.2"
        assert event.action_taken == "unbanned"
        assert event.reason == "dynamic_rule_whitelist"

    def test_send_unban_event_exception_handled(self) -> None:
        self.manager.agent_handler.send_event.side_effect = Exception("agent down")
        self.manager._send_unban_event("10.0.0.2")


# =========================================================================
# RedisManager events
# =========================================================================

class TestRedisManagerEvents:
    """Tests for RedisManager._send_redis_event."""

    def setup_method(self) -> None:
        from flaskapi_guard.handlers.redis_handler import RedisManager

        RedisManager._instance = None
        config = _make_config()
        self.manager = RedisManager(config)
        self.manager.agent_handler = MagicMock()

    def teardown_method(self) -> None:
        from flaskapi_guard.handlers.redis_handler import RedisManager

        RedisManager._instance = None

    def test_send_redis_event_sends_correct_event(self) -> None:
        self.manager._send_redis_event(
            "redis_connection", "connection_established", "connected", foo="bar"
        )
        self.manager.agent_handler.send_event.assert_called_once()
        event = self.manager.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "redis_connection"
        assert event.ip_address == "system"
        assert event.action_taken == "connection_established"
        assert event.reason == "connected"
        assert event.metadata == {"foo": "bar"}

    def test_send_redis_event_no_agent(self) -> None:
        self.manager.agent_handler = None
        # Should return early without error
        self.manager._send_redis_event("redis_connection", "test", "test")

    def test_send_redis_event_exception_handled(self) -> None:
        self.manager.agent_handler.send_event.side_effect = Exception("agent down")
        self.manager._send_redis_event("redis_error", "failed", "reason")


# =========================================================================
# RateLimitManager events
# =========================================================================

class TestRateLimitManagerEvents:
    """Tests for RateLimitManager._send_rate_limit_event."""

    def setup_method(self) -> None:
        from flaskapi_guard.handlers.ratelimit_handler import RateLimitManager

        RateLimitManager._instance = None
        config = _make_config()
        self.manager = RateLimitManager(config)
        self.manager.agent_handler = MagicMock()
        self.app = Flask(__name__)

    def teardown_method(self) -> None:
        from flaskapi_guard.handlers.ratelimit_handler import RateLimitManager

        RateLimitManager._instance = None

    def test_send_rate_limit_event_sends_correct_event(self) -> None:
        with self.app.test_request_context("/api/test", method="POST"):
            from flask import request

            self.manager._send_rate_limit_event(request, "192.168.1.1", 150)
        self.manager.agent_handler.send_event.assert_called_once()
        event = self.manager.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "rate_limited"
        assert event.ip_address == "192.168.1.1"
        assert event.action_taken == "request_blocked"
        assert "150 requests" in event.reason
        assert event.endpoint == "/api/test"
        assert event.method == "POST"
        assert event.metadata["request_count"] == 150

    def test_send_rate_limit_event_no_agent(self) -> None:
        self.manager.agent_handler = None
        with self.app.test_request_context("/api/test"):
            from flask import request

            # Should not raise — the caller guards with `if self.agent_handler`
            # but calling directly still works (try/except inside)
            self.manager._send_rate_limit_event(request, "1.2.3.4", 10)

    def test_send_rate_limit_event_exception_handled(self) -> None:
        self.manager.agent_handler.send_event.side_effect = Exception("agent down")
        with self.app.test_request_context("/api/test"):
            from flask import request

            self.manager._send_rate_limit_event(request, "1.2.3.4", 10)


# =========================================================================
# CloudManager events
# =========================================================================

class TestCloudManagerEvents:
    """Tests for CloudManager._send_cloud_event and send_cloud_detection_event."""

    def setup_method(self) -> None:
        from flaskapi_guard.handlers.cloud_handler import CloudManager

        CloudManager._instance = None
        self.manager = CloudManager()
        self.manager.agent_handler = MagicMock()

    def teardown_method(self) -> None:
        from flaskapi_guard.handlers.cloud_handler import CloudManager

        CloudManager._instance = None

    def test_send_cloud_event_sends_correct_event(self) -> None:
        self.manager._send_cloud_event(
            event_type="cloud_blocked",
            ip_address="3.5.140.1",
            action_taken="request_blocked",
            reason="blocked cloud",
            cloud_provider="AWS",
        )
        self.manager.agent_handler.send_event.assert_called_once()
        event = self.manager.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "cloud_blocked"
        assert event.ip_address == "3.5.140.1"
        assert event.metadata == {"cloud_provider": "AWS"}

    def test_send_cloud_event_no_agent(self) -> None:
        self.manager.agent_handler = None
        # Should return early
        self.manager._send_cloud_event(
            "cloud_blocked", "1.2.3.4", "blocked", "reason"
        )

    def test_send_cloud_event_exception_handled(self) -> None:
        self.manager.agent_handler.send_event.side_effect = Exception("agent down")
        self.manager._send_cloud_event(
            "cloud_blocked", "1.2.3.4", "blocked", "reason"
        )

    def test_send_cloud_detection_event(self) -> None:
        self.manager.send_cloud_detection_event(
            ip="3.5.140.1",
            provider="AWS",
            network="3.5.140.0/22",
            action_taken="request_blocked",
        )
        self.manager.agent_handler.send_event.assert_called_once()
        event = self.manager.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "cloud_blocked"
        assert "AWS" in event.reason
        assert event.metadata["cloud_provider"] == "AWS"
        assert event.metadata["network"] == "3.5.140.0/22"

    def test_send_cloud_detection_event_no_agent(self) -> None:
        self.manager.agent_handler = None
        # Should return early without error
        self.manager.send_cloud_detection_event("1.2.3.4", "GCP", "10.0.0.0/8")


# =========================================================================
# BehaviorTracker events
# =========================================================================

class TestBehaviorTrackerEvents:
    """Tests for BehaviorTracker._send_behavior_event."""

    def setup_method(self) -> None:
        config = _make_config()
        from flaskapi_guard.handlers.behavior_handler import BehaviorTracker

        self.tracker = BehaviorTracker(config)
        self.tracker.agent_handler = MagicMock()

    def test_send_behavior_event_sends_correct_event(self) -> None:
        self.tracker._send_behavior_event(
            event_type="behavioral_violation",
            ip_address="10.0.0.5",
            action_taken="banned",
            reason="Too many requests",
            endpoint="/api/data",
            rule_type="usage",
        )
        self.tracker.agent_handler.send_event.assert_called_once()
        event = self.tracker.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "behavioral_violation"
        assert event.ip_address == "10.0.0.5"
        assert event.action_taken == "banned"
        assert event.metadata["endpoint"] == "/api/data"
        assert event.metadata["rule_type"] == "usage"

    def test_send_behavior_event_no_agent(self) -> None:
        self.tracker.agent_handler = None
        self.tracker._send_behavior_event(
            "behavioral_violation", "1.2.3.4", "logged", "test"
        )

    def test_send_behavior_event_exception_handled(self) -> None:
        self.tracker.agent_handler.send_event.side_effect = Exception("agent down")
        self.tracker._send_behavior_event(
            "behavioral_violation", "1.2.3.4", "logged", "test"
        )


# =========================================================================
# IPInfoManager events
# =========================================================================

class TestIPInfoManagerEvents:
    """Tests for IPInfoManager._send_geo_event and check_country_access."""

    def setup_method(self) -> None:
        from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager

        IPInfoManager._instance = None
        self.manager = IPInfoManager(token="test_token")
        self.manager.agent_handler = MagicMock()

    def teardown_method(self) -> None:
        from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager

        IPInfoManager._instance = None

    def test_send_geo_event_sends_correct_event(self) -> None:
        self.manager._send_geo_event(
            event_type="country_blocked",
            ip_address="8.8.8.8",
            action_taken="request_blocked",
            reason="Country US is blocked",
            country="US",
        )
        self.manager.agent_handler.send_event.assert_called_once()
        event = self.manager.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "country_blocked"
        assert event.ip_address == "8.8.8.8"
        assert event.action_taken == "request_blocked"
        assert event.metadata == {"country": "US"}

    def test_send_geo_event_no_agent(self) -> None:
        self.manager.agent_handler = None
        self.manager._send_geo_event(
            "country_blocked", "8.8.8.8", "blocked", "test"
        )

    def test_send_geo_event_exception_handled(self) -> None:
        self.manager.agent_handler.send_event.side_effect = Exception("agent down")
        self.manager._send_geo_event(
            "country_blocked", "8.8.8.8", "blocked", "test"
        )

    def test_check_country_access_whitelist_fail_closed(self) -> None:
        """Unknown country (None) should be blocked when whitelist is set."""
        with patch.object(self.manager, "get_country", return_value=None):
            is_allowed, country = self.manager.check_country_access(
                "1.2.3.4", blocked_countries=[], whitelist_countries=["US"]
            )
        assert is_allowed is False
        assert country is None

    def test_check_country_access_blacklist_fail_open(self) -> None:
        """Unknown country (None) should be allowed for blacklist-only configs."""
        with patch.object(self.manager, "get_country", return_value=None):
            is_allowed, country = self.manager.check_country_access(
                "1.2.3.4", blocked_countries=["CN"], whitelist_countries=None
            )
        assert is_allowed is True
        assert country is None

    def test_check_country_access_whitelist_blocked_sends_event(self) -> None:
        """Country not in whitelist should be blocked and send an event."""
        with patch.object(self.manager, "get_country", return_value="RU"):
            is_allowed, country = self.manager.check_country_access(
                "5.6.7.8", blocked_countries=[], whitelist_countries=["US", "GB"]
            )
        assert is_allowed is False
        assert country == "RU"
        self.manager.agent_handler.send_event.assert_called_once()
        event = self.manager.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "country_blocked"
        assert event.metadata["rule_type"] == "country_whitelist"

    def test_check_country_access_blacklist_blocked_sends_event(self) -> None:
        """Country in blacklist should be blocked and send an event."""
        with patch.object(self.manager, "get_country", return_value="CN"):
            is_allowed, country = self.manager.check_country_access(
                "5.6.7.8", blocked_countries=["CN", "RU"]
            )
        assert is_allowed is False
        assert country == "CN"
        self.manager.agent_handler.send_event.assert_called_once()
        event = self.manager.agent_handler.send_event.call_args[0][0]
        assert event.event_type == "country_blocked"
        assert event.metadata["rule_type"] == "country_blacklist"
