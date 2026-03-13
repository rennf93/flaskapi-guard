"""Comprehensive tests for flaskapi_guard/handlers/dynamic_rule_handler.py."""

import logging
import sys
import threading
import time
import types
from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from flaskapi_guard.handlers.dynamic_rule_handler import DynamicRuleManager
from flaskapi_guard.models import DynamicRules, SecurityConfig

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def cleanup_singleton() -> Generator[None, None, None]:
    """Reset singleton before and after each test."""
    DynamicRuleManager._instance = None
    yield
    # Stop any running thread, then reset
    if DynamicRuleManager._instance is not None:
        try:
            DynamicRuleManager._instance.stop()
        except Exception:
            pass
    DynamicRuleManager._instance = None


@pytest.fixture
def config() -> SecurityConfig:
    """Minimal SecurityConfig with dynamic rules enabled."""
    return SecurityConfig(
        enable_dynamic_rules=True,
        enable_agent=True,
        agent_api_key="test-key",
        dynamic_rule_interval=5,
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        rate_limit=100,
        rate_limit_window=60,
        auto_ban_threshold=10,
        enable_redis=False,
    )


@pytest.fixture
def config_disabled() -> SecurityConfig:
    """SecurityConfig with dynamic rules disabled."""
    return SecurityConfig(
        enable_dynamic_rules=False,
        enable_redis=False,
    )


@pytest.fixture
def mock_agent_handler() -> MagicMock:
    """Create a mock agent handler."""
    handler = MagicMock()
    handler.get_dynamic_rules = MagicMock()
    handler.send_event = MagicMock()
    return handler


@pytest.fixture
def mock_redis_handler() -> MagicMock:
    """Create a mock redis handler."""
    return MagicMock()


@pytest.fixture
def manager(config: SecurityConfig) -> DynamicRuleManager:
    """Create a fresh DynamicRuleManager instance."""
    return DynamicRuleManager(config)


@pytest.fixture
def sample_rules() -> DynamicRules:
    """Create sample dynamic rules for testing."""
    return DynamicRules(
        rule_id="test-rule-1",
        version=1,
        timestamp=datetime.now(timezone.utc),
        ip_blacklist=["172.16.0.100", "10.0.0.50"],
        ip_whitelist=["192.168.1.200"],
        ip_ban_duration=3600,
        blocked_countries=["XX", "YY"],
        whitelist_countries=["US", "CA"],
        global_rate_limit=50,
        global_rate_window=30,
        endpoint_rate_limits={"/api/endpoint": (10, 60)},
        blocked_cloud_providers={"aws", "azure"},
        blocked_user_agents=["badbot", "scanner"],
        suspicious_patterns=["../", "SELECT * FROM"],
        enable_penetration_detection=True,
        enable_ip_banning=True,
        enable_rate_limiting=True,
        emergency_mode=False,
        emergency_whitelist=[],
    )


@pytest.fixture
def mock_guard_agent() -> Generator[Any, None, None]:
    """Mock the guard_agent module so SecurityEvent imports succeed."""
    mock_module = types.ModuleType("guard_agent")
    mock_security_event = MagicMock(name="SecurityEvent")
    mock_module.SecurityEvent = mock_security_event  # type: ignore[attr-defined]

    original = sys.modules.get("guard_agent")
    sys.modules["guard_agent"] = mock_module
    try:
        yield mock_module
    finally:
        if original is not None:
            sys.modules["guard_agent"] = original
        else:
            sys.modules.pop("guard_agent", None)


# ---------------------------------------------------------------------------
# 1. Singleton pattern and initialization
# ---------------------------------------------------------------------------


class TestSingletonPattern:
    """Test DynamicRuleManager singleton behaviour."""

    def test_singleton_returns_same_instance(
        self, config: SecurityConfig
    ) -> None:
        instance_a = DynamicRuleManager(config)
        instance_b = DynamicRuleManager(config)
        assert instance_a is instance_b
        assert DynamicRuleManager._instance is instance_a

    def test_singleton_preserves_state(self, config: SecurityConfig) -> None:
        instance_a = DynamicRuleManager(config)
        instance_a.last_update = 99999.0
        instance_b = DynamicRuleManager(config)
        assert instance_b.last_update == 99999.0

    def test_new_instance_after_reset(self, config: SecurityConfig) -> None:
        instance_a = DynamicRuleManager(config)
        DynamicRuleManager._instance = None
        instance_b = DynamicRuleManager(config)
        assert instance_a is not instance_b

    def test_initial_attributes(self, manager: DynamicRuleManager) -> None:
        assert manager.last_update == 0
        assert manager.current_rules is None
        assert manager._update_thread is None
        assert manager._stop_event is None
        assert manager.agent_handler is None
        assert manager.redis_handler is None


# ---------------------------------------------------------------------------
# 2. initialize_agent
# ---------------------------------------------------------------------------


class TestInitializeAgent:
    """Test initialize_agent thread management."""

    def test_thread_starts_when_dynamic_rules_enabled(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
    ) -> None:
        manager.initialize_agent(mock_agent_handler)
        assert manager.agent_handler is mock_agent_handler
        assert manager._update_thread is not None
        assert isinstance(manager._update_thread, threading.Thread)
        assert manager._update_thread.daemon is True
        manager.stop()

    def test_thread_not_started_when_disabled(
        self,
        config_disabled: SecurityConfig,
        mock_agent_handler: MagicMock,
    ) -> None:
        mgr = DynamicRuleManager(config_disabled)
        mgr.initialize_agent(mock_agent_handler)
        assert mgr.agent_handler is mock_agent_handler
        assert mgr._update_thread is None

    def test_no_duplicate_threads(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
    ) -> None:
        manager.initialize_agent(mock_agent_handler)
        first_thread = manager._update_thread

        manager.initialize_agent(mock_agent_handler)
        assert manager._update_thread is first_thread
        manager.stop()


# ---------------------------------------------------------------------------
# 3. initialize_redis
# ---------------------------------------------------------------------------


class TestInitializeRedis:
    def test_sets_redis_handler(
        self,
        manager: DynamicRuleManager,
        mock_redis_handler: MagicMock,
    ) -> None:
        manager.initialize_redis(mock_redis_handler)
        assert manager.redis_handler is mock_redis_handler


# ---------------------------------------------------------------------------
# 4. _rule_update_loop
# ---------------------------------------------------------------------------


class TestRuleUpdateLoop:
    """Test the background loop."""

    def test_loop_calls_update_rules(
        self,
        config: SecurityConfig,
        mock_agent_handler: MagicMock,
    ) -> None:
        config.dynamic_rule_interval = 1
        mgr = DynamicRuleManager(config)
        mgr.agent_handler = mock_agent_handler
        mock_agent_handler.get_dynamic_rules.return_value = None

        with patch.object(mgr, "update_rules") as mock_update:
            mgr._stop_event = threading.Event()
            t = threading.Thread(target=mgr._rule_update_loop, daemon=True)
            t.start()
            time.sleep(0.3)
            mgr._stop_event.set()
            t.join(timeout=3)
            assert mock_update.call_count >= 1

    def test_loop_handles_exception(
        self,
        config: SecurityConfig,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        config.dynamic_rule_interval = 1
        mgr = DynamicRuleManager(config)

        with patch.object(
            mgr, "update_rules", side_effect=RuntimeError("boom")
        ):
            mgr._stop_event = threading.Event()
            with caplog.at_level(
                logging.ERROR, logger="flaskapi_guard.handlers.dynamic_rule"
            ):
                t = threading.Thread(target=mgr._rule_update_loop, daemon=True)
                t.start()
                time.sleep(0.3)
                mgr._stop_event.set()
                t.join(timeout=3)

            assert "Error in dynamic rule update loop" in caplog.text

    def test_loop_stops_when_stop_event_none(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        """Loop should exit immediately if _stop_event is None."""
        manager._stop_event = None
        # Should return immediately without hanging
        manager._rule_update_loop()


# ---------------------------------------------------------------------------
# 5. _should_update_rules
# ---------------------------------------------------------------------------


class TestShouldUpdateRules:
    def test_true_when_no_current_rules(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        assert manager.current_rules is None
        assert manager._should_update_rules(sample_rules) is True

    def test_false_when_same_id_and_same_version(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        manager.current_rules = sample_rules.model_copy()
        assert manager._should_update_rules(sample_rules) is False

    def test_false_when_same_id_lower_version(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        manager.current_rules = sample_rules.model_copy()
        manager.current_rules.version = 5
        older = sample_rules.model_copy()
        older.version = 3
        assert manager._should_update_rules(older) is False

    def test_true_when_same_id_higher_version(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        manager.current_rules = sample_rules.model_copy()
        manager.current_rules.version = 1
        newer = sample_rules.model_copy()
        newer.version = 2
        assert manager._should_update_rules(newer) is True

    def test_true_when_different_rule_id(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        manager.current_rules = sample_rules.model_copy()
        different = sample_rules.model_copy()
        different.rule_id = "completely-different-id"
        different.version = 0  # even lower version
        assert manager._should_update_rules(different) is True


# ---------------------------------------------------------------------------
# 6. update_rules – full flow
# ---------------------------------------------------------------------------


class TestUpdateRules:
    def test_full_flow(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        sample_rules: DynamicRules,
    ) -> None:
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules
        manager.agent_handler = mock_agent_handler
        manager.config.enable_dynamic_rules = True

        with (
            patch.object(manager, "_apply_rules") as mock_apply,
            patch.object(manager, "_send_rule_received_event") as mock_recv,
            patch.object(manager, "_send_rule_applied_event") as mock_applied,
        ):
            manager.update_rules()

            mock_recv.assert_called_once_with(sample_rules)
            mock_apply.assert_called_once_with(sample_rules)
            mock_applied.assert_called_once_with(sample_rules)
            assert manager.current_rules is sample_rules
            assert manager.last_update > 0

    def test_returns_early_when_disabled(
        self,
        config_disabled: SecurityConfig,
        mock_agent_handler: MagicMock,
    ) -> None:
        mgr = DynamicRuleManager(config_disabled)
        mgr.agent_handler = mock_agent_handler
        mock_agent_handler.get_dynamic_rules.return_value = MagicMock()

        mgr.update_rules()
        mock_agent_handler.get_dynamic_rules.assert_not_called()

    def test_returns_early_when_no_agent(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        manager.agent_handler = None
        # Should not raise
        manager.update_rules()

    def test_returns_early_when_agent_returns_none(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
    ) -> None:
        mock_agent_handler.get_dynamic_rules.return_value = None
        manager.agent_handler = mock_agent_handler

        manager.update_rules()
        assert manager.current_rules is None

    def test_returns_early_when_should_not_update(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        sample_rules: DynamicRules,
    ) -> None:
        manager.current_rules = sample_rules.model_copy()
        mock_agent_handler.get_dynamic_rules.return_value = sample_rules
        manager.agent_handler = mock_agent_handler

        with patch.object(manager, "_apply_rules") as mock_apply:
            manager.update_rules()
            mock_apply.assert_not_called()

    def test_handles_exception_in_update(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        mock_agent_handler.get_dynamic_rules.side_effect = RuntimeError("net error")
        manager.agent_handler = mock_agent_handler

        with caplog.at_level(logging.ERROR, logger="flaskapi_guard.handlers.dynamic_rule"):
            manager.update_rules()

        assert "Failed to update dynamic rules" in caplog.text


# ---------------------------------------------------------------------------
# 7. _apply_rules (orchestrator)
# ---------------------------------------------------------------------------


class TestApplyRules:
    def test_calls_sub_methods(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        with (
            patch.object(manager, "_apply_ip_rules") as m_ip,
            patch.object(manager, "_apply_blocking_rules") as m_block,
            patch.object(manager, "_apply_rate_limit_rules") as m_rate,
            patch.object(manager, "_apply_feature_toggles") as m_feat,
            patch.object(manager, "_activate_emergency_mode") as m_emrg,
        ):
            manager._apply_rules(sample_rules)
            m_ip.assert_called_once_with(sample_rules)
            m_block.assert_called_once_with(sample_rules)
            m_rate.assert_called_once_with(sample_rules)
            m_feat.assert_called_once_with(sample_rules)
            m_emrg.assert_not_called()  # emergency_mode=False

    def test_activates_emergency_mode(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        sample_rules.emergency_mode = True
        sample_rules.emergency_whitelist = ["10.0.0.1"]

        with (
            patch.object(manager, "_apply_ip_rules"),
            patch.object(manager, "_apply_blocking_rules"),
            patch.object(manager, "_apply_rate_limit_rules"),
            patch.object(manager, "_apply_feature_toggles"),
            patch.object(manager, "_activate_emergency_mode") as m_emrg,
        ):
            manager._apply_rules(sample_rules)
            m_emrg.assert_called_once_with(["10.0.0.1"])

    def test_no_rate_limit_call_when_no_rate_rules(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        sample_rules.global_rate_limit = None
        sample_rules.endpoint_rate_limits = {}

        with (
            patch.object(manager, "_apply_ip_rules"),
            patch.object(manager, "_apply_blocking_rules"),
            patch.object(manager, "_apply_rate_limit_rules") as m_rate,
            patch.object(manager, "_apply_feature_toggles"),
        ):
            manager._apply_rules(sample_rules)
            m_rate.assert_not_called()

    def test_apply_rules_propagates_exception(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        with patch.object(
            manager, "_apply_ip_rules", side_effect=RuntimeError("fail")
        ):
            with pytest.raises(RuntimeError, match="fail"):
                manager._apply_rules(sample_rules)


# ---------------------------------------------------------------------------
# 8. _apply_ip_rules
# ---------------------------------------------------------------------------


class TestApplyIpRules:
    def test_calls_ban_and_whitelist(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        with (
            patch.object(manager, "_apply_ip_bans") as m_ban,
            patch.object(manager, "_apply_ip_whitelist") as m_wl,
        ):
            manager._apply_ip_rules(sample_rules)
            m_ban.assert_called_once_with(
                sample_rules.ip_blacklist, sample_rules.ip_ban_duration
            )
            m_wl.assert_called_once_with(sample_rules.ip_whitelist)

    def test_skips_empty_lists(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        sample_rules.ip_blacklist = []
        sample_rules.ip_whitelist = []
        with (
            patch.object(manager, "_apply_ip_bans") as m_ban,
            patch.object(manager, "_apply_ip_whitelist") as m_wl,
        ):
            manager._apply_ip_rules(sample_rules)
            m_ban.assert_not_called()
            m_wl.assert_not_called()


# ---------------------------------------------------------------------------
# 9. _apply_ip_bans
# ---------------------------------------------------------------------------


class TestApplyIpBans:
    def test_bans_each_ip(self, manager: DynamicRuleManager) -> None:
        mock_ban_mgr = MagicMock()
        with patch(
            "flaskapi_guard.handlers.ipban_handler.ip_ban_manager",
            mock_ban_mgr,
            create=True,
        ):
            manager._apply_ip_bans(["1.2.3.4", "5.6.7.8"], 600)
            assert mock_ban_mgr.ban_ip.call_count == 2
            mock_ban_mgr.ban_ip.assert_any_call("1.2.3.4", 600, "dynamic_rule")
            mock_ban_mgr.ban_ip.assert_any_call("5.6.7.8", 600, "dynamic_rule")

    def test_handles_ban_exception(
        self,
        manager: DynamicRuleManager,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        mock_ban_mgr = MagicMock()
        mock_ban_mgr.ban_ip.side_effect = RuntimeError("ban error")
        with patch(
            "flaskapi_guard.handlers.ipban_handler.ip_ban_manager",
            mock_ban_mgr,
            create=True,
        ):
            with caplog.at_level(
                logging.ERROR, logger="flaskapi_guard.handlers.dynamic_rule"
            ):
                manager._apply_ip_bans(["1.2.3.4"], 600)
            assert "Failed to ban IP 1.2.3.4" in caplog.text


# ---------------------------------------------------------------------------
# 10. _apply_ip_whitelist
# ---------------------------------------------------------------------------


class TestApplyIpWhitelist:
    def test_unbans_each_ip(self, manager: DynamicRuleManager) -> None:
        mock_ban_mgr = MagicMock()
        with patch(
            "flaskapi_guard.handlers.ipban_handler.ip_ban_manager",
            mock_ban_mgr,
            create=True,
        ):
            manager._apply_ip_whitelist(["10.0.0.1", "10.0.0.2"])
            assert mock_ban_mgr.unban_ip.call_count == 2

    def test_handles_unban_exception(
        self,
        manager: DynamicRuleManager,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        mock_ban_mgr = MagicMock()
        mock_ban_mgr.unban_ip.side_effect = RuntimeError("unban error")
        with patch(
            "flaskapi_guard.handlers.ipban_handler.ip_ban_manager",
            mock_ban_mgr,
            create=True,
        ):
            with caplog.at_level(
                logging.ERROR, logger="flaskapi_guard.handlers.dynamic_rule"
            ):
                manager._apply_ip_whitelist(["10.0.0.1"])
            assert "Failed to whitelist IP 10.0.0.1" in caplog.text


# ---------------------------------------------------------------------------
# 11. _apply_blocking_rules
# ---------------------------------------------------------------------------


class TestApplyBlockingRules:
    def test_calls_all_sub_methods(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        with (
            patch.object(manager, "_apply_country_rules") as m_country,
            patch.object(manager, "_apply_cloud_provider_rules") as m_cloud,
            patch.object(manager, "_apply_user_agent_rules") as m_ua,
            patch.object(manager, "_apply_pattern_rules") as m_pat,
        ):
            manager._apply_blocking_rules(sample_rules)
            m_country.assert_called_once_with(
                sample_rules.blocked_countries, sample_rules.whitelist_countries
            )
            m_cloud.assert_called_once_with(sample_rules.blocked_cloud_providers)
            m_ua.assert_called_once_with(sample_rules.blocked_user_agents)
            m_pat.assert_called_once_with(sample_rules.suspicious_patterns)

    def test_skips_empty_fields(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        sample_rules.blocked_countries = []
        sample_rules.whitelist_countries = []
        sample_rules.blocked_cloud_providers = set()
        sample_rules.blocked_user_agents = []
        sample_rules.suspicious_patterns = []

        with (
            patch.object(manager, "_apply_country_rules") as m_country,
            patch.object(manager, "_apply_cloud_provider_rules") as m_cloud,
            patch.object(manager, "_apply_user_agent_rules") as m_ua,
            patch.object(manager, "_apply_pattern_rules") as m_pat,
        ):
            manager._apply_blocking_rules(sample_rules)
            m_country.assert_not_called()
            m_cloud.assert_not_called()
            m_ua.assert_not_called()
            m_pat.assert_not_called()


# ---------------------------------------------------------------------------
# 12. _apply_country_rules
# ---------------------------------------------------------------------------


class TestApplyCountryRules:
    def test_sets_blocked_and_whitelisted(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        manager._apply_country_rules(["CN", "RU"], ["US"])
        assert manager.config.blocked_countries == ["CN", "RU"]
        assert manager.config.whitelist_countries == ["US"]

    def test_only_blocked(self, manager: DynamicRuleManager) -> None:
        original_whitelist = manager.config.whitelist_countries[:]
        manager._apply_country_rules(["CN"], [])
        assert manager.config.blocked_countries == ["CN"]
        assert manager.config.whitelist_countries == original_whitelist

    def test_only_allowed(self, manager: DynamicRuleManager) -> None:
        original_blocked = manager.config.blocked_countries[:]
        manager._apply_country_rules([], ["US"])
        assert manager.config.blocked_countries == original_blocked
        assert manager.config.whitelist_countries == ["US"]


# ---------------------------------------------------------------------------
# 13. _apply_rate_limit_rules
# ---------------------------------------------------------------------------


class TestApplyRateLimitRules:
    def test_global_rate_limit_and_window(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        manager._apply_rate_limit_rules(sample_rules)
        assert manager.config.rate_limit == 50
        assert manager.config.rate_limit_window == 30

    def test_global_rate_limit_without_window(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        sample_rules.global_rate_window = None
        original_window = manager.config.rate_limit_window
        manager._apply_rate_limit_rules(sample_rules)
        assert manager.config.rate_limit == 50
        assert manager.config.rate_limit_window == original_window

    def test_endpoint_rate_limits(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        manager._apply_rate_limit_rules(sample_rules)
        assert "/api/endpoint" in manager.config.endpoint_rate_limits
        assert manager.config.endpoint_rate_limits["/api/endpoint"] == (10, 60)

    def test_no_global_rate_limit(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        sample_rules.global_rate_limit = None
        sample_rules.global_rate_window = None
        original_rate = manager.config.rate_limit
        manager._apply_rate_limit_rules(sample_rules)
        assert manager.config.rate_limit == original_rate


# ---------------------------------------------------------------------------
# 14. _apply_cloud_provider_rules
# ---------------------------------------------------------------------------


class TestApplyCloudProviderRules:
    def test_sets_providers(self, manager: DynamicRuleManager) -> None:
        manager._apply_cloud_provider_rules({"aws", "gcp"})
        assert manager.config.block_cloud_providers == {"aws", "gcp"}


# ---------------------------------------------------------------------------
# 15. _apply_user_agent_rules
# ---------------------------------------------------------------------------


class TestApplyUserAgentRules:
    def test_sets_user_agents(self, manager: DynamicRuleManager) -> None:
        manager._apply_user_agent_rules(["badbot", "crawler"])
        assert manager.config.blocked_user_agents == ["badbot", "crawler"]


# ---------------------------------------------------------------------------
# 16. _apply_pattern_rules
# ---------------------------------------------------------------------------


class TestApplyPatternRules:
    def test_adds_each_pattern(self, manager: DynamicRuleManager) -> None:
        mock_sus = MagicMock()
        with patch(
            "flaskapi_guard.handlers.suspatterns_handler.sus_patterns_handler",
            mock_sus,
            create=True,
        ):
            manager._apply_pattern_rules(["../", "DROP TABLE"])
            assert mock_sus.add_pattern.call_count == 2
            mock_sus.add_pattern.assert_any_call("../")
            mock_sus.add_pattern.assert_any_call("DROP TABLE")


# ---------------------------------------------------------------------------
# 17. _apply_feature_toggles
# ---------------------------------------------------------------------------


class TestApplyFeatureToggles:
    def test_penetration_detection_enabled(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        rules = DynamicRules(
            rule_id="ft-1",
            version=1,
            timestamp=datetime.now(timezone.utc),
            enable_penetration_detection=True,
        )
        manager._apply_feature_toggles(rules)
        assert manager.config.enable_penetration_detection is True

    def test_penetration_detection_disabled(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        rules = DynamicRules(
            rule_id="ft-2",
            version=1,
            timestamp=datetime.now(timezone.utc),
            enable_penetration_detection=False,
        )
        manager._apply_feature_toggles(rules)
        assert manager.config.enable_penetration_detection is False

    def test_ip_banning_toggle(self, manager: DynamicRuleManager) -> None:
        rules = DynamicRules(
            rule_id="ft-3",
            version=1,
            timestamp=datetime.now(timezone.utc),
            enable_ip_banning=False,
        )
        manager._apply_feature_toggles(rules)
        assert manager.config.enable_ip_banning is False

    def test_rate_limiting_toggle(self, manager: DynamicRuleManager) -> None:
        rules = DynamicRules(
            rule_id="ft-4",
            version=1,
            timestamp=datetime.now(timezone.utc),
            enable_rate_limiting=False,
        )
        manager._apply_feature_toggles(rules)
        assert manager.config.enable_rate_limiting is False

    def test_none_values_leave_config_unchanged(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        original_pen = manager.config.enable_penetration_detection
        original_ban = manager.config.enable_ip_banning
        original_rl = manager.config.enable_rate_limiting

        rules = DynamicRules(
            rule_id="ft-5",
            version=1,
            timestamp=datetime.now(timezone.utc),
            enable_penetration_detection=None,
            enable_ip_banning=None,
            enable_rate_limiting=None,
        )
        manager._apply_feature_toggles(rules)

        assert manager.config.enable_penetration_detection == original_pen
        assert manager.config.enable_ip_banning == original_ban
        assert manager.config.enable_rate_limiting == original_rl


# ---------------------------------------------------------------------------
# 18. _activate_emergency_mode
# ---------------------------------------------------------------------------


class TestActivateEmergencyMode:
    def test_sets_emergency_mode(self, manager: DynamicRuleManager) -> None:
        manager._activate_emergency_mode(["10.0.0.1"])
        assert manager.config.emergency_mode is True
        assert manager.config.emergency_whitelist == ["10.0.0.1"]

    def test_halves_auto_ban_threshold(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        manager.config.auto_ban_threshold = 10
        manager._activate_emergency_mode([])
        assert manager.config.auto_ban_threshold == 5

    def test_threshold_minimum_is_one(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        manager.config.auto_ban_threshold = 1
        manager._activate_emergency_mode([])
        assert manager.config.auto_ban_threshold == 1

    def test_sends_emergency_event_when_agent_present(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
    ) -> None:
        manager.agent_handler = mock_agent_handler
        with patch.object(manager, "_send_emergency_event") as m_event:
            manager._activate_emergency_mode(["10.0.0.1"])
            m_event.assert_called_once_with(["10.0.0.1"])

    def test_no_event_when_no_agent(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        manager.agent_handler = None
        with patch.object(manager, "_send_emergency_event") as m_event:
            manager._activate_emergency_mode([])
            m_event.assert_not_called()


# ---------------------------------------------------------------------------
# 19. _send_rule_received_event
# ---------------------------------------------------------------------------


class TestSendRuleReceivedEvent:
    def test_no_agent_returns_early(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        manager.agent_handler = None
        # Should not raise
        manager._send_rule_received_event(sample_rules)

    def test_sends_event(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        sample_rules: DynamicRules,
        mock_guard_agent: Any,
    ) -> None:
        manager.agent_handler = mock_agent_handler
        manager._send_rule_received_event(sample_rules)
        mock_agent_handler.send_event.assert_called_once()

    def test_sends_event_with_current_rules(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        sample_rules: DynamicRules,
        mock_guard_agent: Any,
    ) -> None:
        # Set existing rules so previous_version is populated
        existing = sample_rules.model_copy()
        existing.version = 3
        manager.current_rules = existing
        manager.agent_handler = mock_agent_handler

        newer = sample_rules.model_copy()
        newer.version = 5
        manager._send_rule_received_event(newer)
        mock_agent_handler.send_event.assert_called_once()

    def test_handles_import_error(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        sample_rules: DynamicRules,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        manager.agent_handler = mock_agent_handler
        # Remove guard_agent from sys.modules to trigger ImportError
        original = sys.modules.pop("guard_agent", None)
        try:
            with caplog.at_level(
                logging.ERROR, logger="flaskapi_guard.handlers.dynamic_rule"
            ):
                manager._send_rule_received_event(sample_rules)
            assert "Failed to send rule updated event" in caplog.text
        finally:
            if original is not None:
                sys.modules["guard_agent"] = original


# ---------------------------------------------------------------------------
# 20. _send_rule_applied_event
# ---------------------------------------------------------------------------


class TestSendRuleAppliedEvent:
    def test_no_agent_returns_early(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        manager.agent_handler = None
        manager._send_rule_applied_event(sample_rules)

    def test_sends_event(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        sample_rules: DynamicRules,
        mock_guard_agent: Any,
    ) -> None:
        manager.agent_handler = mock_agent_handler
        manager._send_rule_applied_event(sample_rules)
        mock_agent_handler.send_event.assert_called_once()

    def test_handles_exception(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        sample_rules: DynamicRules,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        manager.agent_handler = mock_agent_handler
        original = sys.modules.pop("guard_agent", None)
        try:
            with caplog.at_level(
                logging.ERROR, logger="flaskapi_guard.handlers.dynamic_rule"
            ):
                manager._send_rule_applied_event(sample_rules)
            assert "Failed to send rule applied event" in caplog.text
        finally:
            if original is not None:
                sys.modules["guard_agent"] = original


# ---------------------------------------------------------------------------
# 21. _send_emergency_event
# ---------------------------------------------------------------------------


class TestSendEmergencyEvent:
    def test_no_agent_returns_early(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        manager.agent_handler = None
        manager._send_emergency_event(["10.0.0.1"])

    def test_sends_event(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        mock_guard_agent: Any,
    ) -> None:
        manager.agent_handler = mock_agent_handler
        manager._send_emergency_event(["10.0.0.1", "10.0.0.2"])
        mock_agent_handler.send_event.assert_called_once()

    def test_handles_exception(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        manager.agent_handler = mock_agent_handler
        original = sys.modules.pop("guard_agent", None)
        try:
            with caplog.at_level(
                logging.ERROR, logger="flaskapi_guard.handlers.dynamic_rule"
            ):
                manager._send_emergency_event(["10.0.0.1"])
            assert "Failed to send emergency event" in caplog.text
        finally:
            if original is not None:
                sys.modules["guard_agent"] = original


# ---------------------------------------------------------------------------
# 22. get_current_rules
# ---------------------------------------------------------------------------


class TestGetCurrentRules:
    def test_returns_none_initially(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        assert manager.get_current_rules() is None

    def test_returns_rules_after_set(
        self,
        manager: DynamicRuleManager,
        sample_rules: DynamicRules,
    ) -> None:
        manager.current_rules = sample_rules
        assert manager.get_current_rules() is sample_rules


# ---------------------------------------------------------------------------
# 23. force_update
# ---------------------------------------------------------------------------


class TestForceUpdate:
    def test_calls_update_rules(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        with patch.object(manager, "update_rules") as m_update:
            manager.force_update()
            m_update.assert_called_once()


# ---------------------------------------------------------------------------
# 24. stop
# ---------------------------------------------------------------------------


class TestStop:
    def test_stop_with_running_thread(
        self,
        manager: DynamicRuleManager,
        mock_agent_handler: MagicMock,
    ) -> None:
        mock_agent_handler.get_dynamic_rules.return_value = None
        manager.initialize_agent(mock_agent_handler)
        assert manager._update_thread is not None

        manager.stop()
        assert manager._update_thread is None

    def test_stop_without_thread(
        self,
        manager: DynamicRuleManager,
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        manager._update_thread = None
        manager._stop_event = None
        # Should not raise
        manager.stop()

    def test_stop_sets_event(
        self,
        manager: DynamicRuleManager,
    ) -> None:
        manager._stop_event = threading.Event()
        mock_thread = MagicMock()
        manager._update_thread = mock_thread

        manager.stop()
        assert manager._stop_event.is_set()
        mock_thread.join.assert_called_once_with(timeout=5)
        assert manager._update_thread is None
