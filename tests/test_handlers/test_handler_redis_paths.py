"""Tests for Redis-specific code paths in handlers using mocked Redis."""

import sys
import time
import types
from unittest.mock import MagicMock, Mock

import pytest

from flaskapi_guard.handlers.ipban_handler import IPBanManager
from flaskapi_guard.handlers.ratelimit_handler import RateLimitManager
from flaskapi_guard.handlers.redis_handler import RedisManager
from flaskapi_guard.models import SecurityConfig


def _install_mock_guard_agent() -> types.ModuleType:
    """Install a mock guard_agent module into sys.modules."""
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
def fresh_ipban() -> IPBanManager:
    """Return a fresh IPBanManager singleton."""
    IPBanManager._instance = None
    mgr = IPBanManager()
    return mgr


@pytest.fixture()
def mock_redis_handler() -> MagicMock:
    """Return a MagicMock that behaves like RedisManager."""
    handler = MagicMock()
    handler.config = MagicMock()
    handler.config.redis_prefix = "flaskapi_guard_test:"
    handler.config.enable_redis = True
    return handler


@pytest.fixture()
def redis_config() -> SecurityConfig:
    return SecurityConfig(
        enable_redis=True,
        redis_url="redis://localhost:6379",
        redis_prefix="flaskapi_guard_test:",
    )


class TestIPBanManagerRedis:
    """Tests for Redis-specific paths in IPBanManager."""

    def test_initialize_agent(self, fresh_ipban: IPBanManager) -> None:
        """initialize_agent stores the agent handler (line 33)."""
        agent = Mock()
        fresh_ipban.initialize_agent(agent)
        assert fresh_ipban.agent_handler is agent

    def test_ban_ip_with_redis(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """ban_ip calls redis_handler.set_key (lines 45-46)."""
        fresh_ipban.initialize_redis(mock_redis_handler)
        fresh_ipban.ban_ip("10.0.0.1", duration=600, reason="test")

        mock_redis_handler.set_key.assert_called_once()
        args = mock_redis_handler.set_key.call_args
        assert args[0][0] == "banned_ips"
        assert args[0][1] == "10.0.0.1"
        assert args[1]["ttl"] == 600 or args[0][3] == 600

    def test_ban_ip_with_agent(self, fresh_ipban: IPBanManager) -> None:
        """ban_ip sends ban event via agent (lines 49-50)."""
        agent = Mock()
        fresh_ipban.initialize_agent(agent)
        fresh_ipban.ban_ip("10.0.0.2", duration=300, reason="abuse")

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "ip_banned"
        assert event.ip_address == "10.0.0.2"

    def test_unban_ip_full_path(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """unban_ip removes from cache, Redis, and sends agent event (lines 77-86)."""
        agent = Mock()
        fresh_ipban.initialize_redis(mock_redis_handler)
        fresh_ipban.initialize_agent(agent)

        fresh_ipban.ban_ip("10.0.0.3", duration=600)
        agent.reset_mock()

        fresh_ipban.unban_ip("10.0.0.3")

        assert "10.0.0.3" not in fresh_ipban.banned_ips
        mock_redis_handler.delete.assert_called_with("banned_ips", "10.0.0.3")
        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "ip_unbanned"

    def test_is_ip_banned_redis_fallback_hit(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """Cache miss -> Redis hit -> populates cache (lines 121-128)."""
        future_expiry = str(time.time() + 3600)
        mock_redis_handler.get_key.return_value = future_expiry
        fresh_ipban.initialize_redis(mock_redis_handler)

        result = fresh_ipban.is_ip_banned("10.0.0.4")

        assert result is True
        assert "10.0.0.4" in fresh_ipban.banned_ips
        mock_redis_handler.get_key.assert_called_with("banned_ips", "10.0.0.4")

    def test_is_ip_banned_redis_expired_cleanup(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """Cache miss -> Redis hit but expired -> deletes from Redis (line 128)."""
        past_expiry = str(time.time() - 100)
        mock_redis_handler.get_key.return_value = past_expiry
        fresh_ipban.initialize_redis(mock_redis_handler)

        result = fresh_ipban.is_ip_banned("10.0.0.5")

        assert result is False
        mock_redis_handler.delete.assert_called_with("banned_ips", "10.0.0.5")

    def test_reset_with_redis(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """reset clears local cache and Redis keys (lines 136-143)."""
        fresh_ipban.initialize_redis(mock_redis_handler)
        fresh_ipban.ban_ip("10.0.0.6", duration=600)

        mock_conn = MagicMock()
        mock_conn.keys.return_value = [
            "flaskapi_guard_test:banned_ips:10.0.0.6",
        ]
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        fresh_ipban.reset()

        assert len(fresh_ipban.banned_ips) == 0
        mock_conn.keys.assert_called_once()
        mock_conn.delete.assert_called_once()

    def test_reset_with_redis_no_keys(
        self, fresh_ipban: IPBanManager, mock_redis_handler: MagicMock
    ) -> None:
        """reset with Redis but no matching keys does not call delete."""
        fresh_ipban.initialize_redis(mock_redis_handler)

        mock_conn = MagicMock()
        mock_conn.keys.return_value = []
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        fresh_ipban.reset()
        mock_conn.delete.assert_not_called()


class TestRedisManagerPaths:
    """Tests for uncovered RedisManager code paths."""

    def test_initialize_agent(self, redis_config: SecurityConfig) -> None:
        """initialize_agent stores the agent handler (line 39)."""
        mgr = RedisManager(redis_config)
        agent = Mock()
        mgr.initialize_agent(agent)
        assert mgr.agent_handler is agent

    def test_send_redis_event_full_flow(self, redis_config: SecurityConfig) -> None:
        """_send_redis_event constructs and sends SecurityEvent (lines 48-62)."""
        mgr = RedisManager(redis_config)
        agent = Mock()
        mgr.initialize_agent(agent)

        mgr._send_redis_event(
            event_type="redis_connection",
            action_taken="connection_established",
            reason="test reason",
            extra_key="extra_val",
        )

        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.event_type == "redis_connection"
        assert event.ip_address == "system"
        assert event.metadata["extra_key"] == "extra_val"

    def test_send_redis_event_no_agent(self, redis_config: SecurityConfig) -> None:
        """_send_redis_event returns early when no agent (line 45-46)."""
        mgr = RedisManager(redis_config)
        mgr.agent_handler = None
        mgr._send_redis_event("test", "test", "test")

    def test_send_redis_event_exception(self, redis_config: SecurityConfig) -> None:
        """_send_redis_event logs error on exception (lines 60-62)."""
        mgr = RedisManager(redis_config)
        agent = Mock()
        agent.send_event.side_effect = RuntimeError("agent down")
        mgr.initialize_agent(agent)

        mgr._send_redis_event("test", "test", "test")

    def test_close_with_connection(self, redis_config: SecurityConfig) -> None:
        """close() closes Redis connection and sends event (lines 109-120)."""
        mgr = RedisManager(redis_config)
        agent = Mock()
        mgr.initialize_agent(agent)

        mock_redis = MagicMock()
        mgr._redis = mock_redis

        mgr.close()

        mock_redis.close.assert_called_once()
        assert mgr._redis is None
        assert mgr._closed is True
        agent.send_event.assert_called_once()
        event = agent.send_event.call_args[0][0]
        assert event.action_taken == "connection_closed"

    def test_delete_pattern_no_keys(self, redis_config: SecurityConfig) -> None:
        """delete_pattern returns 0 when no keys match (line 282-283)."""
        mgr = RedisManager(redis_config)
        mgr._closed = False

        mock_redis = MagicMock()
        mock_redis.keys.return_value = []
        mgr._redis = mock_redis

        result = mgr.delete_pattern("nonexistent:*")

        assert result == 0
        mock_redis.delete.assert_not_called()


class TestRateLimitManagerRedis:
    """Tests for Redis-specific paths in RateLimitManager."""

    @pytest.fixture(autouse=True)
    def _clean_rate_limiter(self) -> None:
        RateLimitManager._instance = None

    def test_initialize_agent(self) -> None:
        """initialize_agent stores the agent handler (line 64)."""
        config = SecurityConfig(enable_redis=False)
        mgr = RateLimitManager(config)
        agent = Mock()
        mgr.initialize_agent(agent)
        assert mgr.agent_handler is agent

    def test_non_lua_fallback_path(self) -> None:
        """Pipeline fallback when no Lua script SHA (lines 96-103)."""
        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="flaskapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mgr.redis_handler = mock_redis_handler
        mgr.rate_limit_script_sha = None

        mock_conn = MagicMock()
        mock_pipeline = MagicMock()
        mock_pipeline.execute.return_value = [True, 0, 5, True]
        mock_pipeline.__enter__ = Mock(return_value=mock_pipeline)
        mock_pipeline.__exit__ = Mock(return_value=False)
        mock_conn.pipeline.return_value = mock_pipeline
        mock_conn.__enter__ = Mock(return_value=mock_conn)
        mock_conn.__exit__ = Mock(return_value=False)
        mock_redis_handler.get_connection.return_value = mock_conn

        result = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)

        assert result == 5
        mock_pipeline.zadd.assert_called_once()
        mock_pipeline.zremrangebyscore.assert_called_once()
        mock_pipeline.zcard.assert_called_once()
        mock_pipeline.expire.assert_called_once()

    def test_redis_error_fallback_to_none(self) -> None:
        """Redis error returns None so caller falls back to in-memory."""
        from redis.exceptions import RedisError

        config = SecurityConfig(
            enable_redis=True,
            redis_url="redis://localhost:6379",
            redis_prefix="flaskapi_guard_test:",
            rate_limit=10,
            rate_limit_window=60,
        )
        mgr = RateLimitManager(config)

        mock_redis_handler = MagicMock()
        mock_redis_handler.config = config
        mgr.redis_handler = mock_redis_handler
        mgr.rate_limit_script_sha = "fake_sha"

        mock_conn = MagicMock()
        mock_conn.evalsha.side_effect = RedisError("Connection lost")
        mock_redis_handler.get_connection.return_value.__enter__ = Mock(
            return_value=mock_conn
        )
        mock_redis_handler.get_connection.return_value.__exit__ = Mock(
            return_value=False
        )

        result = mgr._get_redis_request_count("1.2.3.4", time.time(), time.time() - 60)

        assert result is None
