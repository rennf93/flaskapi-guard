import os
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from pytest_mock import MockerFixture
from redis.exceptions import ConnectionError
from werkzeug.exceptions import InternalServerError

from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager
from flaskapi_guard.handlers.redis_handler import redis_handler
from flaskapi_guard.models import SecurityConfig

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


def test_redis_basic_operations(security_config_redis: SecurityConfig) -> None:
    """Test basic Redis operations"""
    handler = redis_handler(security_config_redis)
    handler.initialize()

    # Test set and get
    handler.set_key("test", "key1", "value1")
    value = handler.get_key("test", "key1")
    assert value == "value1"

    # Test exists
    exists = handler.exists("test", "key1")
    assert exists is True

    # Test delete
    handler.delete("test", "key1")
    exists = handler.exists("test", "key1")
    assert exists is False

    handler.close()


def test_redis_disabled(security_config: SecurityConfig) -> None:
    """Test Redis operations when disabled"""
    handler = redis_handler(security_config)
    handler.initialize()

    assert not security_config.enable_redis
    assert handler._redis is None
    result = handler.set_key("test", "key1", "value1")
    assert result is None
    value = handler.get_key("test", "key1")
    assert value is None


def test_redis_error_handling(security_config_redis: SecurityConfig) -> None:
    """Test Redis error handling"""
    handler = redis_handler(security_config_redis)
    handler.initialize()

    def _fail_operation(conn: Any) -> None:
        raise ConnectionError("Test connection error")

    with pytest.raises(InternalServerError):
        handler.safe_operation(_fail_operation)

    handler.close()


def test_redis_connection_retry(
    security_config_redis: SecurityConfig, mocker: MockerFixture
) -> None:
    """Test Redis connection retry mechanism"""
    handler = redis_handler(security_config_redis)
    handler.initialize()

    # Mock the Redis get method
    mock_get = MagicMock(side_effect=ConnectionError("Test connection error"))
    if handler._redis:
        mocker.patch.object(handler._redis, "get", mock_get)

    with pytest.raises(InternalServerError):
        handler.get_key("test", "retry")


def test_redis_ttl_operations(security_config_redis: SecurityConfig) -> None:
    """Test Redis TTL operations"""
    handler = redis_handler(security_config_redis)
    handler.initialize()

    # Test set with TTL
    handler.set_key("test", "ttl_key", "value", ttl=1)
    value = handler.get_key("test", "ttl_key")
    assert value == "value"

    # Wait for TTL to expire
    time.sleep(1.1)
    value = handler.get_key("test", "ttl_key")
    assert value is None

    handler.close()


def test_redis_increment_operations(
    security_config_redis: SecurityConfig,
) -> None:
    """Test Redis increment operations"""
    handler = redis_handler(security_config_redis)
    handler.initialize()

    # Clean up stale keys from previous test runs
    with handler.get_connection() as conn:
        prefix = security_config_redis.redis_prefix
        conn.delete(f"{prefix}test:counter")
        conn.delete(f"{prefix}test:ttl_counter")

    # Test increment without TTL
    value = handler.incr("test", "counter")
    assert value == 1
    value = handler.incr("test", "counter")
    assert value == 2

    # Test increment with TTL
    value = handler.incr("test", "ttl_counter", ttl=1)
    assert value == 1
    time.sleep(1.1)
    exists = handler.exists("test", "ttl_counter")
    assert not exists

    handler.close()


def test_redis_connection_context_get_error(
    security_config_redis: SecurityConfig, monkeypatch: Any
) -> None:
    """Test Redis connection get operation with error"""
    handler = redis_handler(security_config_redis)
    handler.initialize()

    def mock_get(*args: Any, **kwargs: Any) -> None:
        raise ConnectionError("Test connection error on get")

    with pytest.raises(InternalServerError):
        with handler.get_connection() as conn:
            monkeypatch.setattr(conn, "get", mock_get)
            conn.get("test:key")

    handler.close()


def test_redis_connection_failures(security_config_redis: SecurityConfig) -> None:
    """Test Redis connection failure scenarios"""
    # Test initialization failure
    bad_config = SecurityConfig(
        **{
            **security_config_redis.model_dump(),
            "redis_url": "redis://nonexistent:6379",
        }
    )
    handler = redis_handler(bad_config)
    with pytest.raises(InternalServerError):
        handler.initialize()
    assert handler._redis is None

    # Test with valid config but force connection failure
    handler = redis_handler(security_config_redis)
    handler.initialize()

    # Test operation after connection drop
    handler.close()
    with pytest.raises(InternalServerError):
        handler.get_key("test", "key")

    # Test safe_operation with null connection
    handler._redis = None
    with pytest.raises(InternalServerError):
        handler.safe_operation(lambda conn: conn.get("test:key"))


def test_redis_disabled_operations(security_config_redis: SecurityConfig) -> None:
    """Test Redis operations when Redis is disabled"""
    security_config_redis.enable_redis = False
    handler = redis_handler(security_config_redis)

    # All operations should return None when Redis is disabled
    assert handler.get_key("test", "key") is None
    assert handler.set_key("test", "key", "value") is None
    assert handler.incr("test", "counter") is None
    assert handler.exists("test", "key") is None
    assert handler.delete("test", "key") is None


def test_redis_failed_initialization_operations(
    security_config_redis: SecurityConfig,
) -> None:
    """Test operations after failed initialization"""
    bad_config = SecurityConfig(
        **{**security_config_redis.model_dump(), "redis_url": "redis://invalid:6379"}
    )
    handler = redis_handler(bad_config)

    with pytest.raises(InternalServerError):
        handler.get_key("test", "key")

    with pytest.raises(InternalServerError):
        handler.set_key("test", "key", "value")


def test_redis_url_none(security_config_redis: SecurityConfig) -> None:
    """Test Redis initialization when redis_url is None"""
    security_config_redis.redis_url = None

    handler = redis_handler(security_config_redis)

    with patch("logging.Logger.warning") as mock_warning:
        handler.initialize()
        mock_warning.assert_called_once_with("Redis URL is None, skipping connection")
        assert handler._redis is None


def test_safe_operation_redis_disabled(security_config: SecurityConfig) -> None:
    """Test safe_operation when Redis is disabled"""
    handler = redis_handler(security_config)

    mock_func = MagicMock()
    result = handler.safe_operation(mock_func)

    assert result is None
    mock_func.assert_not_called()


def test_connection_context_redis_none(
    security_config_redis: SecurityConfig, monkeypatch: Any
) -> None:
    """Test when Redis is None after initialization attempt"""
    handler = redis_handler(security_config_redis)

    initialize_called = False

    def mocked_initialize() -> None:
        nonlocal initialize_called
        initialize_called = True

    monkeypatch.setattr(handler, "initialize", mocked_initialize)

    handler._closed = False
    handler._redis = None

    with pytest.raises(InternalServerError) as exc_info:
        with handler.get_connection():
            pass

    assert initialize_called, "initialize() was not called"
    assert "Redis connection failed" in str(exc_info.value.description)


def test_redis_keys_and_delete_pattern_with_redis_disabled() -> None:
    """Test keys and delete_pattern functions when Redis is disabled"""
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN), enable_redis=False
    )
    handler = redis_handler(config)

    keys_result = handler.keys("*")
    assert keys_result is None

    delete_result = handler.delete_pattern("*")
    assert delete_result is None
