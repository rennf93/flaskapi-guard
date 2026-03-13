import json
from collections.abc import Generator
from unittest.mock import MagicMock, patch

import pytest

from flaskapi_guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)


@pytest.fixture
def headers_manager() -> Generator[SecurityHeadersManager, None, None]:
    """Create a fresh headers manager for testing."""
    # Save the original redis_handler
    original_redis = security_headers_manager.redis_handler
    # Set to None to avoid warnings during reset
    security_headers_manager.redis_handler = None

    # Reset before test
    security_headers_manager.reset()

    yield security_headers_manager

    # Clean up: set to None before reset to avoid warnings
    security_headers_manager.redis_handler = None
    security_headers_manager.reset()

    # Restore the original redis_handler
    security_headers_manager.redis_handler = original_redis


def test_initialize_redis(headers_manager: SecurityHeadersManager) -> None:
    """Test Redis initialization for headers manager."""
    mock_redis = MagicMock()
    mock_redis.get_key = MagicMock(return_value=None)

    headers_manager.initialize_redis(mock_redis)

    assert headers_manager.redis_handler == mock_redis
    # Should attempt to load cached config
    mock_redis.get_key.assert_called()


def test_load_cached_config_from_redis(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test loading cached configuration from Redis."""
    mock_redis = MagicMock()

    # Mock cached CSP config
    csp_config = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdn.com"],
    }
    mock_redis.get_key = MagicMock(
        side_effect=[
            json.dumps(csp_config),  # CSP config
            json.dumps(
                {"max_age": 31536000, "include_subdomains": True}
            ),  # HSTS config
            json.dumps({"X-Custom": "value"}),  # Custom headers
        ]
    )

    headers_manager.redis_handler = mock_redis
    headers_manager._load_cached_config()

    assert headers_manager.csp_config == csp_config
    assert headers_manager.hsts_config is not None
    assert headers_manager.hsts_config["max_age"] == 31536000
    assert headers_manager.custom_headers["X-Custom"] == "value"

    # Verify Redis calls
    assert mock_redis.get_key.call_count == 3
    mock_redis.get_key.assert_any_call("security_headers", "csp_config")
    mock_redis.get_key.assert_any_call("security_headers", "hsts_config")
    mock_redis.get_key.assert_any_call("security_headers", "custom_headers")


def test_load_cached_config_redis_error(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test handling Redis errors when loading cached config."""
    mock_redis = MagicMock()
    mock_redis.get_key = MagicMock(side_effect=Exception("Redis connection error"))

    headers_manager.redis_handler = mock_redis

    # Should not raise, just log warning
    headers_manager._load_cached_config()

    # Config should remain unchanged
    assert headers_manager.csp_config is None
    assert headers_manager.hsts_config is None


def test_load_cached_config_no_redis_handler(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test _load_cached_config returns early when no Redis handler."""
    # Ensure redis_handler is None
    headers_manager.redis_handler = None

    # Should return early without any errors
    headers_manager._load_cached_config()

    # Config should remain as initialized
    assert headers_manager.csp_config is None
    assert headers_manager.hsts_config is None


def test_cache_configuration_to_redis(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test caching configuration to Redis."""
    mock_redis = MagicMock()
    mock_redis.set_key = MagicMock()

    headers_manager.redis_handler = mock_redis
    headers_manager.csp_config = {"default-src": ["'self'"]}
    headers_manager.hsts_config = {"max_age": 31536000}
    headers_manager.custom_headers = {"X-Custom": "value"}

    headers_manager._cache_configuration()

    # Verify all configs were cached
    assert mock_redis.set_key.call_count == 3
    mock_redis.set_key.assert_any_call(
        "security_headers",
        "csp_config",
        json.dumps({"default-src": ["'self'"]}),
        ttl=86400,
    )
    mock_redis.set_key.assert_any_call(
        "security_headers", "hsts_config", json.dumps({"max_age": 31536000}), ttl=86400
    )
    mock_redis.set_key.assert_any_call(
        "security_headers",
        "custom_headers",
        json.dumps({"X-Custom": "value"}),
        ttl=86400,
    )


def test_cache_configuration_redis_error(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test handling Redis errors when caching configuration."""
    mock_redis = MagicMock()
    mock_redis.set_key = MagicMock(side_effect=Exception("Redis write error"))

    headers_manager.redis_handler = mock_redis
    headers_manager.csp_config = {"default-src": ["'self'"]}

    # Should not raise, just log warning
    headers_manager._cache_configuration()


def test_cache_configuration_no_redis(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test caching when Redis is not configured."""
    headers_manager.redis_handler = None
    headers_manager.csp_config = {"default-src": ["'self'"]}

    # Should return early without error
    headers_manager._cache_configuration()


def test_cache_configuration_partial_config(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test caching when only some configurations are set."""
    mock_redis = MagicMock()
    mock_redis.set_key = MagicMock()

    mock_conn = MagicMock()
    mock_conn.keys = MagicMock(return_value=[])
    mock_conn.delete = MagicMock()

    mock_context = MagicMock()
    mock_context.__enter__ = MagicMock(return_value=mock_conn)
    mock_context.__exit__ = MagicMock()

    mock_redis.get_connection = MagicMock(return_value=mock_context)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "flaskapi_guard:"

    headers_manager.redis_handler = mock_redis
    # Only set CSP config, not HSTS or custom headers
    headers_manager.csp_config = {"default-src": ["'self'"]}
    headers_manager.hsts_config = None
    headers_manager.custom_headers = {}

    headers_manager._cache_configuration()

    # Should only cache CSP config
    mock_redis.set_key.assert_called_once_with(
        "security_headers",
        "csp_config",
        json.dumps({"default-src": ["'self'"]}),
        ttl=86400,
    )


def test_reset_with_redis_proper_sync(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test reset functionality with Redis using proper sync context manager."""
    with patch.object(headers_manager, "redis_handler") as mock_redis:
        mock_conn = MagicMock()
        mock_conn.keys = MagicMock(
            return_value=[
                b"flaskapi_guard:security_headers:csp_config",
                b"flaskapi_guard:security_headers:custom_headers",
            ]
        )
        mock_conn.delete = MagicMock()

        # Setup context manager
        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock()

        mock_redis.get_connection.return_value = mock_context
        mock_redis.config.redis_prefix = "flaskapi_guard:"

        headers_manager.custom_headers = {"X-Test": "value"}
        headers_manager.csp_config = {"default-src": ["'self'"]}

        headers_manager.reset()

        # Verify state is reset
        assert len(headers_manager.custom_headers) == 0
        assert headers_manager.csp_config is None


def test_reset_with_empty_redis_keys(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test reset when Redis returns no keys."""
    with patch.object(headers_manager, "redis_handler") as mock_redis:
        mock_conn = MagicMock()
        mock_conn.keys = MagicMock(return_value=[])  # No keys found
        mock_conn.delete = MagicMock()

        # Setup context manager
        mock_context = MagicMock()
        mock_context.__enter__ = MagicMock(return_value=mock_conn)
        mock_context.__exit__ = MagicMock()

        mock_redis.get_connection.return_value = mock_context
        mock_redis.config.redis_prefix = "flaskapi_guard:"

        headers_manager.custom_headers = {"X-Test": "value"}

        headers_manager.reset()

        # Verify state is reset
        assert len(headers_manager.custom_headers) == 0

        # keys should be called but delete should not (no keys to delete)
        mock_conn.keys.assert_called_once_with("flaskapi_guard:security_headers:*")
        mock_conn.delete.assert_not_called()


def test_reset_redis_error(headers_manager: SecurityHeadersManager) -> None:
    """Test reset with Redis errors."""
    # Create a context manager that fails on connection
    mock_context = MagicMock()
    mock_context.__enter__ = MagicMock(side_effect=Exception("Connection failed"))
    mock_context.__exit__ = MagicMock()

    # Create mock redis that fails on connection
    mock_redis = MagicMock()
    mock_redis.get_connection.return_value = mock_context
    mock_redis.config.redis_prefix = "flaskapi_guard:"

    headers_manager.redis_handler = mock_redis
    headers_manager.custom_headers = {"X-Test": "value"}

    # Should not raise, just log warning
    headers_manager.reset()

    # Local state should still be reset
    assert len(headers_manager.custom_headers) == 0
    assert headers_manager.enabled


def test_reset_without_redis(headers_manager: SecurityHeadersManager) -> None:
    """Test reset without Redis configured."""
    headers_manager.redis_handler = None
    headers_manager.custom_headers = {"X-Test": "value"}
    headers_manager.csp_config = {"default-src": ["'self'"]}

    headers_manager.reset()

    # State should be reset
    assert len(headers_manager.custom_headers) == 0
    assert headers_manager.csp_config is None


def test_initialize_redis_and_cache_configuration(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test Redis initialization triggers caching of configuration."""
    mock_redis = MagicMock()
    mock_redis.get_key = MagicMock(return_value=None)
    mock_redis.set_key = MagicMock()

    mock_conn = MagicMock()
    mock_conn.keys = MagicMock(return_value=[])
    mock_conn.delete = MagicMock()

    mock_context = MagicMock()
    mock_context.__enter__ = MagicMock(return_value=mock_conn)
    mock_context.__exit__ = MagicMock()

    mock_redis.get_connection = MagicMock(return_value=mock_context)
    mock_redis.config = MagicMock()
    mock_redis.config.redis_prefix = "flaskapi_guard:"

    # Set some configuration before initialization
    headers_manager.configure(
        csp={"default-src": ["'self'"]},
        hsts_max_age=31536000,
        custom_headers={"X-Custom": "value"},
    )

    headers_manager.initialize_redis(mock_redis)

    assert headers_manager.redis_handler == mock_redis

    # Should have tried to load cached config
    assert mock_redis.get_key.call_count == 3  # CSP, HSTS, custom headers

    # Should have cached the configuration
    assert mock_redis.set_key.call_count == 3  # CSP, HSTS, custom headers
