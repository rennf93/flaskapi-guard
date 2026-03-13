from typing import Any, cast

import pytest

from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager
from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.protocols.geo_ip_protocol import GeoIPHandler


def test_security_config_validation() -> None:
    valid_config = SecurityConfig(
        geo_ip_handler=IPInfoManager("valid_token"),
        whitelist=["10.0.0.0/24", "192.168.1.1"],
        blacklist=["203.0.113.0/25"],
    )
    assert valid_config.whitelist == ["10.0.0.0/24", "192.168.1.1"]


def test_invalid_ip_validation() -> None:
    with pytest.raises(ValueError):
        SecurityConfig(
            geo_ip_handler=IPInfoManager("test"),
            whitelist=["invalid.ip"],
            blacklist=["256.0.0.0"],
        )


def test_cloud_provider_validation() -> None:
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager("test"),
        block_cloud_providers={"AWS", "INVALID"},
    )
    assert config.block_cloud_providers == {"AWS"}


def test_security_config_none_whitelist() -> None:
    """Test that None whitelist is handled correctly"""
    config = SecurityConfig(geo_ip_handler=IPInfoManager("test"), whitelist=None)
    assert config.whitelist is None


def test_none_cloud_providers() -> None:
    """Test that None cloud_providers is handled correctly"""
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager("test"), block_cloud_providers=None
    )
    assert config.block_cloud_providers == set()


def test_missing_ipinfo_token() -> None:
    """Test that missing ipinfo_token and geo_ip_handler raises a ValueError"""
    with pytest.raises(ValueError):
        SecurityConfig(blocked_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(whitelist_countries=["US"])

    with pytest.raises(ValueError):
        SecurityConfig(blocked_countries=["US"], whitelist_countries=["US"])


class ValidGeoIPHandler:
    @property
    def is_initialized(self) -> bool:
        return True

    def initialize(self) -> None:
        return

    def initialize_redis(self, redis_handler: Any) -> None:
        return

    def initialize_agent(self, agent_handler: Any) -> None:
        return

    def get_country(self, ip: str) -> str | None:
        return None


def test_geo_ip_handler_validation() -> None:
    ipinfo = IPInfoManager(token="test")
    config = SecurityConfig(geo_ip_handler=ipinfo)
    assert config.geo_ip_handler == ipinfo

    valid_instance = ValidGeoIPHandler()
    config = SecurityConfig(geo_ip_handler=valid_instance)
    assert config.geo_ip_handler == valid_instance

    config = SecurityConfig(geo_ip_handler=None)
    assert config.geo_ip_handler is None

    class InvalidGeoIPHandler:
        pass

    invalid_handler = cast(GeoIPHandler, InvalidGeoIPHandler())
    with pytest.raises(ValueError):
        SecurityConfig(geo_ip_handler=invalid_handler)


def test_geo_ip_handler_deprecated_fallback() -> None:
    config = SecurityConfig(ipinfo_token="test", whitelist_countries=["US"])
    assert isinstance(config.geo_ip_handler, IPInfoManager)


def test_geo_ip_handler_sync_methods() -> None:
    """Test that sync methods in GeoIPHandler are called properly"""
    handler = ValidGeoIPHandler()

    handler.initialize()
    assert handler.is_initialized is True

    mock_redis = object()
    handler.initialize_redis(mock_redis)

    mock_agent = object()
    handler.initialize_agent(mock_agent)

    result = handler.get_country("192.168.1.1")
    assert result is None


def test_validate_trusted_proxies() -> None:
    """Test validation of trusted proxies."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1", "192.168.1.0/24"])
    assert "127.0.0.1" in config.trusted_proxies
    assert "192.168.1.0/24" in config.trusted_proxies

    with pytest.raises(ValueError, match="Invalid proxy IP or CIDR range"):
        SecurityConfig(trusted_proxies=["invalid-ip"])

    config = SecurityConfig(trusted_proxies=[])
    assert config.trusted_proxies == []


def test_validate_proxy_depth() -> None:
    """Test validation of trusted proxy depth."""
    config = SecurityConfig(trusted_proxy_depth=2)
    assert config.trusted_proxy_depth == 2

    with pytest.raises(ValueError, match="trusted_proxy_depth must be at least 1"):
        SecurityConfig(trusted_proxy_depth=0)


def test_validate_agent_config_missing_api_key() -> None:
    """Test that enable_agent without api_key raises ValueError."""
    with pytest.raises(ValueError, match="agent_api_key is required"):
        SecurityConfig(enable_agent=True)


def test_validate_agent_config_dynamic_rules_without_agent() -> None:
    """Test that enable_dynamic_rules without enable_agent raises ValueError."""
    with pytest.raises(ValueError, match="enable_agent must be True"):
        SecurityConfig(enable_dynamic_rules=True, enable_agent=False)


def test_to_agent_config_disabled() -> None:
    """Test to_agent_config returns None when agent is disabled."""
    config = SecurityConfig(enable_agent=False)
    assert config.to_agent_config() is None


def test_to_agent_config_no_api_key() -> None:
    """Test to_agent_config returns None when no api_key."""
    config = SecurityConfig(enable_agent=False, agent_api_key=None)
    assert config.to_agent_config() is None


def test_to_agent_config_import_error() -> None:
    """Test to_agent_config returns None on ImportError."""
    import sys
    from unittest.mock import patch

    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
    )

    with patch.dict(sys.modules, {"guard_agent": None}):
        result = config.to_agent_config()
        assert result is None


def test_to_agent_config_success() -> None:
    """Test to_agent_config returns AgentConfig when properly configured."""
    import sys
    import types

    config = SecurityConfig(
        enable_agent=True,
        agent_api_key="test-key",
        agent_endpoint="https://api.example.com",
        agent_project_id="proj-123",
        agent_buffer_size=50,
        agent_flush_interval=15,
        agent_enable_events=True,
        agent_enable_metrics=True,
        agent_timeout=10,
        agent_retry_attempts=2,
    )

    mock_module = types.ModuleType("guard_agent")

    class MockAgentConfig:
        def __init__(self, **kwargs: Any) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    mock_module.AgentConfig = MockAgentConfig  # type: ignore[attr-defined]

    original = sys.modules.get("guard_agent")
    sys.modules["guard_agent"] = mock_module
    try:
        result = config.to_agent_config()
        assert result is not None
        assert result.api_key == "test-key"
        assert result.endpoint == "https://api.example.com"
        assert result.project_id == "proj-123"
        assert result.buffer_size == 50
        assert result.flush_interval == 15
        assert result.timeout == 10
        assert result.retry_attempts == 2
    finally:
        if original:
            sys.modules["guard_agent"] = original
        else:
            sys.modules.pop("guard_agent", None)
