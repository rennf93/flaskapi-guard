import os
import time

from flask import Flask

from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.ipban_handler import ip_ban_manager
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager
from flaskapi_guard.handlers.redis_handler import redis_handler
from flaskapi_guard.models import SecurityConfig

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


def test_ip_ban_manager(reset_state: None) -> None:
    """
    Test the IPBanManager.
    """
    ip = "192.168.1.1"

    assert not ip_ban_manager.is_ip_banned(ip)

    ip_ban_manager.ban_ip(ip, 1)
    assert ip_ban_manager.is_ip_banned(ip)

    time.sleep(1.1)
    assert not ip_ban_manager.is_ip_banned(ip)


def test_automatic_ip_ban(reset_state: None) -> None:
    """
    Test the automatic IP banning.
    """
    app = Flask(__name__)
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        enable_ip_banning=True,
        enable_penetration_detection=True,
        auto_ban_threshold=3,
        auto_ban_duration=300,
    )
    FlaskAPIGuard(app, config=config)

    with app.test_client() as client:
        for _ in range(config.auto_ban_threshold):
            client.get(
                "/test?input=<script>alert(1)</script>",
                headers={"X-Forwarded-For": "192.168.1.2"},
            )

        response = client.get("/", headers={"X-Forwarded-For": "192.168.1.2"})
        assert response.status_code == 403


def test_reset_ip_ban_manager() -> None:
    """
    Test the IPBanManager reset method.
    """
    ip_ban_manager.ban_ip("test_ip", 3600)
    ip_ban_manager.reset()
    assert not ip_ban_manager.is_ip_banned("test_ip")


def test_ban_ip_concurrent_access() -> None:
    ip = "192.168.1.100"
    for _ in range(10):
        ip_ban_manager.ban_ip(ip, 1)
    assert ip_ban_manager.is_ip_banned(ip)


def test_ip_ban_manager_with_redis(security_config_redis: SecurityConfig) -> None:
    """Test IPBanManager with Redis integration"""
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    ip_ban_manager.initialize_redis(redis_mgr)

    ip = "192.168.1.1"
    duration = 2

    # Test banning
    ip_ban_manager.ban_ip(ip, duration)
    assert ip_ban_manager.is_ip_banned(ip)

    # Test Redis persistence
    new_manager = ip_ban_manager
    new_manager.initialize_redis(redis_mgr)
    assert new_manager.is_ip_banned(ip)

    # Test expiration
    time.sleep(2.1)
    assert not ip_ban_manager.is_ip_banned(ip)
    assert not new_manager.is_ip_banned(ip)

    redis_mgr.close()


def test_ip_ban_manager_redis_reset(
    security_config_redis: SecurityConfig,
) -> None:
    """Test IPBanManager reset with Redis"""
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    ip_ban_manager.initialize_redis(redis_mgr)

    # Ban multiple IPs
    ips = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    for ip in ips:
        ip_ban_manager.ban_ip(ip, 3600)
        assert ip_ban_manager.is_ip_banned(ip)

    # Reset and verify
    ip_ban_manager.reset()
    for ip in ips:
        assert not ip_ban_manager.is_ip_banned(ip)
        # Verify Redis keys are also cleared
        assert not redis_mgr.exists("banned_ips", ip)

    redis_mgr.close()


def test_ip_ban_manager_redis_expired_cleanup(
    security_config_redis: SecurityConfig,
) -> None:
    """Test cleanup of expired bans in Redis"""
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    ip_ban_manager.initialize_redis(redis_mgr)

    ip = "192.168.1.1"
    duration = 1

    # Ban the IP
    ip_ban_manager.ban_ip(ip, duration)
    assert ip_ban_manager.is_ip_banned(ip)

    # Clear local cache and manually set expired time in Redis
    ip_ban_manager.banned_ips.clear()
    past_expiry = str(time.time() - 10)
    redis_mgr.set_key("banned_ips", ip, past_expiry)

    # Check ban status - this should trigger the cleanup
    assert not ip_ban_manager.is_ip_banned(ip)

    # Verify the key was deleted from Redis
    assert not redis_mgr.exists("banned_ips", ip)

    redis_mgr.close()


def test_ban_in_redis_not_in_cache(security_config_redis: SecurityConfig) -> None:
    """Test when a ban exists in Redis but not in local cache"""
    redis_mgr = redis_handler(security_config_redis)
    redis_mgr.initialize()
    ip_ban_manager.initialize_redis(redis_mgr)

    ip_ban_manager.banned_ips.clear()

    ip = "192.168.100.100"
    # Future expiry in Redis (active ban)
    future_expiry = str(time.time() + 3600)  # 1 hour in the future
    redis_mgr.set_key("banned_ips", ip, future_expiry)

    # Before check - IP should not be in local cache
    assert ip not in ip_ban_manager.banned_ips

    # Finding active ban in Redis
    assert ip_ban_manager.is_ip_banned(ip)

    # IP in local cache with correct expiry
    assert ip in ip_ban_manager.banned_ips
    assert abs(ip_ban_manager.banned_ips[ip] - float(future_expiry)) < 0.01

    redis_mgr.close()
