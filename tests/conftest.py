import os
from collections.abc import Generator
from pathlib import Path

import pytest
from flask import Flask

from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.cloud_handler import cloud_handler
from flaskapi_guard.handlers.ipban_handler import reset_global_state
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager
from flaskapi_guard.handlers.ratelimit_handler import rate_limit_handler
from flaskapi_guard.handlers.suspatterns_handler import sus_patterns_handler
from flaskapi_guard.models import SecurityConfig

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))
REDIS_URL = str(os.getenv("REDIS_URL"))
REDIS_PREFIX = str(os.getenv("REDIS_PREFIX"))


@pytest.fixture(autouse=True)
def reset_state() -> Generator[None, None, None]:
    # Reset IPBanManager
    reset_global_state()

    # Reset SusPatternsManager
    original_patterns = sus_patterns_handler.patterns.copy()

    # Reset CloudManager
    cloud_instance = cloud_handler._instance
    if cloud_instance:
        cloud_instance.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
        cloud_instance.redis_handler = None

    # Reset IPInfoManager
    if IPInfoManager._instance:
        if IPInfoManager._instance.reader:
            IPInfoManager._instance.reader.close()
        IPInfoManager._instance = None

    yield
    sus_patterns_handler.patterns = original_patterns.copy()


@pytest.fixture
def security_config() -> SecurityConfig:
    """
    Fixture to create a SecurityConfig object for testing.

    Returns:
        SecurityConfig: A configured SecurityConfig object.
    """
    return SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN, None),
        enable_redis=False,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_countries=["CN"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture
def flaskapi_guard_app() -> Generator[tuple[Flask, FlaskAPIGuard], None, None]:
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        whitelist=[],
        blacklist=[],
        auto_ban_threshold=10,
        auto_ban_duration=300,
    )
    app = Flask(__name__)
    app.config["TESTING"] = True
    guard = FlaskAPIGuard(app, config=config)
    yield app, guard
    guard.reset()


@pytest.fixture(scope="session")
def ipinfo_db_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Shared temporary path for IPInfo database"""
    return tmp_path_factory.mktemp("ipinfo_data") / "country_asn.mmdb"


@pytest.fixture
def security_config_redis(ipinfo_db_path: Path) -> SecurityConfig:
    """SecurityConfig with Redis enabled"""
    return SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN, ipinfo_db_path),
        redis_url=REDIS_URL,
        redis_prefix=REDIS_PREFIX,
        whitelist=["127.0.0.1"],
        blacklist=["192.168.1.1"],
        blocked_countries=["CN"],
        blocked_user_agents=[r"badbot"],
        auto_ban_threshold=3,
        auto_ban_duration=300,
        custom_log_file="test_log.log",
        custom_error_responses={
            403: "Custom Forbidden",
            429: "Custom Too Many Requests",
        },
        enable_cors=True,
        cors_allow_origins=["https://example.com"],
        cors_allow_methods=["GET", "POST"],
        cors_allow_headers=["*"],
        cors_allow_credentials=True,
        cors_expose_headers=["X-Custom-Header"],
        cors_max_age=600,
    )


@pytest.fixture(autouse=True)
def redis_cleanup() -> None:
    """Clean Redis test keys before each test"""
    if not REDIS_URL or REDIS_URL == "None":
        return
    try:
        import redis as redis_lib

        r = redis_lib.Redis.from_url(REDIS_URL)
        try:
            # Clean all rate limit and guard keys regardless of prefix
            for pattern in [
                f"{REDIS_PREFIX}*",
                "flaskapi_guard:*",
                "*rate_limit:*",
            ]:
                keys = r.keys(pattern)
                if keys:
                    r.delete(*keys)
        finally:
            r.close()
    except Exception:
        pass


@pytest.fixture(autouse=True)
def reset_rate_limiter() -> None:
    """Reset rate limiter between tests to avoid interference"""
    try:
        config = SecurityConfig(
            geo_ip_handler=IPInfoManager(IPINFO_TOKEN, None),
            enable_redis=False,
        )
        rate_limit = rate_limit_handler(config)
        rate_limit.reset()
    except Exception:
        pass


@pytest.fixture
def clean_rate_limiter() -> None:
    """Reset rate limiter singleton for tests that need a completely clean state"""
    from flaskapi_guard.handlers.ratelimit_handler import RateLimitManager

    RateLimitManager._instance = None
