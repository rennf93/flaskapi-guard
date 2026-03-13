import threading
from collections.abc import Generator

import pytest

from flaskapi_guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    reset_global_state,
)


@pytest.fixture(autouse=True)
def cleanup() -> Generator[None, None, None]:
    """Reset global state before each test."""
    reset_global_state()
    yield
    reset_global_state()


def test_header_value_with_newline_rejected() -> None:
    """Test that header values with newlines are rejected."""
    manager = SecurityHeadersManager()

    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(custom_headers={"X-Custom": "value\r\nX-Injected: evil"})

    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(custom_headers={"X-Custom": "value\nX-Injected: evil"})


def test_header_value_too_long_rejected() -> None:
    """Test that excessively long header values are rejected."""
    manager = SecurityHeadersManager()

    long_value = "x" * 8193

    with pytest.raises(ValueError, match="Header value too long"):
        manager.configure(custom_headers={"X-Custom": long_value})


def test_control_characters_sanitized() -> None:
    """Test that control characters are removed from header values."""
    manager = SecurityHeadersManager()

    value_with_controls = "normal\x00\x01\x02\ttext\x1f"
    manager.configure(custom_headers={"X-Custom": value_with_controls})

    headers = manager.get_headers()
    assert headers["X-Custom"] == "normal\ttext"


def test_standard_headers_validated() -> None:
    """Test that standard security headers are validated."""
    manager = SecurityHeadersManager()

    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(frame_options="DENY\r\nX-Evil: true")

    with pytest.raises(ValueError, match="Invalid header value contains newline"):
        manager.configure(referrer_policy="no-referrer\nX-Evil: true")


def test_singleton_thread_safety() -> None:
    """Test that singleton is thread-safe under concurrent access."""
    instances: list[SecurityHeadersManager] = []
    barrier = threading.Barrier(10)

    def create_instance() -> None:
        barrier.wait()
        instance = SecurityHeadersManager()
        instances.append(instance)

    threads = []
    for _ in range(10):
        thread = threading.Thread(target=create_instance)
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert len(set(id(inst) for inst in instances)) == 1
    assert all(inst is instances[0] for inst in instances)


def test_singleton_initialization_once() -> None:
    """Test that singleton initialization happens only once."""
    reset_global_state()

    inst1 = SecurityHeadersManager()
    inst2 = SecurityHeadersManager()
    inst3 = SecurityHeadersManager()

    assert inst1 is inst2 is inst3
    assert id(inst1) == id(inst2) == id(inst3)


def test_cache_key_uses_hashing() -> None:
    """Test that cache keys are generated using secure hashing."""
    manager = SecurityHeadersManager()

    test_paths = [
        "/api/users",
        "/API/USERS",
        "/api/users/",
        "api/users",
    ]

    keys = []
    for path in test_paths:
        key = manager._generate_cache_key(path)
        keys.append(key)
        assert key.startswith("path_")
        assert len(key) == 21
        assert all(c in "0123456789abcdef" for c in key[5:])

    assert keys[0] == keys[1] == keys[2] == keys[3]


def test_cache_key_collision_resistance() -> None:
    """Test that similar paths generate different cache keys."""
    manager = SecurityHeadersManager()

    paths = [
        "/api/users/1",
        "/api/users/2",
        "/api/user/s1",
        "/api/use/rs1",
    ]

    keys = [manager._generate_cache_key(path) for path in paths]

    assert len(set(keys)) == len(keys)


def test_cache_key_default_path() -> None:
    """Test cache key generation for default/None path."""
    manager = SecurityHeadersManager()

    assert manager._generate_cache_key(None) == "default"
    assert manager._generate_cache_key("") == "default"


def test_hsts_preload_requires_long_max_age(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test HSTS preload requires max_age >= 31536000."""
    manager = SecurityHeadersManager()

    manager.configure(
        hsts_max_age=86400,
        hsts_preload=True,
        hsts_include_subdomains=True,
    )

    assert manager.hsts_config is not None
    assert manager.hsts_config["preload"] is False
    assert "HSTS preload requires max_age >= 31536000" in caplog.text


def test_hsts_preload_requires_include_subdomains(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test HSTS preload requires includeSubDomains."""
    manager = SecurityHeadersManager()

    manager.configure(
        hsts_max_age=31536000,
        hsts_preload=True,
        hsts_include_subdomains=False,
    )

    assert manager.hsts_config is not None
    assert manager.hsts_config["include_subdomains"] is True
    assert "HSTS preload requires includeSubDomains" in caplog.text


def test_hsts_valid_preload_configuration(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test valid HSTS preload configuration."""
    manager = SecurityHeadersManager()

    manager.configure(
        hsts_max_age=31536000,
        hsts_preload=True,
        hsts_include_subdomains=True,
    )

    assert manager.hsts_config is not None
    assert manager.hsts_config["preload"] is True
    assert manager.hsts_config["include_subdomains"] is True
    assert manager.hsts_config["max_age"] == 31536000

    assert "HSTS preload requires" not in caplog.text
