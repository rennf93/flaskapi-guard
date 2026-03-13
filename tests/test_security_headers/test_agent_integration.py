from collections.abc import Generator
from typing import Any
from unittest.mock import MagicMock

import pytest

from flaskapi_guard.handlers.security_headers_handler import (
    SecurityHeadersManager,
    security_headers_manager,
)


@pytest.fixture
def headers_manager() -> Generator[SecurityHeadersManager, None, None]:
    """Create a fresh headers manager for testing."""
    # Reset before and after test
    security_headers_manager.reset()
    yield security_headers_manager
    security_headers_manager.reset()


def test_initialize_agent(headers_manager: SecurityHeadersManager) -> None:
    """Test Agent initialization for headers manager."""
    mock_agent = MagicMock()

    headers_manager.initialize_agent(mock_agent)

    assert headers_manager.agent_handler == mock_agent


def test_send_headers_applied_event_no_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test sending event when agent is not configured."""
    headers_manager.agent_handler = None

    # Should not raise when agent is None
    headers_manager._send_headers_applied_event(
        "/api/test", {"X-Content-Type-Options": "nosniff"}
    )


def test_send_headers_applied_event_with_mock_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test that _send_headers_applied_event attempts to send when agent configured."""
    # This tests the structure without requiring flaskapi_guard_agent module
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent

    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
    }

    # The method will try to import flaskapi_guard_agent.SecurityEvent
    # which won't exist in test environment, so it will catch the exception
    headers_manager._send_headers_applied_event("/api/test", headers)

    # The agent handler should still be set
    assert headers_manager.agent_handler == mock_agent


def test_send_headers_event_with_actual_exception(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test _send_headers_applied_event when send_event raises exception."""
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock(side_effect=Exception("Network error"))

    headers_manager.agent_handler = mock_agent

    # Mock the flaskapi_guard_agent module import
    import sys

    mock_flaskapi_guard_agent = MagicMock()
    mock_event_class = MagicMock()
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_flaskapi_guard_agent.SecurityEvent = mock_event_class

    # Temporarily add to sys.modules
    sys.modules["guard_agent"] = mock_flaskapi_guard_agent

    try:
        # Should not raise, just log debug
        headers_manager._send_headers_applied_event(
            "/api/test", {"X-Content-Type-Options": "nosniff"}
        )

        # Event should have been created
        mock_event_class.assert_called_once()

        # send_event should have been called and raised
        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
        # Clean up
        if "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]


def test_send_csp_violation_event_no_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test CSP violation event when agent is not configured."""
    headers_manager.agent_handler = None

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
    }

    # Should not raise when agent is None
    headers_manager._send_csp_violation_event(csp_report)


def test_send_csp_violation_event_with_mock_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test that _send_csp_violation_event attempts to send when agent configured."""
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com/page",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
        "source-file": "https://example.com/app.js",
        "line-number": 42,
    }

    # The method will try to import flaskapi_guard_agent.SecurityEvent
    # which won't exist in test environment, so it will catch the exception
    headers_manager._send_csp_violation_event(csp_report)

    # The agent handler should still be set
    assert headers_manager.agent_handler == mock_agent


def test_send_csp_violation_event_with_actual_exception(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test _send_csp_violation_event when send_event raises exception."""
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock(side_effect=Exception("API error"))

    headers_manager.agent_handler = mock_agent

    csp_report: dict[str, Any] = {
        "document-uri": "https://example.com",
        "violated-directive": "script-src",
        "blocked-uri": "https://evil.com/script.js",
    }

    # Mock the flaskapi_guard_agent module import
    import sys

    mock_flaskapi_guard_agent = MagicMock()
    mock_event_class = MagicMock()
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_flaskapi_guard_agent.SecurityEvent = mock_event_class

    # Temporarily add to sys.modules
    sys.modules["guard_agent"] = mock_flaskapi_guard_agent

    try:
        # Should not raise, just log debug
        headers_manager._send_csp_violation_event(csp_report)

        # Event should have been created
        mock_event_class.assert_called_once()

        # send_event should have been called and raised
        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
        # Clean up
        if "guard_agent" in sys.modules:
            del sys.modules["guard_agent"]


def test_validate_csp_report_with_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test CSP report validation with agent configured."""
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent

    valid_report = {
        "csp-report": {
            "document-uri": "https://example.com",
            "violated-directive": "script-src",
            "blocked-uri": "https://evil.com/script.js",
        }
    }

    result = headers_manager.validate_csp_report(valid_report)

    assert result is True
    # Agent handler should still be configured
    assert headers_manager.agent_handler == mock_agent


def test_get_headers_with_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test getting headers with agent configured."""
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent
    headers_manager.enabled = True

    # Get headers for a specific path
    headers = headers_manager.get_headers("/api/secure")

    # Should have default headers
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    # Agent handler should still be configured
    assert headers_manager.agent_handler == mock_agent


def test_get_headers_no_agent_no_path(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test getting headers without agent and without path."""
    headers_manager.agent_handler = None
    headers_manager.enabled = True

    # Get headers without path
    headers = headers_manager.get_headers()

    # Should have default headers
    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    # Cache key should be "default"
    assert "default" in headers_manager.headers_cache


def test_get_headers_disabled(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test getting headers when disabled."""
    headers_manager.enabled = False

    headers = headers_manager.get_headers("/test")

    assert headers == {}


def test_concurrent_access_thread_safety() -> None:
    """Test thread safety under concurrent access."""
    import threading

    manager = SecurityHeadersManager()

    results: list[dict[str, str]] = []
    lock = threading.Lock()

    def configure_and_get_headers(config_id: int) -> None:
        """Configure manager and get headers."""
        manager.configure(custom_headers={f"X-Thread-{config_id}": str(config_id)})
        headers = manager.get_headers(f"/path/{config_id}")
        with lock:
            results.append(headers)

    # Run multiple concurrent configurations
    threads = []
    for i in range(10):
        thread = threading.Thread(target=configure_and_get_headers, args=(i,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    # All results should be valid (no crashes/corruption)
    assert len(results) == 10
    for result in results:
        assert isinstance(result, dict)
        # Should have base security headers
        assert "X-Content-Type-Options" in result
