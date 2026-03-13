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

    headers_manager._send_headers_applied_event(
        "/api/test", {"X-Content-Type-Options": "nosniff"}
    )


def test_send_headers_applied_event_with_mock_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test that _send_headers_applied_event attempts to send when agent configured."""
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent

    headers = {
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=31536000",
    }

    headers_manager._send_headers_applied_event("/api/test", headers)

    assert headers_manager.agent_handler == mock_agent


def test_send_headers_event_with_actual_exception(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test _send_headers_applied_event when send_event raises exception."""
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock(side_effect=Exception("Network error"))

    headers_manager.agent_handler = mock_agent

    import sys

    mock_flaskapi_guard_agent = MagicMock()
    mock_event_class = MagicMock()
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_flaskapi_guard_agent.SecurityEvent = mock_event_class

    sys.modules["guard_agent"] = mock_flaskapi_guard_agent

    try:
        headers_manager._send_headers_applied_event(
            "/api/test", {"X-Content-Type-Options": "nosniff"}
        )

        mock_event_class.assert_called_once()

        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
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

    headers_manager._send_csp_violation_event(csp_report)

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

    import sys

    mock_flaskapi_guard_agent = MagicMock()
    mock_event_class = MagicMock()
    mock_event_instance = MagicMock()
    mock_event_class.return_value = mock_event_instance
    mock_flaskapi_guard_agent.SecurityEvent = mock_event_class

    sys.modules["guard_agent"] = mock_flaskapi_guard_agent

    try:
        headers_manager._send_csp_violation_event(csp_report)

        mock_event_class.assert_called_once()

        mock_agent.send_event.assert_called_once_with(mock_event_instance)
    finally:
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
    assert headers_manager.agent_handler == mock_agent


def test_get_headers_with_agent(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test getting headers with agent configured."""
    mock_agent = MagicMock()
    mock_agent.send_event = MagicMock()

    headers_manager.agent_handler = mock_agent
    headers_manager.enabled = True

    headers = headers_manager.get_headers("/api/secure")

    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

    assert headers_manager.agent_handler == mock_agent


def test_get_headers_no_agent_no_path(
    headers_manager: SecurityHeadersManager,
) -> None:
    """Test getting headers without agent and without path."""
    headers_manager.agent_handler = None
    headers_manager.enabled = True

    headers = headers_manager.get_headers()

    assert "X-Content-Type-Options" in headers
    assert "X-Frame-Options" in headers

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

    threads = []
    for i in range(10):
        thread = threading.Thread(target=configure_and_get_headers, args=(i,))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    assert len(results) == 10
    for result in results:
        assert isinstance(result, dict)
        assert "X-Content-Type-Options" in result
