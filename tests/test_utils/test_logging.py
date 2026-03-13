import logging
import os
from typing import Any, Literal
from unittest.mock import patch

import pytest
from flask import Flask
from pytest_mock import MockerFixture

from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.behavior_handler import BehaviorRule, BehaviorTracker
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager
from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.utils import (
    is_ip_allowed,
    is_user_agent_allowed,
    log_activity,
    setup_custom_logging,
)

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


def test_is_ip_allowed(security_config: SecurityConfig, mocker: MockerFixture) -> None:
    """
    Test the is_ip_allowed function
    with various IP addresses.
    """
    mocker.patch("flaskapi_guard.utils.check_ip_country", return_value=False)

    assert is_ip_allowed("127.0.0.1", security_config)
    assert not is_ip_allowed("192.168.1.1", security_config)

    empty_config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN), whitelist=[], blacklist=[]
    )
    assert is_ip_allowed("127.0.0.1", empty_config)
    assert is_ip_allowed("192.168.1.1", empty_config)

    whitelist_config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN), whitelist=["127.0.0.1"]
    )
    assert is_ip_allowed("127.0.0.1", whitelist_config)
    assert not is_ip_allowed("192.168.1.1", whitelist_config)

    blacklist_config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN), blacklist=["192.168.1.1"]
    )
    assert is_ip_allowed("127.0.0.1", blacklist_config)
    assert not is_ip_allowed("192.168.1.1", blacklist_config)


def test_is_user_agent_allowed(security_config: SecurityConfig) -> None:
    """
    Test the is_user_agent_allowed function
    with allowed and blocked user agents.
    """
    assert is_user_agent_allowed("goodbot", security_config)
    assert not is_user_agent_allowed("badbot", security_config)


def test_custom_logging(
    reset_state: None, security_config: SecurityConfig, tmp_path: Any
) -> None:
    """
    Test the custom logging.
    """
    log_file = tmp_path / "test_log.log"
    logger = setup_custom_logging(str(log_file))

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"User-Agent": "test-agent"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        log_activity(request, logger)

    with open(log_file) as f:
        log_content = f.read()
        assert "Request from 127.0.0.1: GET" in log_content


def test_log_request(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test the log_request function to ensure
    it logs the request details correctly.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"User-Agent": "test-agent"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        logger = logging.getLogger(__name__)
        with caplog.at_level(logging.INFO):
            log_activity(request, logger)

    assert "Request from 127.0.0.1: GET" in caplog.text
    assert "Headers:" in caplog.text


def test_log_suspicious_activity(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test the log_activity function with suspicious activity.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"User-Agent": "test-agent"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        logger = logging.getLogger(__name__)
        with caplog.at_level(logging.WARNING):
            log_activity(
                request,
                logger,
                log_type="suspicious",
                reason="Suspicious activity detected",
            )

    assert "Suspicious activity detected" in caplog.text
    assert "127.0.0.1" in caplog.text
    assert "GET" in caplog.text


def test_log_suspicious_activity_passive_mode(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """
    Test the log_activity function with suspicious activity in passive mode.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"User-Agent": "test-agent"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        logger = logging.getLogger(__name__)
        with caplog.at_level(logging.WARNING):
            log_activity(
                request,
                logger,
                log_type="suspicious",
                reason="Suspicious activity detected",
                passive_mode=True,
                trigger_info="SQL injection attempt",
            )

    assert "[PASSIVE MODE] Penetration attempt detected from" in caplog.text
    assert "127.0.0.1" in caplog.text
    assert "GET" in caplog.text
    assert "Trigger: SQL injection attempt" in caplog.text


def test_log_custom_type(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test the log_activity function with a custom log type.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"User-Agent": "test-agent"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        logger = logging.getLogger(__name__)
        with caplog.at_level(logging.WARNING):
            log_activity(
                request, logger, log_type="custom_event", reason="Custom event reason"
            )

    assert "Custom_event from 127.0.0.1: GET" in caplog.text
    assert "Details: Custom event reason" in caplog.text
    assert "Headers:" in caplog.text


def test_setup_custom_logging() -> None:
    """
    Test the setup_custom_logging function.
    """
    log_file = os.path.join(os.getcwd(), "security.log")
    logger = setup_custom_logging(log_file)

    handler_count = sum(
        1
        for h in logger.handlers
        if isinstance(h, logging.FileHandler | logging.StreamHandler)
    )
    assert handler_count >= 2


def test_no_duplicate_logs(caplog: pytest.LogCaptureFixture, tmp_path: Any) -> None:
    """
    Test that our logging setup doesn't cause duplicate log messages.

    This verifies that even though we allow propagation, the hierarchical
    namespace prevents duplicate console output.
    """
    log_file = tmp_path / "test_no_duplicates.log"

    guard_logger = setup_custom_logging(str(log_file))

    root_logger = logging.getLogger()
    original_handlers = root_logger.handlers.copy()
    original_level = root_logger.level

    root_handler = logging.StreamHandler()
    root_handler.setFormatter(logging.Formatter("ROOT: %(message)s"))
    root_logger.addHandler(root_handler)
    root_logger.setLevel(logging.INFO)

    try:
        caplog.clear()
        caplog.set_level(logging.INFO)

        test_message = "Test message for duplicate check"
        guard_logger.info(test_message)

        matching_records = [r for r in caplog.records if test_message in r.message]

        assert len(matching_records) > 0, "Message should be logged"

        seen = set()
        for record in matching_records:
            key = (record.name, record.message, record.levelname)
            assert key not in seen, f"Duplicate log found: {key}"
            seen.add(key)

        with open(log_file) as f:
            file_content = f.read()
            assert test_message in file_content
            assert file_content.count(test_message) == 1, (
                "Message should appear once in log file"
            )

    finally:
        root_logger.handlers = original_handlers
        root_logger.setLevel(original_level)


def test_hierarchical_namespace_isolation() -> None:
    """
    Test that our hierarchical namespace properly isolates Flask API Guard logs.

    This ensures that flaskapi_guard.* loggers are separate from user loggers.
    """
    guard_logger = logging.getLogger("flaskapi_guard")
    guard_handler_logger = logging.getLogger("flaskapi_guard.handlers.redis")
    user_logger = logging.getLogger("myapp")

    assert guard_handler_logger.parent == guard_logger
    assert guard_logger.parent == logging.getLogger()
    assert user_logger.parent == logging.getLogger()

    assert guard_logger is not user_logger
    assert guard_handler_logger is not user_logger

    assert guard_logger.name == "flaskapi_guard"
    assert guard_handler_logger.name == "flaskapi_guard.handlers.redis"
    assert user_logger.name == "myapp"


def test_custom_log_file_configuration(tmp_path: Any) -> None:
    """
    Test that custom_log_file configuration is properly used.
    """
    custom_log_path = tmp_path / "my_custom_security.log"
    logger = setup_custom_logging(str(custom_log_path))

    test_message = "Custom log file test"
    logger.info(test_message)

    assert custom_log_path.exists(), "Custom log file should be created"
    with open(custom_log_path) as f:
        content = f.read()
        assert test_message in content

    logger_no_file = setup_custom_logging(None)

    file_handlers = [
        h for h in logger_no_file.handlers if isinstance(h, logging.FileHandler)
    ]
    stream_handlers = [
        h for h in logger_no_file.handlers if isinstance(h, logging.StreamHandler)
    ]

    assert len(file_handlers) == 0, "Should have no file handlers when log_file is None"
    assert len(stream_handlers) >= 1, (
        "Should have at least one stream handler for console"
    )


def test_console_always_enabled(caplog: pytest.LogCaptureFixture) -> None:
    """
    Test that console output is ALWAYS enabled regardless of file configuration.
    """
    logger_no_file = setup_custom_logging(None)

    caplog.clear()
    caplog.set_level(logging.INFO)

    test_message = "Console output test - no file"
    logger_no_file.info(test_message)

    assert test_message in caplog.text, "Console output should work without file"

    import tempfile

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tmp_file:
        logger_with_file = setup_custom_logging(tmp_file.name)

        caplog.clear()
        test_message_2 = "Console output test - with file"
        logger_with_file.info(test_message_2)

        assert test_message_2 in caplog.text, "Console output should work with file"

        os.unlink(tmp_file.name)


def test_setup_custom_logging_creates_directory(tmp_path: Any) -> None:
    """
    Test that setup_custom_logging creates directory if it doesn't exist.
    """
    non_existent_dir = tmp_path / "logs" / "subdirectory" / "deep"
    log_file_path = non_existent_dir / "test.log"

    assert not non_existent_dir.exists(), "Directory should not exist initially"

    logger = setup_custom_logging(str(log_file_path))

    assert non_existent_dir.exists(), "Directory should be created"

    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert len(file_handlers) == 1, "Should have exactly one file handler"

    test_message = "Directory creation test"
    logger.info(test_message)

    assert log_file_path.exists(), "Log file should be created"
    with open(log_file_path) as f:
        content = f.read()
        assert test_message in content


def test_setup_custom_logging_file_handler_exception(
    caplog: pytest.LogCaptureFixture, mocker: MockerFixture
) -> None:
    """
    Test that setup_custom_logging handles exceptions when creating file handler.
    """
    mocker.patch("os.path.exists", return_value=True)
    mocker.patch(
        "flaskapi_guard.utils.logging.FileHandler",
        side_effect=PermissionError("Permission denied: cannot create log file"),
    )

    caplog.clear()
    caplog.set_level(logging.WARNING, logger="flaskapi_guard")

    logger = setup_custom_logging("/invalid/path/test.log")

    assert "Failed to create log file /invalid/path/test.log" in caplog.text
    assert "Permission denied" in caplog.text or "cannot create log file" in caplog.text

    assert logger is not None

    assert len(logger.handlers) == 1, "Should have exactly one handler"
    assert isinstance(logger.handlers[0], logging.StreamHandler), (
        "Should have console handler"
    )

    caplog.clear()
    caplog.set_level(logging.INFO, logger="flaskapi_guard")
    test_message = "Console still works after file handler failure"
    logger.info(test_message)
    assert test_message in caplog.text


def test_log_level(caplog: pytest.LogCaptureFixture) -> None:
    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"User-Agent": "test-agent"},
    ):
        from flask import request

        logger = logging.getLogger(__name__)

        LOG_LEVELS: list[
            Literal["INFO", "DEBUG", "WARNING", "ERROR", "CRITICAL"] | None
        ] = [
            "INFO",
            "DEBUG",
            "WARNING",
            "ERROR",
            "CRITICAL",
            None,
        ]

        for level in LOG_LEVELS:
            caplog.clear()

            with caplog.at_level(logging.DEBUG):
                log_activity(request, logger, level=level)

            if level is not None:
                assert len(caplog.records) == 1
                assert caplog.records[0].levelname == level
            else:
                assert len(caplog.records) == 0


def test_passive_mode_rate_limiting_scenarios(
    security_config: SecurityConfig,
) -> None:
    """
    Test passive mode rate limiting.
    """
    security_config.passive_mode = True
    security_config.enable_redis = False
    security_config.endpoint_rate_limits = {"/api/test": (1, 60)}

    app = Flask(__name__)
    guard = FlaskAPIGuard(app, config=security_config)

    route_config = RouteConfig()
    route_config.rate_limit = 5
    route_config.rate_limit_window = 30

    with app.test_request_context("/test"):
        from flask import request

        result = guard._check_rate_limit(request, "127.0.0.1", route_config)
        assert result is None


def test_behavior_tracker_passive_mode_logging(
    security_config: SecurityConfig,
) -> None:
    """
    Test for behavior handler passive mode.
    """
    security_config.passive_mode = True
    tracker = BehaviorTracker(security_config)

    test_cases: list[tuple[Literal["ban", "log", "throttle", "alert"], str, str]] = [
        (
            "ban",
            "warning",
            "[PASSIVE MODE] Would ban IP 192.168.1.1 for behavioral "
            "violation: Test details",
        ),
        (
            "log",
            "warning",
            "[PASSIVE MODE] Behavioral anomaly detected: Test details",
        ),
        (
            "throttle",
            "warning",
            "[PASSIVE MODE] Would throttle IP 192.168.1.1: Test details",
        ),
        (
            "alert",
            "critical",
            "[PASSIVE MODE] ALERT - Behavioral anomaly: Test details",
        ),
    ]

    for action, log_level, expected_message in test_cases:
        rule = BehaviorRule(
            rule_type="usage",
            threshold=5,
            action=action,
        )

        with patch.object(tracker.logger, log_level) as mock_logger:
            tracker.apply_action(
                rule=rule,
                client_ip="192.168.1.1",
                endpoint_id="/api/test",
                details="Test details",
            )

            mock_logger.assert_called_once_with(expected_message)
