import concurrent.futures
import re
from unittest.mock import MagicMock, patch

import pytest

from flaskapi_guard.handlers.redis_handler import RedisManager
from flaskapi_guard.handlers.suspatterns_handler import (
    SusPatternsManager,
    sus_patterns_handler,
)
from flaskapi_guard.models import SecurityConfig


def test_add_pattern() -> None:
    """
    Test adding a custom pattern to SusPatternsManager.
    """
    pattern_to_add = r"new_pattern"
    sus_patterns_handler.add_pattern(pattern_to_add, custom=True)
    assert pattern_to_add in sus_patterns_handler.custom_patterns


def test_remove_pattern() -> None:
    """
    Test removing a custom pattern from SusPatternsManager.
    """
    pattern_to_remove = r"new_pattern"
    sus_patterns_handler.add_pattern(pattern_to_remove, custom=True)
    result = sus_patterns_handler.remove_pattern(pattern_to_remove, custom=True)
    assert result is True
    assert pattern_to_remove not in sus_patterns_handler.custom_patterns


def test_get_all_patterns() -> None:
    """
    Test retrieving all patterns (default and custom) from SusPatternsManager.
    """
    default_patterns = sus_patterns_handler.patterns
    custom_pattern = r"custom_pattern"
    sus_patterns_handler.add_pattern(custom_pattern, custom=True)
    all_patterns = sus_patterns_handler.get_all_patterns()
    assert custom_pattern in all_patterns
    assert all(pattern in all_patterns for pattern in default_patterns)


def test_get_default_patterns() -> None:
    """
    Test retrieving only default patterns from SusPatternsManager.
    """
    default_patterns = sus_patterns_handler.patterns
    custom_pattern = r"custom_pattern_test"
    sus_patterns_handler.add_pattern(custom_pattern, custom=True)

    patterns = sus_patterns_handler.get_default_patterns()

    assert custom_pattern not in patterns
    assert all(pattern in patterns for pattern in default_patterns)


def test_get_custom_patterns() -> None:
    """
    Test retrieving only custom patterns from SusPatternsManager.
    """
    custom_pattern = r"custom_pattern_only"
    sus_patterns_handler.add_pattern(custom_pattern, custom=True)

    patterns = sus_patterns_handler.get_custom_patterns()

    assert custom_pattern in patterns
    default_pattern = sus_patterns_handler.patterns[0]
    assert default_pattern not in patterns


def test_invalid_pattern_handling() -> None:
    with pytest.raises(re.error):
        sus_patterns_handler.add_pattern(r"invalid(regex", custom=True)


def test_remove_nonexistent_pattern() -> None:
    result = sus_patterns_handler.remove_pattern("nonexistent", custom=True)
    assert result is False


def test_singleton_behavior() -> None:
    instance1 = sus_patterns_handler
    instance2 = sus_patterns_handler
    assert instance1 is instance2
    assert instance1.compiled_patterns is instance2.compiled_patterns


def test_add_default_pattern() -> None:
    """
    Test adding a default pattern to SusPatternsManager.
    """
    pattern_to_add = r"default_pattern"
    initial_length = len(sus_patterns_handler.patterns)

    sus_patterns_handler.add_pattern(pattern_to_add, custom=False)

    assert len(sus_patterns_handler.patterns) == initial_length + 1
    assert pattern_to_add in sus_patterns_handler.patterns


def test_remove_default_pattern() -> None:
    """
    Test removing a default pattern from SusPatternsManager.
    """
    sus_patterns_handler._instance = None
    original_patterns = sus_patterns_handler.patterns.copy()

    try:
        pattern_to_remove = r"default_pattern"

        sus_patterns_handler.add_pattern(pattern_to_remove, custom=False)

        result = sus_patterns_handler.remove_pattern(pattern_to_remove, custom=False)

        assert result is True
        assert pattern_to_remove not in sus_patterns_handler.patterns
        assert len(sus_patterns_handler.patterns) == len(original_patterns)

    finally:
        sus_patterns_handler.patterns = original_patterns.copy()
        sus_patterns_handler._instance = None


def test_get_compiled_patterns_separation() -> None:
    """
    Test separation of compiled patterns
    """
    default_pattern = r"default_test_pattern_\d+"
    custom_pattern = r"custom_test_pattern_\d+"

    sus_patterns_handler.add_pattern(default_pattern, custom=False)
    sus_patterns_handler.add_pattern(custom_pattern, custom=True)

    default_compiled = sus_patterns_handler.get_default_compiled_patterns()
    custom_compiled = sus_patterns_handler.get_custom_compiled_patterns()

    test_default_string = "default_test_pattern_123"
    default_matched = any(p.search(test_default_string) for p in default_compiled)
    assert default_matched

    test_custom_string = "custom_test_pattern_456"
    custom_matched = any(p.search(test_custom_string) for p in custom_compiled)
    assert custom_matched

    assert len(default_compiled) == len(sus_patterns_handler.compiled_patterns)
    assert len(custom_compiled) == len(sus_patterns_handler.compiled_custom_patterns)


def test_redis_initialization(security_config_redis: SecurityConfig) -> None:
    """Test Redis initialization and pattern caching"""
    redis_handler = RedisManager(security_config_redis)
    redis_handler.initialize()

    test_patterns = "pattern1,pattern2,pattern3"
    redis_handler.set_key("patterns", "custom", test_patterns)

    sus_patterns_handler.initialize_redis(redis_handler)

    for pattern in test_patterns.split(","):
        assert pattern in sus_patterns_handler.custom_patterns

    redis_handler.close()


def test_redis_pattern_persistence(security_config_redis: SecurityConfig) -> None:
    """Test pattern persistence to Redis"""
    redis_handler = RedisManager(security_config_redis)
    redis_handler.initialize()

    sus_patterns_handler.initialize_redis(redis_handler)

    test_pattern = "test_pattern"
    sus_patterns_handler.add_pattern(test_pattern, custom=True)

    cached_patterns = redis_handler.get_key("patterns", "custom")
    assert test_pattern in cached_patterns.split(",")

    result = sus_patterns_handler.remove_pattern(test_pattern, custom=True)
    assert result is True

    cached_patterns = redis_handler.get_key("patterns", "custom")
    assert not cached_patterns or test_pattern not in cached_patterns.split(",")

    redis_handler.close()


def test_redis_disabled() -> None:
    """Test SusPatternsManager behavior when Redis is disabled"""

    sus_patterns_handler.initialize_redis(None)

    test_pattern = "test_pattern"
    sus_patterns_handler.add_pattern(test_pattern, custom=True)
    assert test_pattern in sus_patterns_handler.custom_patterns

    result = sus_patterns_handler.remove_pattern(test_pattern, custom=True)
    assert result is True
    assert test_pattern not in sus_patterns_handler.custom_patterns


def test_get_all_compiled_patterns() -> None:
    """Test retrieving all compiled patterns"""

    test_pattern = r"test_pattern\d+"
    sus_patterns_handler.add_pattern(test_pattern, custom=True)

    compiled_patterns = sus_patterns_handler.get_all_compiled_patterns()

    assert len(compiled_patterns) == len(sus_patterns_handler.compiled_patterns) + len(
        sus_patterns_handler.compiled_custom_patterns
    )

    test_string = "test_pattern123"
    matched = False
    for pattern in compiled_patterns:
        if pattern.search(test_string):
            matched = True
            break
    assert matched


def test_init_with_config() -> None:
    """Test SusPatternsManager initialization with detection engine config."""
    config = MagicMock()
    config.detection_compiler_timeout = 3.0
    config.detection_max_tracked_patterns = 500
    config.detection_max_content_length = 20000
    config.detection_preserve_attack_patterns = True
    config.detection_anomaly_threshold = 2.5
    config.detection_slow_pattern_threshold = 0.2
    config.detection_monitor_history_size = 100
    config.detection_semantic_threshold = 0.8

    SusPatternsManager._instance = None
    manager = SusPatternsManager(config)

    assert manager._compiler is not None
    assert manager._compiler.default_timeout == 3.0
    assert manager._preprocessor is not None
    assert manager._preprocessor.max_content_length == 20000
    assert manager._preprocessor.preserve_attack_patterns is True
    assert manager._semantic_analyzer is not None
    assert manager._performance_monitor is not None
    assert manager._performance_monitor.anomaly_threshold == 2.5
    assert manager._performance_monitor.slow_pattern_threshold == 0.2
    assert manager._semantic_threshold == 0.8

    SusPatternsManager._instance = None


def test_regex_timeout_fallback() -> None:
    """Test regex timeout fallback when compiler is not available."""
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    original_compiler = manager._compiler
    manager._compiler = None

    evil_pattern = r"a{100,}b"
    manager.add_pattern(evil_pattern, custom=True)

    evil_content = "a" * 100 + "b"

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        with patch("logging.getLogger") as mock_logger:
            mock_logger.return_value.warning = MagicMock()

            matched, pattern = manager.detect_pattern_match(
                evil_content, "127.0.0.1", "test_timeout"
            )

            assert not matched
            assert pattern is None

            mock_logger.return_value.warning.assert_called()
            warning_msg = mock_logger.return_value.warning.call_args[0][0]
            assert "Regex timeout exceeded" in warning_msg

    manager._compiler = original_compiler
    manager.remove_pattern(evil_pattern, custom=True)
    SusPatternsManager._instance = None


def test_regex_search_success_fallback() -> None:
    """
    Test successful regex search using fallback when compiler is not available.
    """
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    original_compiler = manager._compiler
    manager._compiler = None

    test_pattern = r"test_pattern_\d+"
    manager.add_pattern(test_pattern, custom=True)

    test_content = "This contains test_pattern_123 in it"

    matched, pattern = manager.detect_pattern_match(
        test_content, "127.0.0.1", "test_search"
    )

    assert matched is True
    assert pattern == test_pattern

    manager._compiler = original_compiler
    manager.remove_pattern(test_pattern, custom=True)
    SusPatternsManager._instance = None


def test_get_performance_stats_none() -> None:
    """Test get_performance_stats returns None when monitor is disabled."""
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    original_monitor = manager._performance_monitor
    manager._performance_monitor = None

    stats = manager.get_performance_stats()

    assert stats is None

    manager._performance_monitor = original_monitor
    SusPatternsManager._instance = None


def test_get_performance_stats_with_monitor() -> None:
    """Test get_performance_stats returns None when monitor is not enabled."""
    manager = sus_patterns_handler

    stats = manager.get_performance_stats()
    assert stats is None


def test_pattern_timeout_with_compiler(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test pattern timeout detection when compiler is available."""
    manager = sus_patterns_manager_with_detection

    evil_pattern = r"(a+)+"
    manager.add_pattern(evil_pattern, custom=True)

    evil_content = "a" * 1000 + "b"

    time_counter = 0

    def mock_time() -> float:
        nonlocal time_counter
        time_counter += 1
        if time_counter % 2 == 1:
            return 0.0
        else:
            return 2.0

    with patch.object(manager._compiler, "create_safe_matcher") as mock_create:
        mock_matcher = MagicMock(return_value=None)
        mock_create.return_value = mock_matcher

        with patch("time.time", mock_time):
            with patch("logging.getLogger") as mock_logger:
                mock_log_instance = MagicMock()
                mock_logger.return_value = mock_log_instance

                result = manager.detect(evil_content, "127.0.0.1", "test_timeout")

                if mock_log_instance.warning.called:
                    warning_calls = [
                        call[0][0] for call in mock_log_instance.warning.call_args_list
                    ]
                    timeout_warnings = [
                        msg for msg in warning_calls if "Pattern timeout:" in msg
                    ]
                    assert len(timeout_warnings) > 0

                    assert len(result["timeouts"]) > 0

    manager.remove_pattern(evil_pattern, custom=True)


def test_regex_search_exception_fallback() -> None:
    """Test regex search exception handling in fallback mode."""
    SusPatternsManager._instance = None
    manager = SusPatternsManager()

    original_compiler = manager._compiler
    manager._compiler = None

    test_pattern = r"test_pattern"
    manager.add_pattern(test_pattern, custom=True)

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = RuntimeError("Test exception")
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        with patch("logging.getLogger") as mock_logger:
            mock_log_instance = MagicMock()
            mock_logger.return_value = mock_log_instance

            result = manager.detect("test content", "127.0.0.1", "test_exception")

            assert not result["is_threat"]

            mock_log_instance.error.assert_called()
            error_msg = mock_log_instance.error.call_args[0][0]
            assert "Error in regex search" in error_msg

    manager._compiler = original_compiler
    manager.remove_pattern(test_pattern, custom=True)
    SusPatternsManager._instance = None


def test_semantic_threat_detection(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test semantic threat detection."""
    manager = sus_patterns_manager_with_detection

    assert manager._semantic_analyzer is not None

    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        with patch.object(manager._semantic_analyzer, "get_threat_score") as mock_score:
            semantic_analysis = {
                "attack_probabilities": {
                    "sql_injection": 0.85,
                    "xss": 0.65,
                    "command_injection": 0.45,
                },
                "tokens": ["SELECT", "*", "FROM", "users"],
                "suspicious_patterns": ["sql_keywords"],
            }
            mock_analyze.return_value = semantic_analysis
            mock_score.return_value = 0.85

            manager.configure_semantic_threshold(0.7)

            result = manager.detect(
                "SELECT * FROM users WHERE id=1", "127.0.0.1", "test_semantic"
            )

            assert result["is_threat"]
            assert result["threat_score"] >= 0.85

            semantic_threats = [t for t in result["threats"] if t["type"] == "semantic"]
            assert len(semantic_threats) >= 1

            attack_types = [t["attack_type"] for t in semantic_threats]
            assert "sql_injection" in attack_types


def test_semantic_threat_suspicious_fallback(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test semantic threat detection with general suspicious behavior."""
    manager = sus_patterns_manager_with_detection

    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        with patch.object(manager._semantic_analyzer, "get_threat_score") as mock_score:
            semantic_analysis = {
                "attack_probabilities": {
                    "sql_injection": 0.4,
                    "xss": 0.3,
                    "command_injection": 0.2,
                },
                "suspicious_patterns": ["multiple_keywords"],
            }
            mock_analyze.return_value = semantic_analysis
            mock_score.return_value = 0.75

            manager.configure_semantic_threshold(0.7)

            result = manager.detect(
                "Suspicious content with multiple patterns",
                "127.0.0.1",
                "test_suspicious",
            )

            assert result["is_threat"]

            semantic_threats = [t for t in result["threats"] if t["type"] == "semantic"]
            assert len(semantic_threats) == 1

            assert semantic_threats[0]["attack_type"] == "suspicious"
            assert semantic_threats[0]["threat_score"] == 0.75


def test_legacy_detect_semantic_threat(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test legacy detect_pattern_match with semantic threat."""
    manager = sus_patterns_manager_with_detection

    with patch.object(manager, "detect") as mock_detect:
        mock_detect.return_value = {
            "is_threat": True,
            "threats": [
                {"type": "semantic", "attack_type": "sql_injection", "probability": 0.9}
            ],
        }

        matched, pattern = manager.detect_pattern_match(
            "test content", "127.0.0.1", "test"
        )

        assert matched is True
        assert pattern == "semantic:sql_injection"


def test_legacy_detect_unknown_threat(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test legacy detect_pattern_match with unknown threat type."""
    manager = sus_patterns_manager_with_detection

    with patch.object(manager, "detect") as mock_detect:
        mock_detect.return_value = {
            "is_threat": True,
            "threats": [{"type": "unknown_type", "data": "some_data"}],
        }

        matched, pattern = manager.detect_pattern_match(
            "test content", "127.0.0.1", "test"
        )

        assert matched is True
        assert pattern == "unknown"


def test_compiler_cache_clearing_on_pattern_operations(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test compiler cache clearing on pattern add/remove."""
    manager = sus_patterns_manager_with_detection

    assert manager._compiler is not None

    with patch.object(manager._compiler, "clear_cache") as mock_clear:
        test_pattern = r"cache_test_pattern"
        manager.add_pattern(test_pattern, custom=True)

        mock_clear.assert_called_once()

        mock_clear.reset_mock()

        result = manager.remove_pattern(test_pattern, custom=True)
        assert result is True

        mock_clear.assert_called_once()

    if manager._performance_monitor:
        with patch.object(
            manager._performance_monitor, "remove_pattern_stats"
        ) as mock_remove:
            pattern_to_remove = manager.patterns[0]
            manager.remove_pattern(pattern_to_remove, custom=False)

            mock_remove.assert_called_once_with(pattern_to_remove)


def test_detect_semantic_only_pattern_info(
    sus_patterns_manager_with_detection: SusPatternsManager,
) -> None:
    """Test pattern info extraction for semantic-only threats."""
    manager = sus_patterns_manager_with_detection

    with patch.object(manager._semantic_analyzer, "analyze") as mock_analyze:
        with patch.object(manager._semantic_analyzer, "get_threat_score") as mock_score:
            mock_analyze.return_value = {"attack_probabilities": {"xss": 0.9}}
            mock_score.return_value = 0.9

            mock_agent = MagicMock()
            manager.agent_handler = mock_agent

            result = manager.detect(
                "semantic only threat", "127.0.0.1", "test_semantic_info"
            )

            assert result["is_threat"]


def test_initialize_agent() -> None:
    """Test initialize_agent sets agent_handler."""
    handler = sus_patterns_handler
    original_agent = handler.agent_handler
    try:
        mock_agent = MagicMock()
        handler.initialize_agent(mock_agent)
        assert handler.agent_handler is mock_agent
    finally:
        handler.agent_handler = original_agent


def test_send_pattern_event() -> None:
    """Test _send_pattern_event sends event to agent."""
    import sys
    import types

    handler = sus_patterns_handler
    original_agent = handler.agent_handler

    mock_module = types.ModuleType("guard_agent")

    class MockSecurityEvent:
        def __init__(self, **kwargs: object) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    mock_module.SecurityEvent = MockSecurityEvent  # type: ignore[attr-defined]
    original_module = sys.modules.get("guard_agent")
    sys.modules["guard_agent"] = mock_module

    try:
        mock_agent = MagicMock()
        handler.agent_handler = mock_agent

        handler._send_pattern_event(
            event_type="pattern_detected",
            ip_address="1.2.3.4",
            action_taken="logged",
            reason="Test pattern detected",
            pattern="test.*",
        )
        mock_agent.send_event.assert_called_once()
    finally:
        handler.agent_handler = original_agent
        if original_module:
            sys.modules["guard_agent"] = original_module
        else:
            sys.modules.pop("guard_agent", None)


def test_send_pattern_event_no_agent() -> None:
    """Test _send_pattern_event returns early when no agent."""
    handler = sus_patterns_handler
    original_agent = handler.agent_handler
    try:
        handler.agent_handler = None
        handler._send_pattern_event(
            event_type="test",
            ip_address="1.2.3.4",
            action_taken="test",
            reason="test",
        )
    finally:
        handler.agent_handler = original_agent


def test_add_pattern_sends_agent_event() -> None:
    """Test that adding a pattern sends agent event."""
    import sys
    import types

    handler = sus_patterns_handler
    original_agent = handler.agent_handler

    mock_module = types.ModuleType("guard_agent")

    class MockSecurityEvent:
        def __init__(self, **kwargs: object) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    mock_module.SecurityEvent = MockSecurityEvent  # type: ignore[attr-defined]
    original_module = sys.modules.get("guard_agent")
    sys.modules["guard_agent"] = mock_module

    try:
        mock_agent = MagicMock()
        handler.agent_handler = mock_agent

        test_pattern = r"agent_event_test_pattern_\d+"
        handler.add_pattern(test_pattern, custom=True)

        mock_agent.send_event.assert_called()

        handler.remove_pattern(test_pattern, custom=True)
    finally:
        handler.agent_handler = original_agent
        if original_module:
            sys.modules["guard_agent"] = original_module
        else:
            sys.modules.pop("guard_agent", None)


def test_remove_pattern_sends_agent_event() -> None:
    """Test that removing a pattern sends agent event."""
    import sys
    import types

    handler = sus_patterns_handler
    original_agent = handler.agent_handler

    mock_module = types.ModuleType("guard_agent")

    class MockSecurityEvent:
        def __init__(self, **kwargs: object) -> None:
            for k, v in kwargs.items():
                setattr(self, k, v)

    mock_module.SecurityEvent = MockSecurityEvent  # type: ignore[attr-defined]
    original_module = sys.modules.get("guard_agent")
    sys.modules["guard_agent"] = mock_module

    try:
        handler.agent_handler = None
        test_pattern = r"removal_event_test_\d+"
        handler.add_pattern(test_pattern, custom=True)

        mock_agent = MagicMock()
        handler.agent_handler = mock_agent

        result = handler.remove_pattern(test_pattern, custom=True)
        assert result is True

        mock_agent.send_event.assert_called()
    finally:
        handler.agent_handler = original_agent
        if original_module:
            sys.modules["guard_agent"] = original_module
        else:
            sys.modules.pop("guard_agent", None)


def test_get_component_status() -> None:
    """Test getting component status."""
    original_instance = SusPatternsManager._instance

    try:
        SusPatternsManager._instance = None
        manager = SusPatternsManager()

        status = manager.get_component_status()
        assert status["compiler"] is False
        assert status["preprocessor"] is False
        assert status["semantic_analyzer"] is False
        assert status["performance_monitor"] is False
    finally:
        SusPatternsManager._instance = original_instance
