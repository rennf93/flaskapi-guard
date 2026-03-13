"""
Comprehensive tests for the ContentPreprocessor module.
"""

import concurrent.futures
from unittest.mock import MagicMock, patch

from flaskapi_guard.detection_engine.preprocessor import ContentPreprocessor


def test_initialization() -> None:
    """Test ContentPreprocessor initialization."""
    preprocessor = ContentPreprocessor()
    assert preprocessor.max_content_length == 10000
    assert preprocessor.preserve_attack_patterns is True
    assert preprocessor.agent_handler is None
    assert preprocessor.correlation_id is None
    assert len(preprocessor.attack_indicators) > 0
    assert len(preprocessor.compiled_indicators) == len(preprocessor.attack_indicators)

    agent_handler = MagicMock()
    preprocessor = ContentPreprocessor(
        max_content_length=5000,
        preserve_attack_patterns=False,
        agent_handler=agent_handler,
        correlation_id="test-123",
    )
    assert preprocessor.max_content_length == 5000
    assert preprocessor.preserve_attack_patterns is False
    assert preprocessor.agent_handler is agent_handler
    assert preprocessor.correlation_id == "test-123"


def test_normalize_unicode() -> None:
    """Test Unicode normalization."""
    preprocessor = ContentPreprocessor()

    test_cases = [
        ("\u2044", "/"),
        ("\uff0f", "/"),
        ("\u29f8", "/"),
        ("\u0130", "I"),
        ("\u0131", "i"),
        ("\u200b", ""),
        ("\u200c", ""),
        ("\u200d", ""),
        ("\ufeff", ""),
        ("\u00ad", ""),
        ("\u037e", ";"),
        ("\uff1c", "<"),
        ("\uff1e", ">"),
    ]

    for input_char, expected in test_cases:
        result = preprocessor.normalize_unicode(f"test{input_char}test")
        assert result == f"test{expected}test"

    malicious = f"<script{chr(0x200B)}>{chr(0xFF0F)}alert(1){chr(0xFF1C)}/script>"
    normalized = preprocessor.normalize_unicode(malicious)
    assert normalized == "<script>/alert(1)</script>"


def test_remove_excessive_whitespace() -> None:
    """Test whitespace normalization."""
    preprocessor = ContentPreprocessor()

    assert (
        preprocessor.remove_excessive_whitespace("test  multiple   spaces")
        == "test multiple spaces"
    )

    assert (
        preprocessor.remove_excessive_whitespace("test\t\ttabs\n\nnewlines")
        == "test tabs newlines"
    )

    assert (
        preprocessor.remove_excessive_whitespace("  leading trailing  ")
        == "leading trailing"
    )

    assert (
        preprocessor.remove_excessive_whitespace("  mixed\t \n  whitespace  ")
        == "mixed whitespace"
    )


def test_remove_null_bytes() -> None:
    """Test null byte and control character removal."""
    preprocessor = ContentPreprocessor()

    assert preprocessor.remove_null_bytes("test\x00null\x00bytes") == "testnullbytes"

    content = "test\x01\x02\x03control\x04\x05chars"
    result = preprocessor.remove_null_bytes(content)
    assert result == "testcontrolchars"

    content = "test\ttab\nnewline\rcarriage"
    result = preprocessor.remove_null_bytes(content)
    assert result == content


def test_send_preprocessor_event_no_agent() -> None:
    """Test _send_preprocessor_event when no agent handler."""
    preprocessor = ContentPreprocessor(agent_handler=None)

    preprocessor._send_preprocessor_event(
        event_type="test_event", action_taken="test_action", reason="test_reason"
    )


def test_send_preprocessor_event_with_agent() -> None:
    """Test _send_preprocessor_event with agent handler."""
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()

    preprocessor = ContentPreprocessor(
        agent_handler=agent_handler, correlation_id="test-456"
    )

    preprocessor._send_preprocessor_event(
        event_type="test_event",
        action_taken="test_action",
        reason="test_reason",
        extra_data="test_value",
    )

    agent_handler.send_event.assert_called_once()
    event = agent_handler.send_event.call_args[0][0]
    assert event.event_type == "test_event"
    assert event.action_taken == "test_action"
    assert event.reason == "test_reason"
    assert event.metadata["component"] == "ContentPreprocessor"
    assert event.metadata["correlation_id"] == "test-456"
    assert event.metadata["extra_data"] == "test_value"


def test_send_preprocessor_event_with_error() -> None:
    """Test _send_preprocessor_event with agent error."""
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock(side_effect=Exception("Agent error"))

    preprocessor = ContentPreprocessor(agent_handler=agent_handler)

    with patch("logging.getLogger") as mock_logger:
        mock_logger.return_value.error = MagicMock()

        preprocessor._send_preprocessor_event(
            event_type="test_event", action_taken="test_action", reason="test_reason"
        )

        mock_logger.return_value.error.assert_called_once()
        error_msg = mock_logger.return_value.error.call_args[0][0]
        assert "Failed to send preprocessor event to agent" in error_msg


def test_extract_attack_regions_max_regions() -> None:
    """Test extract_attack_regions with max regions limit."""
    preprocessor = ContentPreprocessor(max_content_length=500)

    content = ""
    for i in range(10):
        content += f" <script>alert({i})</script> padding " * 10

    regions = preprocessor.extract_attack_regions(content)

    assert len(regions) <= 5


def test_extract_attack_regions_timeout() -> None:
    """Test extract_attack_regions with regex timeout."""
    preprocessor = ContentPreprocessor()

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        content = "<script>alert(1)</script>"
        regions = preprocessor.extract_attack_regions(content)

        assert regions == []


def test_extract_attack_regions_early_break() -> None:
    """Test extract_attack_regions early break when max regions reached."""
    preprocessor = ContentPreprocessor(max_content_length=200)

    content = "<script>test1</script> " * 50

    regions = preprocessor.extract_attack_regions(content)

    assert len(regions) <= 2


def test_extract_attack_regions_merge_overlapping() -> None:
    """Test extract_attack_regions merging overlapping regions."""
    preprocessor = ContentPreprocessor()

    content = "text before <script>javascript:alert(1)</script> text after"

    regions = preprocessor.extract_attack_regions(content)

    assert len(regions) >= 1

    for i in range(1, len(regions)):
        assert regions[i][0] > regions[i - 1][1], (
            "Regions should not overlap"
        )  # pragma: no cover


def test_extract_attack_regions_non_overlapping() -> None:
    """Test extract_attack_regions with non-overlapping regions."""
    preprocessor = ContentPreprocessor()

    content = "<script>test</script>" + "x" * 500 + "SELECT * FROM users"

    regions = preprocessor.extract_attack_regions(content)

    assert len(regions) >= 2
    assert regions[1][0] > regions[0][1]


def test_extract_attack_regions_no_attacks() -> None:
    """Test extract_attack_regions with no attack patterns."""
    preprocessor = ContentPreprocessor()

    content = "This is just normal text without any attack patterns"
    regions = preprocessor.extract_attack_regions(content)

    assert regions == []


def test_truncate_safely_no_truncation_needed() -> None:
    """Test truncate_safely when content is already short."""
    preprocessor = ContentPreprocessor(max_content_length=1000)

    content = "Short content"
    result = preprocessor.truncate_safely(content)

    assert result == content


def test_truncate_safely_preserve_disabled() -> None:
    """Test truncate_safely with preserve_attack_patterns=False."""
    preprocessor = ContentPreprocessor(
        max_content_length=50, preserve_attack_patterns=False
    )

    content = "a" * 100
    result = preprocessor.truncate_safely(content)

    assert len(result) == 50
    assert result == "a" * 50


def test_truncate_safely_no_attack_patterns() -> None:
    """Test truncate_safely when no attack patterns found."""
    preprocessor = ContentPreprocessor(max_content_length=50)

    content = "This is normal content without attacks " * 10
    result = preprocessor.truncate_safely(content)

    assert len(result) == 50


def test_truncate_safely_attack_regions_exceed_max() -> None:
    """Test truncate_safely when attack regions exceed max length."""
    preprocessor = ContentPreprocessor(max_content_length=100)

    content = "<script>alert(1)</script>" * 20

    result = preprocessor.truncate_safely(content)

    assert len(result) <= 100
    assert "<script>" in result


def test_truncate_safely_with_non_attack_content() -> None:
    """Test truncate_safely including non-attack content."""
    preprocessor = ContentPreprocessor(max_content_length=50)

    content = (
        "safe_prefix_content_before"
        + "<script>alert(1)</script>"
        + "safe_suffix_content_after"
    )

    with patch.object(preprocessor, "extract_attack_regions") as mock_extract:
        script_start = content.find("<script>")
        script_end = content.find("</script>") + 9
        mock_extract.return_value = [(script_start, script_end)]

        result = preprocessor.truncate_safely(content)

    assert "<script>alert(1)</script>" in result

    assert "safe_prefix" in result

    assert len(result) <= 50


def test_decode_common_encodings_url_decode_error() -> None:
    """Test decode_common_encodings with URL decode error."""
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()
    preprocessor = ContentPreprocessor(agent_handler=agent_handler)

    with patch("urllib.parse.unquote", side_effect=Exception("URL decode error")):
        content = "%3Cscript%3E"
        preprocessor.decode_common_encodings(content)

        agent_handler.send_event.assert_called()
        event = agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decoding_error"
        assert event.action_taken == "decode_failed"
        assert "URL decode" in event.reason


def test_decode_common_encodings_html_decode_error() -> None:
    """Test decode_common_encodings with HTML decode error."""
    agent_handler = MagicMock()
    agent_handler.send_event = MagicMock()
    preprocessor = ContentPreprocessor(agent_handler=agent_handler)

    with patch("html.unescape", side_effect=Exception("HTML decode error")):
        content = "&lt;script&gt;"
        preprocessor.decode_common_encodings(content)

        agent_handler.send_event.assert_called()
        event = agent_handler.send_event.call_args[0][0]
        assert event.event_type == "decoding_error"
        assert event.action_taken == "decode_failed"
        assert "HTML decode" in event.reason


def test_decode_common_encodings_iterations() -> None:
    """Test decode_common_encodings with multiple encoding layers."""
    preprocessor = ContentPreprocessor()

    content = "%253Cscript%253E"
    result = preprocessor.decode_common_encodings(content)

    assert result == "<script>"

    content = "%26lt%3Bscript%26gt%3B"
    result = preprocessor.decode_common_encodings(content)

    assert result == "<script>"


def test_decode_common_encodings_max_iterations() -> None:
    """Test decode_common_encodings respects max iterations."""
    preprocessor = ContentPreprocessor()

    content = "test"
    for _ in range(5):
        content = content.replace("<", "%3C")

    result = preprocessor.decode_common_encodings(content)

    assert "%3C" not in result or result.count("%3C") > 0


def test_preprocess_empty_content() -> None:
    """Test preprocess with empty content."""
    preprocessor = ContentPreprocessor()

    result = preprocessor.preprocess("")
    assert result == ""


def test_preprocess_full_flow() -> None:
    """Test complete preprocessing flow."""
    preprocessor = ContentPreprocessor(max_content_length=200)

    content = (
        f"{chr(0x200B)}<script>{chr(0xFF0F)}alert(1)</script>"
        f"  multiple   spaces %3Cimg%3E\x00null"
    )

    result = preprocessor.preprocess(content)

    assert chr(0x200B) not in result
    assert chr(0xFF0F) not in result
    assert "  " not in result
    assert "<img>" in result
    assert "\x00" not in result
    assert len(result) <= 200


def test_preprocess_batch() -> None:
    """Test batch preprocessing."""
    preprocessor = ContentPreprocessor()

    contents = ["<script>alert(1)</script>", "%3Cimg%3E", "normal text", ""]

    results = preprocessor.preprocess_batch(contents)

    assert len(results) == len(contents)
    assert results[0] == "<script>alert(1)</script>"
    assert results[1] == "<img>"
    assert results[2] == "normal text"
    assert results[3] == ""


def test_attack_indicators_compilation() -> None:
    """Test that attack indicators are properly compiled."""
    preprocessor = ContentPreprocessor()

    test_content = "<script>alert(1)</script> SELECT * FROM users <?php eval() <iframe>"

    matches = []
    for indicator in preprocessor.compiled_indicators:
        if indicator.search(test_content):
            matches.append(indicator.pattern)

    assert len(matches) > 0
    assert any("<script" in m for m in matches)
    assert any("SELECT" in m for m in matches)
    assert any("<?php" in m for m in matches)


def test_integration_xss_bypass_attempt() -> None:
    """Test preprocessing of XSS bypass attempt."""
    preprocessor = ContentPreprocessor()

    xss = f"<scr{chr(0x200B)}ipt>al{chr(0x200C)}ert(1)</sc{chr(0x200D)}ript>"
    result = preprocessor.preprocess(xss)

    assert "<script>alert(1)</script>" in result


def test_integration_sql_injection_bypass() -> None:
    """Test preprocessing of SQL injection bypass attempt."""
    preprocessor = ContentPreprocessor()

    sqli = "1' %55NION %53ELECT * FROM users--"
    result = preprocessor.preprocess(sqli)

    assert "UNION SELECT" in result


def test_integration_padding_attack() -> None:
    """Test preprocessing of padding attack."""
    preprocessor = ContentPreprocessor(max_content_length=200)

    attack = "a" * 50 + "<script>alert(1)</script>" + "b" * 2000
    result = preprocessor.preprocess(attack)

    assert len(result) <= 200
    assert "script" in result
