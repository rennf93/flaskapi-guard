import logging
import os
from typing import Any
from unittest.mock import MagicMock, Mock, patch

from flask import Flask
from pytest_mock import MockerFixture

from flaskapi_guard.handlers.cloud_handler import cloud_handler
from flaskapi_guard.handlers.ipinfo_handler import IPInfoManager
from flaskapi_guard.handlers.suspatterns_handler import sus_patterns_handler
from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.utils import (
    check_ip_country,
    detect_penetration_attempt,
    is_ip_allowed,
    is_user_agent_allowed,
)

IPINFO_TOKEN = str(os.getenv("IPINFO_TOKEN"))


def test_is_ip_allowed(security_config: SecurityConfig, mocker: MockerFixture) -> None:
    """
    Test the is_ip_allowed function with various IP addresses.
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
    Test the is_user_agent_allowed function with allowed and blocked user agents.
    """
    assert is_user_agent_allowed("goodbot", security_config)
    assert not is_user_agent_allowed("badbot", security_config)


def test_detect_penetration_attempt() -> None:
    """
    Test the detect_penetration_attempt
    function with a normal request.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
    ):
        from flask import request

        result, _ = detect_penetration_attempt(request)
        assert not result


def test_detect_penetration_attempt_xss() -> None:
    """
    Test the detect_penetration_attempt
    function with an XSS attempt.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/?param=<script>alert('xss')</script>",
        method="GET",
    ):
        from flask import request

        result, trigger = detect_penetration_attempt(request)
        assert result
        assert "script" in trigger.lower()


def test_detect_penetration_attempt_sql_injection() -> None:
    """Test SQL injection detection."""
    app = Flask(__name__)
    with app.test_request_context(
        "/?query=UNION+SELECT+NULL--",
        method="GET",
    ):
        from flask import request

        result, _ = detect_penetration_attempt(request)
        assert result


def test_detect_penetration_attempt_directory_traversal() -> None:
    """
    Test the detect_penetration_attempt
    function with a directory traversal attempt.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/../../etc/passwd",
        method="GET",
    ):
        from flask import request

        result, _ = detect_penetration_attempt(request)
        assert result


def test_detect_penetration_attempt_command_injection() -> None:
    """
    Test the detect_penetration_attempt
    function with a command injection attempt.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/?cmd=|cat+/etc/passwd",
        method="GET",
    ):
        from flask import request

        result, _ = detect_penetration_attempt(request)
        assert result


def test_detect_penetration_attempt_ssrf() -> None:
    """
    Test the detect_penetration_attempt
    function with an SSRF attempt.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/?param=http://169.254.169.254/latest/meta-data/",
        method="GET",
    ):
        from flask import request

        assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_open_redirect() -> None:
    """
    Test the detect_penetration_attempt
    function with an open redirect attempt.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/?param=//evil.com",
        method="GET",
    ):
        from flask import request

        assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_crlf_injection() -> None:
    """
    Test the detect_penetration_attempt
    function with a CRLF injection attempt.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/?param=%0d%0aSet-Cookie:%20mycookie=myvalue",
        method="GET",
    ):
        from flask import request

        assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_path_manipulation() -> None:
    """
    Test the detect_penetration_attempt
    function with a path manipulation attempt.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/../../../../etc/passwd",
        method="GET",
    ):
        from flask import request

        assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_shell_injection() -> None:
    """Test shell injection detection."""
    app = Flask(__name__)
    with app.test_request_context(
        "/?cmd=;ls%20-la%20/",
        method="GET",
    ):
        from flask import request

        result, _ = detect_penetration_attempt(request)
        assert result

    with app.test_request_context(
        "/?cmd=echo%20hello",
        method="GET",
    ):
        from flask import request as request2

        result, _ = detect_penetration_attempt(request2)
        assert not result


def test_detect_penetration_attempt_nosql_injection() -> None:
    """
    Test the detect_penetration_attempt
    function with a NoSQL injection attempt.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/?param={ '$ne': '' }",
        method="GET",
    ):
        from flask import request

        assert detect_penetration_attempt(request)


def test_detect_penetration_attempt_json_injection() -> None:
    """Test JSON content detection."""
    app = Flask(__name__)

    malicious_body = b"""
            {
                "script": "<script>alert(1)</script>",
                "sql": "UNION SELECT * FROM users",
                "cmd": ";cat /etc/passwd",
                "path": "../../../etc/shadow"
            }
        """

    with app.test_request_context(
        "/",
        method="POST",
        content_type="application/json",
        data=malicious_body,
    ):
        from flask import request

        result, _ = detect_penetration_attempt(request)
        assert result

    legitimate_body = b"""
            {
                "user_id": 123,
                "name": "John Doe",
                "email": "john@example.com",
                "preferences": {
                    "theme": "dark",
                    "notifications": true
                }
            }
        """

    with app.test_request_context(
        "/",
        method="POST",
        content_type="application/json",
        data=legitimate_body,
    ):
        from flask import request as request2

        result, _ = detect_penetration_attempt(request2)
        assert not result


def test_detect_penetration_attempt_http_header_injection() -> None:
    """
    Test the detect_penetration_attempt
    function with an HTTP header injection attempt.
    """
    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        environ_base={
            "HTTP_X_FORWARDED_FOR": "127.0.0.1\r\nSet-Cookie: mycookie=myvalue",
        },
    ):
        from flask import request

        result, _ = detect_penetration_attempt(request)
        assert result


def test_get_ip_country(mocker: MockerFixture) -> None:
    """Test the get_ip_country function."""
    mock_ipinfo = mocker.patch("flaskapi_guard.handlers.ipinfo_handler.IPInfoManager")
    mock_db = mock_ipinfo.return_value
    mock_db.get_country.return_value = "US"
    mock_db.reader = True

    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN), blocked_countries=["CN"]
    )

    country = check_ip_country("1.1.1.1", config, mock_db)
    assert not country

    mock_db.get_country.return_value = "CN"
    country = check_ip_country("1.1.1.1", config, mock_db)
    assert country


def test_is_ip_allowed_cloud_providers(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    """
    Test the is_ip_allowed function with cloud provider IP blocking.
    """
    mocker.patch("flaskapi_guard.utils.check_ip_country", return_value=True)
    mocker.patch.object(
        cloud_handler,
        "is_cloud_ip",
        side_effect=lambda ip, *_: ip.startswith("13."),
    )

    config = SecurityConfig(block_cloud_providers={"AWS"})

    assert is_ip_allowed("127.0.0.1", config)
    assert not is_ip_allowed("13.59.255.255", config)
    assert is_ip_allowed("8.8.8.8", config)


def test_check_ip_country() -> None:
    """Test country checking functionality."""
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        blocked_countries=["CN"],
        whitelist_countries=["US"],
    )

    with patch(
        "flaskapi_guard.handlers.ipinfo_handler.IPInfoManager"
    ) as MockIPInfoManager:
        mock_db = MockIPInfoManager.return_value
        mock_db.get_country.return_value = "CN"

        app = Flask(__name__)
        with app.test_request_context("/"):
            from flask import request

            assert check_ip_country(request, config, mock_db)

            mock_db.get_country.return_value = "US"
            assert not check_ip_country(request, config, mock_db)


def test_whitelisted_country(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    """Test country whitelist functionality"""
    mock_ipinfo = mocker.Mock()
    mock_ipinfo.get_country.return_value = "US"
    mock_ipinfo.reader = True

    security_config.whitelist_countries = ["US"]

    assert not check_ip_country("8.8.8.8", security_config, mock_ipinfo)


def test_cloud_provider_blocking(
    security_config: SecurityConfig, mocker: MockerFixture
) -> None:
    mocker.patch("flaskapi_guard.utils.cloud_handler.is_cloud_ip", return_value=True)
    security_config.block_cloud_providers = {"AWS"}

    assert not is_ip_allowed("8.8.8.8", security_config)


def test_check_ip_country_not_initialized(
    security_config: SecurityConfig,
) -> None:
    """Test check_ip_country when IPInfo reader is not initialized."""
    mock_ipinfo = Mock()
    mock_ipinfo.is_initialized = False
    mock_ipinfo.initialize = MagicMock()
    mock_ipinfo.get_country.return_value = "US"

    result = check_ip_country("1.1.1.1", security_config, mock_ipinfo)
    assert not result
    mock_ipinfo.initialize.assert_called_once()


def test_check_ip_country_no_country_found(
    security_config: SecurityConfig,
) -> None:
    """Test check_ip_country when country lookup fails."""
    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = None

    result = check_ip_country("1.1.1.1", security_config, mock_ipinfo)
    assert not result


def test_check_ip_country_no_countries_configured(
    caplog: Any,
) -> None:
    """Test check_ip_country when no countries are blocked or whitelisted."""
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        blocked_countries=[],
        whitelist_countries=[],
    )

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = "US"

    with caplog.at_level(logging.WARNING):
        result = check_ip_country("1.1.1.1", config, mock_ipinfo)
        assert not result
        assert "No countries blocked or whitelisted" in caplog.text
        assert "1.1.1.1" in caplog.text

    caplog.clear()

    app = Flask(__name__)
    with app.test_request_context("/"):
        from flask import request

        with caplog.at_level(logging.WARNING):
            result = check_ip_country(request, config, mock_ipinfo)
            assert not result
            assert "No countries blocked or whitelisted" in caplog.text


def test_is_ip_allowed_cidr_blacklist() -> None:
    """Test the is_ip_allowed function with CIDR notation in blacklist."""
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        blacklist=["192.168.1.0/24"],
        whitelist=[],
    )

    assert not is_ip_allowed("192.168.1.100", config)
    assert not is_ip_allowed("192.168.1.1", config)
    assert not is_ip_allowed("192.168.1.254", config)

    assert is_ip_allowed("192.168.2.1", config)
    assert is_ip_allowed("192.168.0.1", config)
    assert is_ip_allowed("10.0.0.1", config)

    config_multiple = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        blacklist=["192.168.1.0/24", "10.0.0.0/8"],
        whitelist=[],
    )

    assert not is_ip_allowed("192.168.1.100", config_multiple)
    assert not is_ip_allowed("10.10.10.10", config_multiple)
    assert is_ip_allowed("172.16.0.1", config_multiple)


def test_is_ip_allowed_cidr_whitelist() -> None:
    """Test the is_ip_allowed function with CIDR notation in whitelist."""
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        whitelist=["192.168.1.0/24"],
        blacklist=[],
    )

    assert is_ip_allowed("192.168.1.100", config)
    assert is_ip_allowed("192.168.1.1", config)
    assert is_ip_allowed("192.168.1.254", config)

    assert not is_ip_allowed("192.168.2.1", config)
    assert not is_ip_allowed("192.168.0.1", config)
    assert not is_ip_allowed("10.0.0.1", config)

    config_multiple = SecurityConfig(
        geo_ip_handler=IPInfoManager(IPINFO_TOKEN),
        whitelist=["192.168.1.0/24", "10.0.0.0/8"],
        blacklist=[],
    )

    assert is_ip_allowed("192.168.1.100", config_multiple)
    assert is_ip_allowed("10.10.10.10", config_multiple)
    assert not is_ip_allowed("172.16.0.1", config_multiple)


def test_is_ip_allowed_invalid_ip(caplog: Any) -> None:
    """Test is_ip_allowed with invalid IP address."""
    config = SecurityConfig(geo_ip_handler=IPInfoManager("test"))

    with caplog.at_level(logging.ERROR):
        result = is_ip_allowed("invalid-ip", config)
        assert not result


def test_is_ip_allowed_general_exception(caplog: Any, mocker: MockerFixture) -> None:
    """Test is_ip_allowed with unexpected exception."""
    config = SecurityConfig(geo_ip_handler=IPInfoManager("test"))

    mock_error = Exception("Unexpected error")
    mocker.patch("flaskapi_guard.utils.ip_address", side_effect=mock_error)

    with caplog.at_level(logging.ERROR):
        result = is_ip_allowed("192.168.1.1", config)
        assert result
        assert "Error checking IP 192.168.1.1" in caplog.text
        assert "Unexpected error" in caplog.text


def test_detect_penetration_attempt_body_error() -> None:
    """Test penetration detection with body reading error."""
    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="POST",
        content_type="application/json",
    ):
        from flask import request

        with patch.object(
            request, "get_data", side_effect=Exception("Body read error")
        ):
            result, _ = detect_penetration_attempt(request)
            assert not result


def test_is_ip_allowed_blocked_country(mocker: MockerFixture) -> None:
    """Test is_ip_allowed with blocked country."""
    config = SecurityConfig(
        geo_ip_handler=IPInfoManager("test"), blocked_countries=["CN"]
    )

    mock_ipinfo = Mock()
    mock_ipinfo.reader = True
    mock_ipinfo.get_country.return_value = "CN"

    mocker.patch("flaskapi_guard.utils.check_ip_country", return_value=True)

    result = is_ip_allowed("192.168.1.1", config, mock_ipinfo)
    assert not result


def test_detect_penetration_attempt_regex_timeout() -> None:
    """Test regex timeout handling in detect_penetration_attempt."""
    app = Flask(__name__)
    with app.test_request_context(
        "/?param=test",
        method="GET",
    ):
        from flask import request

        def mock_detect_with_timeout(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "is_threat": False,
                "threat_score": 0.0,
                "threats": [],
                "context": kwargs.get("context", "unknown"),
                "original_length": len(kwargs.get("content", "")),
                "processed_length": len(kwargs.get("content", "")),
                "execution_time": 2.1,
                "detection_method": "enhanced",
                "timeouts": ["test_pattern"],
                "correlation_id": kwargs.get("correlation_id"),
            }

        with (
            patch.object(
                sus_patterns_handler, "detect", side_effect=mock_detect_with_timeout
            ),
            patch("logging.getLogger") as mock_get_logger,
        ):
            mock_logger = MagicMock()
            mock_get_logger.return_value = mock_logger

            result, trigger = detect_penetration_attempt(request)

            assert not result
            assert trigger == ""


def test_detect_penetration_attempt_regex_exception() -> None:
    """Test general exception handling in regex search."""
    app = Flask(__name__)
    with app.test_request_context(
        "/?param=test",
        method="GET",
    ):
        from flask import request

        def mock_detect_with_exception(*args: Any, **kwargs: Any) -> dict[str, Any]:
            raise Exception("Unexpected detection error")

        with (
            patch.object(
                sus_patterns_handler, "detect", side_effect=mock_detect_with_exception
            ),
            patch("logging.error") as mock_error,
        ):
            result, trigger = detect_penetration_attempt(request)

            assert not result
            assert trigger == ""

            mock_error.assert_called()
            error_msg = mock_error.call_args[0][0]
            assert "Enhanced detection failed" in error_msg


def test_detect_penetration_json_non_regex_threat() -> None:
    """Test JSON field detection with non-regex threat types."""
    app = Flask(__name__)

    json_payload = '{"username": "admin", "password": "test_password"}'

    with app.test_request_context(
        f"/?data={json_payload}",
        method="GET",
    ):
        from flask import request

        def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
            content = args[0] if args else kwargs.get("content", "")
            if "test_password" in content:
                return {
                    "is_threat": True,
                    "threats": [
                        {"type": "semantic", "attack_type": "credential_stuffing"}
                    ],
                }
            return {"is_threat": False, "threats": []}

        with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
            result, trigger = detect_penetration_attempt(request)

            assert result is True
            assert "JSON field 'password' contains: semantic" in trigger


def test_detect_penetration_semantic_threat() -> None:
    """Test semantic threat detection."""
    app = Flask(__name__)
    with app.test_request_context(
        "/?search=SELECT * FROM users WHERE admin=1",
        method="GET",
    ):
        from flask import request

        def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "is_threat": True,
                "threats": [
                    {
                        "type": "semantic",
                        "attack_type": "sql_injection",
                        "probability": 0.95,
                    }
                ],
            }

        with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
            result, trigger = detect_penetration_attempt(request)

            assert result is True
            assert "Semantic attack: sql_injection (score: 0.95)" in trigger


def test_detect_penetration_semantic_threat_with_score() -> None:
    """Test semantic threat with threat_score instead of probability."""
    app = Flask(__name__)
    with app.test_request_context(
        "/?input=malicious_content",
        method="GET",
    ):
        from flask import request

        def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "is_threat": True,
                "threats": [
                    {
                        "type": "semantic",
                        "attack_type": "suspicious",
                        "threat_score": 0.88,
                    }
                ],
            }

        with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
            result, trigger = detect_penetration_attempt(request)

            assert result is True
            assert "Semantic attack: suspicious (score: 0.88)" in trigger


def test_detect_penetration_fallback_pattern_match() -> None:
    """Test fallback pattern matching when enhanced detection fails."""
    app = Flask(__name__)
    with app.test_request_context(
        "/?test=<script>alert(1)</script>",
        method="GET",
    ):
        from flask import request

        def mock_detect_error(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("Detection engine failure")

        mock_pattern = MagicMock()
        mock_pattern.search.return_value = MagicMock()
        mock_ctx = frozenset({
            "query_param", "header", "url_path",
            "request_body", "unknown",
        })

        with (
            patch.object(sus_patterns_handler, "detect", side_effect=mock_detect_error),
            patch.object(
                sus_patterns_handler,
                "get_all_compiled_patterns",
                return_value=[(mock_pattern, mock_ctx)],
            ),
            patch("logging.error") as mock_error,
        ):
            result, trigger = detect_penetration_attempt(request)

            assert result is True
            assert "Value matched pattern (fallback)" in trigger

            mock_error.assert_called()
            error_msg = mock_error.call_args[0][0]
            assert "Enhanced detection failed" in error_msg


def test_detect_penetration_fallback_pattern_exception() -> None:
    """Test fallback pattern exception handling."""
    app = Flask(__name__)
    with app.test_request_context(
        "/?test=normal_content",
        method="GET",
    ):
        from flask import request

        def mock_detect_error(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            raise RuntimeError("Detection engine failure")

        mock_pattern = MagicMock()
        mock_pattern.search.side_effect = Exception("Pattern error")
        mock_ctx = frozenset({
            "query_param", "header", "url_path",
            "request_body", "unknown",
        })

        with (
            patch.object(sus_patterns_handler, "detect", side_effect=mock_detect_error),
            patch.object(
                sus_patterns_handler,
                "get_all_compiled_patterns",
                return_value=[(mock_pattern, mock_ctx)],
            ),
            patch("logging.error") as mock_log_error,
        ):
            result, trigger = detect_penetration_attempt(request)

            assert result is False
            assert trigger == ""

            assert mock_log_error.call_count >= 1
            for call in mock_log_error.call_args_list:
                assert "Enhanced detection failed" in call[0][0]
                assert "Detection engine failure" in call[0][0]


def test_detect_penetration_short_body() -> None:
    """Test request body logging when body is short."""
    app = Flask(__name__)

    short_body = b"<script>XSS</script>"

    with app.test_request_context(
        "/api/data",
        method="POST",
        data=short_body,
    ):
        from flask import request

        with patch("logging.warning") as mock_warning:
            result, trigger = detect_penetration_attempt(request)

            assert result is True
            assert "Request body:" in trigger

            warning_calls = mock_warning.call_args_list
            body_logged = False
            for call in warning_calls:
                if "<script>XSS</script>" in str(call):
                    body_logged = True
                    break
            assert body_logged


def test_detect_penetration_empty_threat_fallback() -> None:
    """Test empty threats array fallback."""
    app = Flask(__name__)

    json_payload = '{"field": "suspicious_value"}'

    with app.test_request_context(
        f"/?data={json_payload}",
        method="POST",
    ):
        from flask import request

        def mock_detect(*args: Any, **kwargs: Any) -> dict[str, Any]:
            return {
                "is_threat": True,
                "threats": [],
            }

        with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
            result, trigger = detect_penetration_attempt(request)

            assert result is True
            assert "JSON field 'field' contains threat" in trigger


def test_detect_penetration_unknown_threat_type() -> None:
    """Test handling of unknown threat type."""
    app = Flask(__name__)
    with app.test_request_context(
        "/?param=test_value",
        method="GET",
    ):
        from flask import request

        def mock_detect(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {
                "is_threat": True,
                "threats": [{"type": "unknown_type", "data": "some_data"}],
            }

        with patch.object(sus_patterns_handler, "detect", side_effect=mock_detect):
            result, trigger = detect_penetration_attempt(request)

            assert result is True
            assert trigger == "Query param 'param': Threat detected"
