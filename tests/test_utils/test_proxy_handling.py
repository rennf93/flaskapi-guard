import logging
from unittest.mock import patch

import pytest
from flask import Flask

from flaskapi_guard.models import SecurityConfig
from flaskapi_guard.utils import extract_client_ip


def test_extract_client_ip_without_trusted_proxies() -> None:
    """Test extracting client IP without trusted proxies."""
    config = SecurityConfig()

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        ip = extract_client_ip(request, config)
        assert ip == "127.0.0.1"


def test_extract_client_ip_with_trusted_proxies() -> None:
    """Test extracting client IP with trusted proxies."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        ip = extract_client_ip(request, config)
        assert ip == "1.2.3.4"


def test_extract_client_ip_with_cidr_trusted_proxies() -> None:
    """Test extracting client IP with CIDR notation in trusted proxies."""
    config = SecurityConfig(trusted_proxies=["127.0.0.0/8"])

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        ip = extract_client_ip(request, config)
        assert ip == "1.2.3.4"


def test_extract_client_ip_with_proxy_depth() -> None:
    """Test extracting client IP with proxy depth."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=2)

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"X-Forwarded-For": "5.6.7.8, 1.2.3.4"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        ip = extract_client_ip(request, config)
        assert ip == "5.6.7.8"


def test_extract_client_ip_without_xforwarded() -> None:
    """Test extracting client IP from trusted proxy but without X-Forwarded-For."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        # Should fall back to client IP
        ip = extract_client_ip(request, config)
        assert ip == "127.0.0.1"


def test_extract_client_ip_with_untrusted_proxy() -> None:
    """Test extracting client IP from untrusted proxy."""
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        ip = extract_client_ip(request, config)
        assert ip == "127.0.0.1"


def test_extract_client_ip_error_handling(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Test error handling in extract_client_ip when ip_address validation fails."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"])

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"X-Forwarded-For": "invalid-ip"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        with caplog.at_level(logging.WARNING):
            with patch(
                "flaskapi_guard.utils.ip_address", side_effect=ValueError("Invalid IP")
            ):
                ip = extract_client_ip(request, config)
                assert ip == "127.0.0.1"
                # When ip_address() raises ValueError,
                # _is_trusted_proxy catches it and returns False
                # This triggers the IP spoof attempt warning
                # since forwarded_for is present
                assert "Potential IP spoof attempt" in caplog.text


def test_extract_client_ip_fallback_to_connecting_ip() -> None:
    """Test falling back to connecting IP when forwarded chain is too short."""
    config = SecurityConfig(trusted_proxies=["127.0.0.1"], trusted_proxy_depth=3)

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        headers={"X-Forwarded-For": "1.2.3.4"},
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        ip = extract_client_ip(request, config)
        assert ip == "127.0.0.1"


def test_extract_client_ip_untrusted_without_forwarded() -> None:
    """Test extracting client IP from untrusted proxy without X-Forwarded-For."""
    config = SecurityConfig(trusted_proxies=["10.0.0.1"])

    app = Flask(__name__)
    with app.test_request_context(
        "/",
        method="GET",
        environ_base={"REMOTE_ADDR": "127.0.0.1"},
    ):
        from flask import request

        ip = extract_client_ip(request, config)
        assert ip == "127.0.0.1"
