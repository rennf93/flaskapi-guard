from unittest.mock import MagicMock

from flask import Flask, Response

from flaskapi_guard.adapters import (
    FlaskGuardRequest,
    FlaskGuardResponse,
    FlaskResponseFactory,
    unwrap_response,
)


def test_flask_guard_request_url_path() -> None:
    app = Flask(__name__)
    with app.test_request_context("/test"):
        from flask import request

        guard_request = FlaskGuardRequest(request)
        assert guard_request.url_path == "/test"


def test_flask_guard_request_method() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", method="POST"):
        from flask import request

        guard_request = FlaskGuardRequest(request)
        assert guard_request.method == "POST"


def test_flask_guard_request_client_host() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", environ_base={"REMOTE_ADDR": "10.0.0.1"}):
        from flask import request

        guard_request = FlaskGuardRequest(request)
        assert guard_request.client_host == "10.0.0.1"


def test_flask_guard_request_headers() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", headers={"X-Custom": "value"}):
        from flask import request

        guard_request = FlaskGuardRequest(request)
        assert guard_request.headers.get("X-Custom") == "value"


def test_flask_guard_request_query_params() -> None:
    app = Flask(__name__)
    with app.test_request_context("/?key=val"):
        from flask import request

        guard_request = FlaskGuardRequest(request)
        assert guard_request.query_params.get("key") == "val"


def test_flask_guard_request_scheme() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", base_url="https://localhost"):
        from flask import request

        guard_request = FlaskGuardRequest(request)
        assert guard_request.url_scheme == "https"


def test_flask_guard_request_body() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", data=b"hello"):
        from flask import request

        guard_request = FlaskGuardRequest(request)
        assert guard_request.body() == b"hello"


def test_flask_guard_request_read_body_prefix() -> None:
    app = Flask(__name__)
    with app.test_request_context("/", data=b"hello world"):
        from flask import request

        guard_request = FlaskGuardRequest(request)
        assert guard_request.read_body_prefix(5) == b"hello"
        assert guard_request.read_body_prefix(0) == b""
        assert guard_request.read_body_prefix(-1) == b""


def test_flask_guard_response_read_body_prefix() -> None:
    response = Response("test body", status=200)
    guard_response = FlaskGuardResponse(response)
    assert guard_response.read_body_prefix(4) == b"test"
    assert guard_response.read_body_prefix(0) == b""
    assert guard_response.read_body_prefix(-2) == b""


def test_flask_guard_response_properties() -> None:
    response = Response("test", status=200)
    guard_response = FlaskGuardResponse(response)
    assert guard_response.status_code == 200
    assert guard_response.body == b"test"


def test_flask_guard_response_headers() -> None:
    response = Response("test", status=200)
    guard_response = FlaskGuardResponse(response)
    guard_response.headers["X-Custom"] = "value"
    assert response.headers["X-Custom"] == "value"


def test_flask_response_factory_create() -> None:
    factory = FlaskResponseFactory()
    guard_resp = factory.create_response("error", 403)
    assert guard_resp.status_code == 403


def test_flask_response_factory_redirect() -> None:
    app = Flask(__name__)
    with app.app_context():
        factory = FlaskResponseFactory()
        guard_resp = factory.create_redirect_response("https://example.com", 301)
        assert guard_resp.status_code == 301


def test_unwrap_response_flask() -> None:
    response = Response("test", status=200)
    guard_response = FlaskGuardResponse(response)
    unwrapped = unwrap_response(guard_response)
    assert unwrapped is response


def test_unwrap_response_generic() -> None:
    mock_resp = MagicMock()
    mock_resp.body = b"body"
    mock_resp.status_code = 404
    mock_resp.headers = {"X-Test": "val"}
    unwrapped = unwrap_response(mock_resp)
    assert unwrapped.status_code == 404
