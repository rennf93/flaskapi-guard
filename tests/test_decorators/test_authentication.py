from unittest.mock import Mock

import pytest
from flask import Flask

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard


@pytest.fixture
def auth_decorator_app(security_config: SecurityConfig) -> Flask:
    """Create Flask app with authentication decorator integration."""
    app = Flask(__name__)
    app.config["TESTING"] = True

    security_config.trusted_proxies = ["127.0.0.1"]
    security_config.trust_x_forwarded_proto = True
    security_config.enforce_https = False
    security_config.enable_penetration_detection = False

    decorator = SecurityDecorator(security_config)

    @app.route("/secure")
    @decorator.require_https()
    def secure_endpoint() -> dict[str, str]:
        return {"message": "HTTPS required"}

    @app.route("/auth-default")
    @decorator.require_auth()
    def auth_default_endpoint() -> dict[str, str]:
        return {"message": "Auth required (default)"}

    @app.route("/auth-basic")
    @decorator.require_auth(type="basic")
    def auth_basic_endpoint() -> dict[str, str]:
        return {"message": "Basic auth required"}

    @app.route("/api-key-default")
    @decorator.api_key_auth()
    def api_key_default_endpoint() -> dict[str, str]:
        return {"message": "API key required (default header)"}

    @app.route("/api-key-custom", methods=["POST"])
    @decorator.api_key_auth(header_name="Authorization")
    def api_key_custom_endpoint() -> dict[str, str]:
        return {"message": "API key required (custom header)"}

    @app.route("/headers-single")
    @decorator.require_headers({"X-API-Version": "v1"})
    def headers_single_endpoint() -> dict[str, str]:
        return {"message": "Single header required"}

    @app.route("/headers-multiple", methods=["POST"])
    @decorator.require_headers({"X-API-Version": "v2", "X-Client-ID": "required"})
    def headers_multiple_endpoint() -> dict[str, str]:
        return {"message": "Multiple headers required"}

    FlaskAPIGuard(app, config=security_config)
    app.extensions["flaskapi_guard"]["guard_decorator"] = decorator

    return app


@pytest.mark.parametrize(
    "route_path,expected_attr,expected_value,description",
    [
        ("/secure", "require_https", True, "require_https decorator"),
        ("/auth-default", "auth_required", "bearer", "require_auth default decorator"),
        ("/auth-basic", "auth_required", "basic", "require_auth custom type decorator"),
        (
            "/api-key-default",
            "api_key_required",
            True,
            "api_key_auth default decorator",
        ),
        (
            "/api-key-custom",
            "api_key_required",
            True,
            "api_key_auth custom header decorator",
        ),
    ],
)
def test_authentication_decorators_applied(
    auth_decorator_app: Flask,
    route_path: str,
    expected_attr: str,
    expected_value: str | bool,
    description: str,
) -> None:
    """Test that authentication decorators are applied correctly."""
    # Map route path to endpoint name
    endpoint_map = {
        "/secure": "secure_endpoint",
        "/auth-default": "auth_default_endpoint",
        "/auth-basic": "auth_basic_endpoint",
        "/api-key-default": "api_key_default_endpoint",
        "/api-key-custom": "api_key_custom_endpoint",
    }
    endpoint_name = endpoint_map[route_path]
    view_func = auth_decorator_app.view_functions[endpoint_name]

    assert hasattr(view_func, "_guard_route_id"), f"{description} should have route ID"

    guard_ext = auth_decorator_app.extensions["flaskapi_guard"]
    decorator = guard_ext["guard_decorator"]
    route_id = view_func._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None, f"{description} should have route config"
    assert getattr(route_config, expected_attr) == expected_value, (
        f"{description} should have correct {expected_attr}"
    )


@pytest.mark.parametrize(
    "route_path,expected_headers,description",
    [
        ("/api-key-default", {"X-API-Key": "required"}, "api_key_auth default header"),
        (
            "/api-key-custom",
            {"Authorization": "required"},
            "api_key_auth custom header",
        ),
        ("/headers-single", {"X-API-Version": "v1"}, "require_headers single header"),
        (
            "/headers-multiple",
            {"X-API-Version": "v2", "X-Client-ID": "required"},
            "require_headers multiple headers",
        ),
    ],
)
def test_header_requirements_applied(
    auth_decorator_app: Flask,
    route_path: str,
    expected_headers: dict[str, str],
    description: str,
) -> None:
    """Test that header requirement decorators are applied correctly."""
    endpoint_map = {
        "/api-key-default": "api_key_default_endpoint",
        "/api-key-custom": "api_key_custom_endpoint",
        "/headers-single": "headers_single_endpoint",
        "/headers-multiple": "headers_multiple_endpoint",
    }
    endpoint_name = endpoint_map[route_path]
    view_func = auth_decorator_app.view_functions[endpoint_name]

    assert hasattr(view_func, "_guard_route_id"), f"{description} should have route ID"

    guard_ext = auth_decorator_app.extensions["flaskapi_guard"]
    decorator = guard_ext["guard_decorator"]
    route_id = view_func._guard_route_id
    route_config = decorator.get_route_config(route_id)

    assert route_config is not None, f"{description} should have route config"
    for header, value in expected_headers.items():
        assert route_config.required_headers[header] == value, (
            f"{description} should require {header}={value}"
        )


@pytest.mark.parametrize(
    "endpoint,missing_header,expected_message,description",
    [
        (
            "/api-key-default",
            "X-API-Key",
            "Missing required header: X-API-Key",
            "API key default header missing",
        ),
        (
            "/api-key-custom",
            "Authorization",
            "Missing required header: Authorization",
            "API key custom header missing",
        ),
        (
            "/headers-multiple",
            "X-Client-ID",
            "Missing required header: X-Client-ID",
            "Multiple headers partially missing",
        ),
    ],
)
def test_missing_headers_blocked(
    auth_decorator_app: Flask,
    endpoint: str,
    missing_header: str,
    expected_message: str,
    description: str,
) -> None:
    """Test that missing required headers are blocked."""
    with auth_decorator_app.test_client() as client:
        headers: dict[str, str] = {"X-Forwarded-For": "127.0.0.1"}
        if endpoint == "/headers-multiple":
            headers["X-API-Version"] = "v2"  # Add one header but not the other

        method = (
            "post"
            if endpoint == "/api-key-custom" or endpoint == "/headers-multiple"
            else "get"
        )
        response = getattr(client, method)(endpoint, headers=headers)

        assert response.status_code == 400, f"{description} should return 400"
        assert expected_message in response.data.decode(), (
            f"{description} should show correct error message"
        )


@pytest.mark.parametrize(
    "endpoint,headers,expected_message,description",
    [
        (
            "/api-key-default",
            {"X-Forwarded-For": "127.0.0.1", "X-API-Key": "test-key"},
            "API key required (default header)",
            "API key with header allowed",
        ),
        (
            "/headers-multiple",
            {
                "X-Forwarded-For": "127.0.0.1",
                "X-API-Version": "v2",
                "X-Client-ID": "test-client",
            },
            "Multiple headers required",
            "All required headers present",
        ),
    ],
)
def test_valid_headers_allowed(
    auth_decorator_app: Flask,
    endpoint: str,
    headers: dict[str, str],
    expected_message: str,
    description: str,
) -> None:
    """Test that requests with valid headers are allowed."""
    with auth_decorator_app.test_client() as client:
        method = "post" if endpoint == "/headers-multiple" else "get"
        response = getattr(client, method)(endpoint, headers=headers)

        assert response.status_code == 200, f"{description} should return 200"
        assert response.get_json()["message"] == expected_message, (
            f"{description} should return correct message"
        )


def test_authentication_endpoints_response(auth_decorator_app: Flask) -> None:
    """Test calling authentication endpoints and their responses."""
    with auth_decorator_app.test_client() as client:
        # Test secure endpoint with HTTP (should redirect to HTTPS)
        response = client.get("/secure", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 301  # HTTPS redirect

        # Test secure endpoint with HTTPS (using X-Forwarded-Proto)
        response = client.get(
            "/secure",
            headers={
                "X-Forwarded-For": "8.8.8.8",
                "X-Forwarded-Proto": "https",
            },
        )
        assert response.status_code == 200
        assert response.get_json()["message"] == "HTTPS required"

        # Test auth default endpoint with Bearer token
        response = client.get(
            "/auth-default",
            headers={
                "X-Forwarded-For": "8.8.8.8",
                "Authorization": "Bearer test-token",
            },
        )
        assert response.status_code == 200
        assert response.get_json()["message"] == "Auth required (default)"

        # Test auth basic endpoint with Basic auth
        response = client.get(
            "/auth-basic",
            headers={
                "X-Forwarded-For": "8.8.8.8",
                "Authorization": "Basic dGVzdDp0ZXN0",  # test:test in base64
            },
        )
        assert response.status_code == 200
        assert response.get_json()["message"] == "Basic auth required"

        # Test headers single endpoint
        response = client.get(
            "/headers-single",
            headers={"X-Forwarded-For": "8.8.8.8", "X-API-Version": "v1"},
        )
        assert response.status_code == 200
        assert response.get_json()["message"] == "Single header required"

        # Test api-key-custom endpoint
        response = client.post(
            "/api-key-custom",
            headers={"X-Forwarded-For": "8.8.8.8", "Authorization": "test-key"},
        )
        assert response.status_code == 200
        assert response.get_json()["message"] == "API key required (custom header)"


def test_authentication_decorators_unit(security_config: SecurityConfig) -> None:
    """Unit tests for authentication decorators."""
    decorator = SecurityDecorator(security_config)

    mock_func = Mock()
    mock_func.__name__ = mock_func.__qualname__ = "test_func"
    mock_func.__module__ = "test_module"

    # Test require_https
    https_decorator = decorator.require_https()
    decorated_func = https_decorator(mock_func)

    route_id = decorated_func._guard_route_id
    route_config = decorator.get_route_config(route_id)
    assert route_config is not None
    assert route_config.require_https is True

    # Test require_auth default
    auth_decorator = decorator.require_auth()
    decorated_func2 = auth_decorator(mock_func)

    route_id2 = decorated_func2._guard_route_id
    route_config2 = decorator.get_route_config(route_id2)
    assert route_config2 is not None
    assert route_config2.auth_required == "bearer"

    # Test require_auth custom
    auth_custom_decorator = decorator.require_auth(type="digest")
    decorated_func3 = auth_custom_decorator(mock_func)

    route_id3 = decorated_func3._guard_route_id
    route_config3 = decorator.get_route_config(route_id3)
    assert route_config3 is not None
    assert route_config3.auth_required == "digest"

    # Test api_key_auth default
    api_key_decorator = decorator.api_key_auth()
    decorated_func4 = api_key_decorator(mock_func)

    route_id4 = decorated_func4._guard_route_id
    route_config4 = decorator.get_route_config(route_id4)
    assert route_config4 is not None
    assert route_config4.api_key_required is True
    assert route_config4.required_headers["X-API-Key"] == "required"

    # Test api_key_auth custom
    api_key_custom_decorator = decorator.api_key_auth(header_name="X-Custom-Key")
    decorated_func5 = api_key_custom_decorator(mock_func)

    route_id5 = decorated_func5._guard_route_id
    route_config5 = decorator.get_route_config(route_id5)
    assert route_config5 is not None
    assert route_config5.api_key_required is True
    assert route_config5.required_headers["X-Custom-Key"] == "required"

    # Test require_headers
    headers_decorator = decorator.require_headers(
        {"X-Test": "value", "X-Other": "required"}
    )
    decorated_func6 = headers_decorator(mock_func)

    route_id6 = decorated_func6._guard_route_id
    route_config6 = decorator.get_route_config(route_id6)
    assert route_config6 is not None
    assert route_config6.required_headers["X-Test"] == "value"
    assert route_config6.required_headers["X-Other"] == "required"


def test_authentication_failures_blocked(auth_decorator_app: Flask) -> None:
    """Test that authentication failures are properly blocked and logged."""
    with auth_decorator_app.test_client() as client:
        # Test auth default endpoint without Bearer token
        response = client.get("/auth-default", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 401
        assert "Authentication required" in response.data.decode()

        # Test auth default endpoint with invalid Bearer token format
        response = client.get(
            "/auth-default",
            headers={
                "X-Forwarded-For": "8.8.8.8",
                "Authorization": "Invalid token-format",
            },
        )
        assert response.status_code == 401
        assert "Authentication required" in response.data.decode()

        # Test auth basic endpoint without Basic auth
        response = client.get("/auth-basic", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 401
        assert "Authentication required" in response.data.decode()

        # Test auth basic endpoint with invalid Basic auth format
        response = client.get(
            "/auth-basic",
            headers={
                "X-Forwarded-For": "8.8.8.8",
                "Authorization": "Bearer wrong-type",
            },
        )
        assert response.status_code == 401
        assert "Authentication required" in response.data.decode()


def test_auth_passive_mode(security_config: SecurityConfig) -> None:
    """Test authentication check in passive mode."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    security_config.passive_mode = True
    security_config.trusted_proxies = ["127.0.0.1"]

    decorator = SecurityDecorator(security_config)

    @app.route("/auth-test")
    @decorator.require_auth("bearer")
    def auth_endpoint() -> dict[str, str]:
        return {"message": "ok"}

    FlaskAPIGuard(app, config=security_config)

    with app.test_client() as client:
        # Missing auth - should pass in passive mode
        response = client.get("/auth-test", headers={"X-Forwarded-For": "8.8.8.8"})
        assert response.status_code == 200
