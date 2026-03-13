from unittest.mock import patch

import pytest
from flask import Flask

from flaskapi_guard import SecurityConfig, SecurityDecorator
from flaskapi_guard.extension import FlaskAPIGuard
from flaskapi_guard.handlers.cloud_handler import cloud_handler


@pytest.fixture
def decorator_app(security_config: SecurityConfig) -> Flask:
    """Create Flask app with decorator integration using existing security_config."""
    app = Flask(__name__)
    app.config["TESTING"] = True

    security_config.trusted_proxies = ["127.0.0.1"]
    security_config.enable_penetration_detection = False

    decorator = SecurityDecorator(security_config)

    @app.route("/whitelist")
    @decorator.require_ip(whitelist=["127.0.0.1", "192.168.1.0/24"])
    def whitelist_endpoint() -> dict[str, str]:
        return {"message": "Whitelisted IP access"}

    @app.route("/blacklist")
    @decorator.require_ip(blacklist=["10.0.0.1", "172.16.0.0/16"])
    def blacklist_endpoint() -> dict[str, str]:
        return {"message": "Not blacklisted"}

    @app.route("/block-countries")
    @decorator.block_countries(["CN", "RU"])
    def block_countries_endpoint() -> dict[str, str]:
        return {"message": "Country allowed"}

    @app.route("/allow-countries")
    @decorator.allow_countries(["US", "GB", "DE"])
    def allow_countries_endpoint() -> dict[str, str]:
        return {"message": "Country whitelisted"}

    @app.route("/block-clouds")
    @decorator.block_clouds(["AWS", "GCP"])
    def block_clouds_endpoint() -> dict[str, str]:
        return {"message": "Not from blocked cloud"}

    @app.route("/block-all-clouds")
    @decorator.block_clouds()
    def block_all_clouds_endpoint() -> dict[str, str]:
        return {"message": "Not from any cloud"}

    @app.route("/bypass")
    @decorator.bypass(["ip", "rate_limit"])
    def bypass_endpoint() -> dict[str, str]:
        return {"message": "Security bypassed"}

    @app.route("/multiple")
    @decorator.require_ip(whitelist=["192.168.1.100"])
    @decorator.block_countries(["FR"])
    def multiple_decorators_endpoint() -> dict[str, str]:
        return {"message": "Multiple security rules"}

    FlaskAPIGuard(app, config=security_config)
    app.extensions["flaskapi_guard"]["guard_decorator"] = decorator

    return app


@pytest.mark.parametrize(
    "endpoint,ip,expected_status,description",
    [
        ("/whitelist", "127.0.0.1", 200, "Whitelisted IP should pass"),
        ("/whitelist", "192.168.1.50", 200, "IP in whitelisted CIDR should pass"),
        ("/whitelist", "10.0.0.1", 403, "Non-whitelisted IP should be blocked"),
        ("/blacklist", "127.0.0.1", 200, "Non-blacklisted IP should pass"),
        ("/blacklist", "10.0.0.1", 403, "Blacklisted IP should be blocked"),
        ("/blacklist", "172.16.5.10", 403, "IP in blacklisted CIDR should be blocked"),
    ],
)
def test_ip_access_control(
    decorator_app: Flask,
    endpoint: str,
    ip: str,
    expected_status: int,
    description: str,
) -> None:
    """Test IP whitelist and blacklist decorators."""
    with decorator_app.test_client() as client:
        response = client.get(
            endpoint,
            headers={"X-Forwarded-For": ip},
        )
        assert response.status_code == expected_status, description


@pytest.mark.parametrize(
    "endpoint,country,expected_status,description",
    [
        ("/block-countries", "US", 200, "Allowed country should pass"),
        ("/block-countries", "CN", 403, "Blocked country should be rejected"),
        ("/block-countries", "RU", 403, "Blocked country should be rejected"),
        ("/allow-countries", "US", 200, "Whitelisted country should pass"),
        ("/allow-countries", "GB", 200, "Whitelisted country should pass"),
        ("/allow-countries", "FR", 403, "Non-whitelisted country should be blocked"),
    ],
)
def test_country_access_control(
    decorator_app: Flask,
    endpoint: str,
    country: str,
    expected_status: int,
    description: str,
) -> None:
    """Test country blocking and allowing decorators."""
    test_ips = {
        "US": "8.8.8.8",
        "CN": "1.2.3.4",
        "RU": "5.6.7.8",
        "GB": "9.9.9.9",
        "DE": "10.10.10.10",
        "FR": "11.11.11.11",
    }

    with patch(
        "flaskapi_guard.handlers.ipinfo_handler.IPInfoManager.get_country"
    ) as mock_geo:
        mock_geo.return_value = country

        with decorator_app.test_client() as client:
            response = client.get(
                endpoint,
                headers={"X-Forwarded-For": test_ips[country]},
            )
            assert response.status_code == expected_status, description


def test_cloud_provider_blocking(decorator_app: Flask) -> None:
    """Test cloud provider blocking decorator."""
    with patch.object(cloud_handler, "is_cloud_ip") as mock_cloud:
        mock_cloud.return_value = False
        with decorator_app.test_client() as client:
            response = client.get(
                "/block-clouds",
                headers={"X-Forwarded-For": "192.168.1.1"},
            )
            assert response.status_code == 200

        mock_cloud.return_value = True
        with decorator_app.test_client() as client:
            response = client.get(
                "/block-clouds",
                # NOTE: AWS IP
                headers={"X-Forwarded-For": "54.240.0.1"},
            )
            assert response.status_code == 403


def test_block_all_clouds_default(decorator_app: Flask) -> None:
    """Test block_clouds decorator with default behavior (blocks all providers)."""
    with patch.object(cloud_handler, "is_cloud_ip") as mock_cloud:
        mock_cloud.return_value = False
        with decorator_app.test_client() as client:
            response = client.get(
                "/block-all-clouds",
                headers={"X-Forwarded-For": "192.168.1.1"},
            )
            assert response.status_code == 200

        mock_cloud.return_value = True
        with decorator_app.test_client() as client:
            response = client.get(
                "/block-all-clouds",
                headers={"X-Forwarded-For": "54.240.0.1"},  # AWS IP
            )
            assert response.status_code == 403


def test_security_bypass(decorator_app: Flask) -> None:
    """Test security bypass decorator."""
    with decorator_app.test_client() as client:
        response = client.get(
            "/bypass",
            headers={"X-Forwarded-For": "192.168.1.1"},
        )
        assert response.status_code == 200


def test_multiple_decorators(decorator_app: Flask) -> None:
    """Test multiple decorators on single endpoint."""
    with patch(
        "flaskapi_guard.handlers.ipinfo_handler.IPInfoManager.get_country"
    ) as mock_geo:
        mock_geo.return_value = "US"
        with decorator_app.test_client() as client:
            response = client.get(
                "/multiple",
                headers={"X-Forwarded-For": "192.168.1.100"},
            )
            assert response.status_code == 200

        mock_geo.return_value = "FR"
        with decorator_app.test_client() as client:
            response = client.get(
                "/multiple",
                headers={"X-Forwarded-For": "192.168.1.100"},
            )
            assert response.status_code == 200

        mock_geo.return_value = "FR"
        with decorator_app.test_client() as client:
            response = client.get(
                "/multiple",
                headers={"X-Forwarded-For": "10.0.0.5"},
            )
            assert response.status_code == 403
