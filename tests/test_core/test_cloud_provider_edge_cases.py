from unittest.mock import MagicMock, Mock, patch

import pytest
from flask import Flask, Request, g

from flaskapi_guard.core.checks.implementations.cloud_provider import CloudProviderCheck
from flaskapi_guard.decorators.base import RouteConfig
from flaskapi_guard.models import SecurityConfig


@pytest.fixture
def mock_guard() -> Mock:
    """Create mock guard."""
    config = SecurityConfig()
    config.block_cloud_providers = {"aws", "gcp"}
    config.passive_mode = False

    guard = Mock()
    guard.config = config
    guard.logger = Mock()
    guard.event_bus = Mock()
    guard.event_bus.send_cloud_detection_events = MagicMock()
    guard.create_error_response = MagicMock(return_value=Mock(status_code=403))
    guard.route_resolver = Mock()
    guard.route_resolver.should_bypass_check = Mock(return_value=False)
    guard.route_resolver.get_cloud_providers_to_check = Mock(
        return_value=["aws", "gcp"]
    )
    return guard


@pytest.fixture
def cloud_check(mock_guard: Mock) -> CloudProviderCheck:
    """Create CloudProviderCheck instance."""
    return CloudProviderCheck(mock_guard)


@pytest.fixture
def _app() -> Flask:
    """Create a Flask app for test request context."""
    return Flask(__name__)


class TestCloudProviderEdgeCases:
    """Test CloudProviderCheck edge cases."""

    def test_check_no_client_ip(
        self, cloud_check: CloudProviderCheck, _app: Flask
    ) -> None:
        """Test check returns None when client_ip is None."""
        with _app.test_request_context():
            g.client_ip = None
            g.route_config = None
            g.is_whitelisted = False
            mock_request = Mock(spec=Request)

            result = cloud_check.check(mock_request)
            assert result is None

    def test_check_bypass_clouds_check(
        self, cloud_check: CloudProviderCheck, _app: Flask
    ) -> None:
        """Test check returns None when clouds check is bypassed."""
        route_config = RouteConfig()

        with _app.test_request_context():
            g.client_ip = "1.2.3.4"
            g.route_config = route_config
            g.is_whitelisted = False
            mock_request = Mock(spec=Request)

            # Replace route_resolver with new mock
            cloud_check.middleware.route_resolver = Mock()
            cloud_check.middleware.route_resolver.should_bypass_check = Mock(
                return_value=True
            )
            cloud_check.middleware.route_resolver.get_cloud_providers_to_check = Mock(
                return_value=["aws", "gcp"]
            )

            result = cloud_check.check(mock_request)
            assert result is None

    def test_check_passive_mode(
        self,
        cloud_check: CloudProviderCheck,
        _app: Flask,
    ) -> None:
        """Test check returns None in passive mode."""
        cloud_check.config.passive_mode = True

        with _app.test_request_context():
            g.client_ip = "1.2.3.4"
            g.route_config = None
            g.is_whitelisted = False
            mock_request = Mock(spec=Request)

            with patch(
                "flaskapi_guard.core.checks.implementations.cloud_provider.cloud_handler"
            ) as mock_cloud_handler:
                mock_cloud_handler.is_cloud_ip.return_value = True

                with patch(
                    "flaskapi_guard.core.checks.implementations.cloud_provider.log_activity"
                ) as mock_log:
                    mock_log.return_value = MagicMock()

                    result = cloud_check.check(mock_request)
                    assert result is None

    def test_check_no_cloud_providers_to_check(
        self, cloud_check: CloudProviderCheck, _app: Flask
    ) -> None:
        """Test check returns None when no cloud providers to check."""
        with _app.test_request_context():
            g.client_ip = "1.2.3.4"
            g.route_config = None
            g.is_whitelisted = False
            mock_request = Mock(spec=Request)

            # Replace route_resolver with new mock
            cloud_check.middleware.route_resolver = Mock()
            cloud_check.middleware.route_resolver.should_bypass_check = Mock(
                return_value=False
            )
            cloud_check.middleware.route_resolver.get_cloud_providers_to_check = Mock(
                return_value=None
            )

            result = cloud_check.check(mock_request)
            assert result is None

    def test_check_not_cloud_ip(
        self, cloud_check: CloudProviderCheck, _app: Flask
    ) -> None:
        """Test check returns None when IP is not from blocked cloud provider."""
        with _app.test_request_context():
            g.client_ip = "1.2.3.4"
            g.route_config = None
            g.is_whitelisted = False
            mock_request = Mock(spec=Request)

            with patch(
                "flaskapi_guard.core.checks.implementations.cloud_provider.cloud_handler"
            ) as mock_cloud_handler:
                mock_cloud_handler.is_cloud_ip.return_value = False

                result = cloud_check.check(mock_request)
                assert result is None

    def test_check_cloud_ip_active_mode(
        self,
        cloud_check: CloudProviderCheck,
        _app: Flask,
    ) -> None:
        """Test check returns error response in active mode for cloud IP."""
        cloud_check.config.passive_mode = False

        with _app.test_request_context():
            g.client_ip = "1.2.3.4"
            g.route_config = None
            g.is_whitelisted = False
            mock_request = Mock(spec=Request)

            with patch(
                "flaskapi_guard.core.checks.implementations.cloud_provider.cloud_handler"
            ) as mock_cloud_handler:
                mock_cloud_handler.is_cloud_ip.return_value = True

                with patch(
                    "flaskapi_guard.core.checks.implementations.cloud_provider.log_activity"
                ) as mock_log:
                    mock_log.return_value = MagicMock()

                    result = cloud_check.check(mock_request)
                    assert result is not None
                    assert result.status_code == 403
