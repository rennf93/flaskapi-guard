import ipaddress
import itertools
from collections.abc import Generator
from unittest.mock import MagicMock, Mock, patch

import pytest

from flaskapi_guard.handlers.cloud_handler import (
    cloud_handler,
    fetch_aws_ip_ranges,
    fetch_azure_ip_ranges,
    fetch_gcp_ip_ranges,
)
from flaskapi_guard.handlers.redis_handler import RedisManager
from flaskapi_guard.models import SecurityConfig


@pytest.fixture
def mock_httpx_client() -> Generator[Mock, None, None]:
    """Mock httpx.Client for all fetch functions."""
    with patch("flaskapi_guard.handlers.cloud_handler.httpx.Client") as mock_client_class:
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__ = Mock(return_value=mock_client)
        mock_client_class.return_value.__exit__ = Mock(return_value=False)
        yield mock_client


def test_fetch_aws_ip_ranges(mock_httpx_client: Mock) -> None:
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.return_value = {
        "prefixes": [
            {"ip_prefix": "192.168.0.0/24", "service": "AMAZON"},
            {"ip_prefix": "10.0.0.0/8", "service": "EC2"},
        ]
    }
    mock_httpx_client.get.return_value = mock_response

    result = fetch_aws_ip_ranges()
    assert ipaddress.IPv4Network("192.168.0.0/24") in result
    assert ipaddress.IPv4Network("10.0.0.0/8") not in result


def test_fetch_gcp_ip_ranges(mock_httpx_client: Mock) -> None:
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.return_value = {
        "prefixes": [{"ipv4Prefix": "172.16.0.0/12"}, {"ipv6Prefix": "2001:db8::/32"}]
    }
    mock_httpx_client.get.return_value = mock_response

    result = fetch_gcp_ip_ranges()
    assert ipaddress.IPv4Network("172.16.0.0/12") in result
    assert ipaddress.IPv6Network("2001:db8::/32") in result
    assert len(result) == 2


def test_fetch_azure_ip_ranges(mock_httpx_client: Mock) -> None:
    mock_html_response = Mock()
    mock_html_response.raise_for_status = Mock()
    mock_html_response.text = """
    Some HTML content
    manually <a href="https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230515.json">
    More HTML content
    """
    mock_json_response = Mock()
    mock_json_response.raise_for_status = Mock()
    mock_json_response.json.return_value = {
        "values": [
            {"properties": {"addressPrefixes": ["192.168.1.0/24", "2001:db8::/32"]}}
        ]
    }
    mock_httpx_client.get.side_effect = [mock_html_response, mock_json_response]

    result = fetch_azure_ip_ranges()
    assert ipaddress.IPv4Network("192.168.1.0/24") in result
    assert ipaddress.IPv6Network("2001:db8::/32") in result
    assert len(result) == 2


def test_cloud_ip_ranges() -> None:
    with (
        patch("flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("flaskapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch("flaskapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_handler._refresh_sync()

        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})
        assert not cloud_handler.is_cloud_ip("8.8.8.8", {"AWS", "GCP", "Azure"})


def test_cloud_ip_refresh() -> None:
    with (
        patch("flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("flaskapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch("flaskapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        cloud_handler._refresh_sync()
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})

        mock_aws.return_value = {ipaddress.IPv4Network("192.168.1.0/24")}
        cloud_handler.refresh()

        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert cloud_handler.is_cloud_ip("192.168.1.1", {"AWS"})


def test_cloud_ip_refresh_subset() -> None:
    with (
        patch("flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("flaskapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch("flaskapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        providers = ["AWS", "GCP", "Azure"]
        for r in range(1, 4):  # Test combinations of 1-3 providers
            for combo in itertools.combinations(providers, r):
                provider_set = set(combo)
                cloud_handler.ip_ranges = {}
                cloud_handler._refresh_sync(provider_set)

                # Verify each provider in the combination works
                if "AWS" in provider_set:
                    assert cloud_handler.is_cloud_ip("192.168.0.1")
                if "GCP" in provider_set:
                    assert cloud_handler.is_cloud_ip("172.16.0.1")
                if "Azure" in provider_set:
                    assert cloud_handler.is_cloud_ip("10.0.0.1")

                # Verify providers not in combination don't match
                if "AWS" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("192.168.0.1")
                if "GCP" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("172.16.0.1")
                if "Azure" not in provider_set:
                    assert not cloud_handler.is_cloud_ip("10.0.0.1")


def test_cloud_ip_ranges_error_handling() -> None:
    with (
        patch(
            "flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges",
            side_effect=Exception("AWS error"),
        ),
        patch(
            "flaskapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges",
            side_effect=Exception("GCP error"),
        ),
        patch(
            "flaskapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges",
            side_effect=Exception("Azure error"),
        ),
    ):
        assert not cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        assert not cloud_handler.is_cloud_ip("172.16.0.1", {"GCP"})
        assert not cloud_handler.is_cloud_ip("10.0.0.1", {"Azure"})


def test_cloud_ip_ranges_invalid_ip() -> None:
    assert not cloud_handler.is_cloud_ip("invalid_ip", {"AWS", "GCP", "Azure"})


def test_fetch_aws_ip_ranges_error(mock_httpx_client: Mock) -> None:
    mock_httpx_client.get.side_effect = Exception("API failure")
    result = fetch_aws_ip_ranges()
    assert result == set()


def test_fetch_gcp_ip_ranges_error(mock_httpx_client: Mock) -> None:
    mock_response = Mock()
    mock_response.raise_for_status = Mock()
    mock_response.json.side_effect = Exception("Invalid JSON")
    mock_httpx_client.get.return_value = mock_response
    result = fetch_gcp_ip_ranges()
    assert result == set()


def test_cloud_manager_refresh_handling() -> None:
    with (
        patch("flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("flaskapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges") as mock_gcp,
        patch("flaskapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges") as mock_azure,
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}
        mock_gcp.return_value = {ipaddress.IPv4Network("172.16.0.0/12")}
        mock_azure.return_value = {ipaddress.IPv4Network("10.0.0.0/8")}

        assert len(cloud_handler.ip_ranges["AWS"]) == 0

        cloud_handler.refresh()
        assert len(cloud_handler.ip_ranges["AWS"]) == 1


def test_is_cloud_ip_ipv6() -> None:
    assert not cloud_handler.is_cloud_ip("2001:db8::1", {"AWS"})


def test_fetch_azure_ip_ranges_url_not_found(mock_httpx_client: Mock) -> None:
    mock_html_response = Mock()
    mock_html_response.raise_for_status = Mock()
    mock_html_response.text = "HTML without download link"
    mock_httpx_client.get.return_value = mock_html_response

    result = fetch_azure_ip_ranges()
    assert result == set()


def test_fetch_azure_ip_ranges_download_failure(mock_httpx_client: Mock) -> None:
    mock_html_response = Mock()
    mock_html_response.raise_for_status = Mock()
    mock_html_response.text = '<a href="https://download.microsoft.com/valid.json">'
    mock_download_response = Mock()
    mock_download_response.raise_for_status.side_effect = Exception("Download failed")

    mock_httpx_client.get.side_effect = [mock_html_response, mock_download_response]

    result = fetch_azure_ip_ranges()
    assert result == set()


def test_cloud_ip_redis_caching(security_config_redis: SecurityConfig) -> None:
    """Test CloudManager with Redis caching"""
    with (
        patch("flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws,
        patch("flaskapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges"),
        patch("flaskapi_guard.handlers.cloud_handler.fetch_azure_ip_ranges"),
    ):
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        # Create manager and initialize Redis
        redis_mgr = RedisManager(security_config_redis)
        redis_mgr.initialize()

        # Initialize Redis and perform initial refresh
        cloud_handler.initialize_redis(redis_mgr)

        # Verify initial fetch and cache
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        cached = redis_mgr.get_key("cloud_ranges", "AWS")
        assert cached == "192.168.0.0/24"

        # Change mock return value and refresh
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.1.0/24")}
        cloud_handler.refresh()

        # Clear Redis cache to force refresh
        redis_mgr.delete("cloud_ranges", "AWS")
        cloud_handler.refresh()

        # Test error handling
        mock_aws.side_effect = Exception("API Error")
        cloud_handler.refresh()
        assert cloud_handler.is_cloud_ip("192.168.1.1", {"AWS"})

        # Test refresh without Redis
        cloud_handler.redis_handler = None
        cloud_handler.refresh()

        redis_mgr.close()


def test_cloud_ip_redis_cache_hit(security_config_redis: SecurityConfig) -> None:
    """Test CloudManager using cached Redis values"""
    redis_mgr = RedisManager(security_config_redis)
    redis_mgr.initialize()

    # Pre-populate Redis cache
    redis_mgr.set_key("cloud_ranges", "AWS", "192.168.0.0/24")

    # Initialize manager with Redis
    cloud_handler.initialize_redis(redis_mgr)

    # Verify manager uses cached value
    with patch("flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws:
        assert cloud_handler.is_cloud_ip("192.168.0.1", {"AWS"})
        mock_aws.assert_not_called()

    redis_mgr.close()


def test_cloud_ip_redis_error_handling(
    security_config_redis: SecurityConfig,
) -> None:
    """Test CloudManager error handling during Redis operations"""
    with patch("flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges") as mock_aws:
        mock_aws.return_value = {ipaddress.IPv4Network("192.168.0.0/24")}

        redis_mgr = RedisManager(security_config_redis)
        redis_mgr.initialize()

        # Clear any existing Redis data
        redis_mgr.delete("cloud_ranges", "AWS")

        # Initialize Redis and test error handling
        mock_aws.side_effect = Exception("API Error")
        cloud_handler.initialize_redis(redis_mgr)

        # Test provider not in ip_ranges during error
        cloud_handler.ip_ranges.pop("AWS", None)
        cloud_handler.refresh({"AWS"})

        assert isinstance(cloud_handler.ip_ranges["AWS"], set)
        assert len(cloud_handler.ip_ranges["AWS"]) == 0

        redis_mgr.close()
