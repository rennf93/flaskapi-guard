import ipaddress
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from flaskapi_guard.handlers.cloud_handler import cloud_handler


@pytest.fixture(autouse=True)
def reset_cloud_handler() -> None:
    cloud_handler.ip_ranges = {"AWS": set(), "GCP": set(), "Azure": set()}
    cloud_handler.last_updated = {"AWS": None, "GCP": None, "Azure": None}
    cloud_handler.redis_handler = None
    cloud_handler.agent_handler = None


def test_last_updated_initialized_to_none() -> None:
    assert cloud_handler.last_updated["AWS"] is None
    assert cloud_handler.last_updated["GCP"] is None
    assert cloud_handler.last_updated["Azure"] is None


def test_last_updated_after_sync_refresh() -> None:
    test_ranges = {ipaddress.ip_network("10.0.0.0/8")}
    with patch(
        "flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges",
        return_value=test_ranges,
    ):
        cloud_handler._refresh_sync({"AWS"})

    assert cloud_handler.last_updated["AWS"] is not None
    assert isinstance(cloud_handler.last_updated["AWS"], datetime)
    assert cloud_handler.last_updated["AWS"].tzinfo == timezone.utc
    assert cloud_handler.last_updated["GCP"] is None


def test_last_updated_after_redis_refresh() -> None:
    mock_redis = MagicMock()
    mock_redis.get_key = MagicMock(return_value=None)
    mock_redis.set_key = MagicMock()
    cloud_handler.redis_handler = mock_redis

    test_ranges = {ipaddress.ip_network("10.0.0.0/8")}
    with patch(
        "flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges",
        return_value=test_ranges,
    ):
        cloud_handler.refresh({"AWS"})

    assert cloud_handler.last_updated["AWS"] is not None
    assert isinstance(cloud_handler.last_updated["AWS"], datetime)
    assert cloud_handler.last_updated["AWS"].tzinfo == timezone.utc


def test_failed_refresh_leaves_last_updated_unchanged() -> None:
    with patch(
        "flaskapi_guard.handlers.cloud_handler.fetch_aws_ip_ranges",
        return_value=set(),
    ):
        cloud_handler._refresh_sync({"AWS"})

    assert cloud_handler.last_updated["AWS"] is None


def test_failed_redis_refresh_leaves_last_updated_unchanged() -> None:
    mock_redis = MagicMock()
    mock_redis.get_key = MagicMock(return_value=None)
    cloud_handler.redis_handler = mock_redis

    with patch(
        "flaskapi_guard.handlers.cloud_handler.fetch_gcp_ip_ranges",
        return_value=set(),
    ):
        cloud_handler.refresh({"GCP"})

    assert cloud_handler.last_updated["GCP"] is None
