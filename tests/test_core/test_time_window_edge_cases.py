from typing import cast
from unittest.mock import MagicMock, Mock

import pytest

from flaskapi_guard.core.checks.implementations.time_window import TimeWindowCheck
from flaskapi_guard.models import SecurityConfig


@pytest.fixture
def mock_guard() -> Mock:
    """Create mock guard."""
    config = SecurityConfig()
    config.passive_mode = False

    guard = Mock()
    guard.config = config
    guard.logger = MagicMock()
    guard.event_bus = Mock()
    guard.event_bus.send_middleware_event = MagicMock()
    guard.create_error_response = MagicMock(return_value=Mock(status_code=403))
    return guard


@pytest.fixture
def time_window_check(mock_guard: Mock) -> TimeWindowCheck:
    """Create TimeWindowCheck instance."""
    return TimeWindowCheck(mock_guard)


class TestTimeWindowEdgeCases:
    """Test TimeWindowCheck edge cases."""

    def test_check_time_window_exception_handling(
        self, time_window_check: TimeWindowCheck
    ) -> None:
        """Test _check_time_window handles exceptions and returns True."""
        invalid_restrictions = {"invalid": "data"}

        result = time_window_check._check_time_window(invalid_restrictions)

        assert result is True
        cast(MagicMock, time_window_check.logger.error).assert_called_once()

    def test_check_time_window_missing_start_key(
        self, time_window_check: TimeWindowCheck
    ) -> None:
        """Test _check_time_window with missing start key."""
        incomplete_restrictions = {"end": "18:00"}

        result = time_window_check._check_time_window(incomplete_restrictions)

        assert result is True
        cast(MagicMock, time_window_check.logger.error).assert_called_once()

    def test_check_time_window_missing_end_key(
        self, time_window_check: TimeWindowCheck
    ) -> None:
        """Test _check_time_window with missing end key."""
        incomplete_restrictions = {"start": "09:00"}

        result = time_window_check._check_time_window(incomplete_restrictions)

        assert result is True
        cast(MagicMock, time_window_check.logger.error).assert_called_once()

    def test_check_time_window_invalid_timezone_fallback(
        self, time_window_check: TimeWindowCheck
    ) -> None:
        """Test _check_time_window falls back to UTC for invalid timezone."""
        restrictions = {
            "start": "00:00",
            "end": "23:59",
            "timezone": "Invalid/Timezone",
        }

        result = time_window_check._check_time_window(restrictions)

        assert result is True
