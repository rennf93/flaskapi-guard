from typing import Any

import pytest

from flaskapi_guard.handlers.behavior_handler import BehaviorTracker
from flaskapi_guard.models import SecurityConfig


@pytest.fixture
def security_config() -> SecurityConfig:
    """Create security config."""
    return SecurityConfig()


@pytest.fixture
def tracker(security_config: SecurityConfig) -> BehaviorTracker:
    """Create BehaviorTracker instance."""
    return BehaviorTracker(security_config)


class TestHandleArrayMatchEdgeCases:
    """Test _handle_array_match edge cases."""

    def test_handle_array_match_part_not_in_dict(
        self, tracker: BehaviorTracker
    ) -> None:
        """Test _handle_array_match when part not in current dict."""
        current = {"other_field": [1, 2, 3]}
        part = "missing_field[]"
        expected = "test"

        result = tracker._handle_array_match(current, part, expected)
        assert result is False

    def test_handle_array_match_not_a_list(self, tracker: BehaviorTracker) -> None:
        """Test _handle_array_match when field is not a list."""
        current = {"items": "not_a_list"}
        part = "items[]"
        expected = "test"

        result = tracker._handle_array_match(current, part, expected)
        assert result is False

    def test_handle_array_match_current_not_dict(
        self, tracker: BehaviorTracker
    ) -> None:
        """Test _handle_array_match when current is not a dict."""
        current = ["not", "a", "dict"]
        part = "items[]"
        expected = "test"

        result = tracker._handle_array_match(current, part, expected)
        assert result is False


class TestTraverseJsonPathEdgeCases:
    """Test _traverse_json_path edge cases."""

    def test_traverse_json_path_missing_key(self, tracker: BehaviorTracker) -> None:
        """Test _traverse_json_path with missing key in path."""
        data = {"level1": {"level2": "value"}}
        path = "level1.missing.level3"

        result = tracker._traverse_json_path(data, path)
        assert result is None

    def test_traverse_json_path_not_a_dict(self, tracker: BehaviorTracker) -> None:
        """Test _traverse_json_path when encountering non-dict."""
        data = {"level1": "string_value"}
        path = "level1.level2"

        result = tracker._traverse_json_path(data, path)
        assert result is None

    def test_traverse_json_path_root_not_dict(self, tracker: BehaviorTracker) -> None:
        """Test _traverse_json_path when data is not a dict."""
        data = ["not", "a", "dict"]
        path = "some.path"

        result = tracker._traverse_json_path(data, path)
        assert result is None

    def test_traverse_json_path_success(self, tracker: BehaviorTracker) -> None:
        """Test _traverse_json_path with valid path."""
        data = {"level1": {"level2": {"level3": "found"}}}
        path = "level1.level2.level3"

        result = tracker._traverse_json_path(data, path)
        assert result == "found"


class TestMatchJsonPatternEdgeCases:
    """Test _match_json_pattern edge cases covering non-dict traversal."""

    def test_match_json_pattern_non_dict_in_path(
        self, tracker: BehaviorTracker
    ) -> None:
        """Test _match_json_pattern when encountering non-dict during traversal."""
        data = {"result": "string_not_dict"}
        pattern = "result.nested==value"

        result = tracker._match_json_pattern(data, pattern)
        assert result is False

    def test_match_json_pattern_missing_key_in_path(
        self, tracker: BehaviorTracker
    ) -> None:
        """Test _match_json_pattern with missing key in path."""
        data = {"result": {"status": "win"}}
        pattern = "result.missing.key==value"

        result = tracker._match_json_pattern(data, pattern)
        assert result is False

    @pytest.mark.parametrize(
        "data,pattern",
        [
            ({"other": [1, 2, 3]}, "items[]==test"),
            ({"items": "not_a_list"}, "items[]==test"),
            ({"level1": "not_dict"}, "level1.level2==value"),
        ],
    )
    def test_match_json_pattern_edge_cases(
        self, tracker: BehaviorTracker, data: dict[str, Any], pattern: str
    ) -> None:
        """Test various edge cases in JSON pattern matching."""
        result = tracker._match_json_pattern(data, pattern)
        assert result is False
