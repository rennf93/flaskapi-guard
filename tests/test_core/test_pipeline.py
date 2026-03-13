from unittest.mock import MagicMock, Mock

import pytest
from flask import Request, Response

from flaskapi_guard.core.checks.base import SecurityCheck
from flaskapi_guard.core.checks.pipeline import SecurityCheckPipeline


class MockCheck(SecurityCheck):
    """Mock security check for testing."""

    def __init__(self, middleware: Mock, name: str, should_block: bool = False) -> None:
        super().__init__(middleware)
        self._name = name
        self._should_block = should_block

    @property
    def check_name(self) -> str:
        return self._name

    def check(self, request: Request) -> Response | None:
        if self._should_block:
            return Response("Blocked", status=403)
        return None


class FailingCheck(SecurityCheck):
    """Check that raises an exception."""

    def __init__(self, middleware: Mock, name: str = "failing_check") -> None:
        super().__init__(middleware)
        self._name = name

    @property
    def check_name(self) -> str:
        return self._name

    def check(self, request: Request) -> Response | None:
        raise ValueError("Check error")


@pytest.fixture
def mock_guard() -> Mock:
    """Create a mock guard instance."""
    guard = Mock()
    guard.config = Mock()
    guard.config.fail_secure = False
    guard.config.passive_mode = False
    guard.logger = Mock()
    guard.event_bus = Mock()
    guard.create_error_response = MagicMock(return_value=Response("Error", status=500))
    return guard


@pytest.fixture
def mock_request() -> Mock:
    """Create a mock request."""
    request = Mock(spec=Request)
    request.path = "/test"
    request.method = "GET"
    return request


class TestSecurityCheckPipeline:
    """Test SecurityCheckPipeline class."""

    def test_pipeline_initialization(self, mock_guard: Mock) -> None:
        """Test pipeline initialization with checks."""
        check1 = MockCheck(mock_guard, "check1")
        check2 = MockCheck(mock_guard, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])

        assert len(pipeline) == 2
        assert pipeline.get_check_names() == ["check1", "check2"]

    def test_execute_all_checks_pass(
        self, mock_guard: Mock, mock_request: Mock
    ) -> None:
        """Test pipeline execution when all checks pass."""
        check1 = MockCheck(mock_guard, "check1", should_block=False)
        check2 = MockCheck(mock_guard, "check2", should_block=False)

        pipeline = SecurityCheckPipeline([check1, check2])
        result = pipeline.execute(mock_request)

        assert result is None

    def test_execute_first_check_blocks(
        self, mock_guard: Mock, mock_request: Mock
    ) -> None:
        """Test pipeline stops when first check blocks."""
        check1 = MockCheck(mock_guard, "check1", should_block=True)
        check2 = MockCheck(mock_guard, "check2", should_block=False)

        pipeline = SecurityCheckPipeline([check1, check2])
        result = pipeline.execute(mock_request)

        assert result is not None
        assert result.status_code == 403

    def test_execute_second_check_blocks(
        self, mock_guard: Mock, mock_request: Mock
    ) -> None:
        """Test pipeline continues until second check blocks."""
        check1 = MockCheck(mock_guard, "check1", should_block=False)
        check2 = MockCheck(mock_guard, "check2", should_block=True)

        pipeline = SecurityCheckPipeline([check1, check2])
        result = pipeline.execute(mock_request)

        assert result is not None
        assert result.status_code == 403

    def test_execute_with_exception_fail_open(
        self, mock_guard: Mock, mock_request: Mock
    ) -> None:
        """Test exception handling with fail-open (default)."""
        failing_check = FailingCheck(mock_guard, "failing_check")
        passing_check = MockCheck(mock_guard, "passing_check", should_block=False)

        mock_guard.config.fail_secure = False

        pipeline = SecurityCheckPipeline([failing_check, passing_check])
        result = pipeline.execute(mock_request)

        assert result is None

    def test_execute_with_exception_fail_secure(
        self, mock_guard: Mock, mock_request: Mock
    ) -> None:
        """Test exception handling with fail-secure mode."""
        failing_check = FailingCheck(mock_guard, "failing_check")
        passing_check = MockCheck(mock_guard, "passing_check", should_block=False)

        mock_guard.config.fail_secure = True

        pipeline = SecurityCheckPipeline([failing_check, passing_check])
        result = pipeline.execute(mock_request)

        assert result is not None
        assert result.status_code == 500

    def test_execute_with_exception_no_fail_secure_attr(
        self, mock_guard: Mock, mock_request: Mock
    ) -> None:
        """Test exception handling when fail_secure attribute doesn't exist."""
        failing_check = FailingCheck(mock_guard, "failing_check")

        if hasattr(mock_guard.config, "fail_secure"):
            delattr(mock_guard.config, "fail_secure")

        pipeline = SecurityCheckPipeline([failing_check])
        result = pipeline.execute(mock_request)

        assert result is None

    def test_add_check(self, mock_guard: Mock) -> None:
        """Test adding a check to the pipeline."""
        check1 = MockCheck(mock_guard, "check1")
        check2 = MockCheck(mock_guard, "check2")

        pipeline = SecurityCheckPipeline([check1])
        assert len(pipeline) == 1

        pipeline.add_check(check2)
        assert len(pipeline) == 2
        assert pipeline.get_check_names() == ["check1", "check2"]

    def test_insert_check(self, mock_guard: Mock) -> None:
        """Test inserting a check at specific position."""
        check1 = MockCheck(mock_guard, "check1")
        check2 = MockCheck(mock_guard, "check2")
        check3 = MockCheck(mock_guard, "check3")

        pipeline = SecurityCheckPipeline([check1, check3])
        pipeline.insert_check(1, check2)

        assert len(pipeline) == 3
        assert pipeline.get_check_names() == ["check1", "check2", "check3"]

    def test_remove_check_found(self, mock_guard: Mock) -> None:
        """Test removing a check by name when found."""
        check1 = MockCheck(mock_guard, "check1")
        check2 = MockCheck(mock_guard, "check2")
        check3 = MockCheck(mock_guard, "check3")

        pipeline = SecurityCheckPipeline([check1, check2, check3])
        result = pipeline.remove_check("check2")

        assert result is True
        assert len(pipeline) == 2
        assert pipeline.get_check_names() == ["check1", "check3"]

    def test_remove_check_not_found(self, mock_guard: Mock) -> None:
        """Test removing a check by name when not found."""
        check1 = MockCheck(mock_guard, "check1")

        pipeline = SecurityCheckPipeline([check1])
        result = pipeline.remove_check("nonexistent")

        assert result is False
        assert len(pipeline) == 1

    def test_get_check_names(self, mock_guard: Mock) -> None:
        """Test getting list of check names."""
        check1 = MockCheck(mock_guard, "check1")
        check2 = MockCheck(mock_guard, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])
        names = pipeline.get_check_names()

        assert names == ["check1", "check2"]

    def test_len(self, mock_guard: Mock) -> None:
        """Test __len__ returns correct number of checks."""
        check1 = MockCheck(mock_guard, "check1")
        check2 = MockCheck(mock_guard, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])

        assert len(pipeline) == 2

    def test_repr(self, mock_guard: Mock) -> None:
        """Test __repr__ returns readable string representation."""
        check1 = MockCheck(mock_guard, "check1")
        check2 = MockCheck(mock_guard, "check2")

        pipeline = SecurityCheckPipeline([check1, check2])
        repr_str = repr(pipeline)

        assert "SecurityCheckPipeline" in repr_str
        assert "2 checks" in repr_str
        assert "check1" in repr_str
        assert "check2" in repr_str

    @pytest.mark.parametrize(
        "checks,expected_count",
        [
            ([], 0),
            (["check1"], 1),
            (["check1", "check2"], 2),
            (["check1", "check2", "check3"], 3),
        ],
    )
    def test_pipeline_various_sizes(
        self, mock_guard: Mock, checks: list[str], expected_count: int
    ) -> None:
        """Test pipeline with various numbers of checks."""
        check_objects: list[SecurityCheck] = [
            MockCheck(mock_guard, name) for name in checks
        ]
        pipeline = SecurityCheckPipeline(check_objects)

        assert len(pipeline) == expected_count
        assert pipeline.get_check_names() == checks
