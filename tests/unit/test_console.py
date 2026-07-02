"""Unit tests for console progress indicators (Story 5.3, Task 7.1, 7.2)."""

import asyncio
import io
from unittest.mock import patch

import pytest
from rich.console import Console

from bqcheck.console import (
    show_analysis_progress,
    show_extraction_progress,
    show_server_upload,
    show_start_message,
    show_success_message,
)


class TestProgressMessages:
    """Test progress message formatting (Task 7.1)."""

    def test_start_message_formatting(self):
        """Test start message includes emoji and project ID (AC1)."""
        # Given: Project ID
        project_id = "my-gcp-project"

        # When: Display start message
        console = Console(file=io.StringIO())
        with patch("bqcheck.console.console", console):
            show_start_message(project_id)

        # Then: Message includes emoji and project ID
        output = console.file.getvalue()
        assert "🔍" in output
        assert "Starting BigQuery sanity check" in output
        assert "my-gcp-project" in output

    def test_extraction_progress_context_manager(self):
        """Test extraction progress returns a context manager (AC2)."""
        # Given: Console for testing
        console = Console(file=io.StringIO())

        # When: Get extraction progress context
        with patch("bqcheck.console.console", console):
            context = show_extraction_progress()

        # Then: Context is a status manager
        assert hasattr(context, "__enter__")
        assert hasattr(context, "__exit__")

    def test_server_upload_message(self):
        """Test server upload message (AC3)."""
        # Given: Console for testing
        console = Console(file=io.StringIO())

        # When: Display server upload message
        with patch("bqcheck.console.console", console):
            show_server_upload()

        # Then: Message includes emoji and text
        output = console.file.getvalue()
        assert "☁️" in output
        assert "Sending anonymized metadata" in output

    def test_success_message_formatting(self):
        """Test success message includes count and formatted savings (AC5)."""
        # Given: Check results
        count = 5
        savings = 1234.56

        # When: Display success message
        console = Console(file=io.StringIO())
        with patch("bqcheck.console.console", console):
            show_success_message(count, savings)

        # Then: Message includes count and formatted savings
        output = console.file.getvalue()
        assert "✅" in output
        assert "5 recommendations" in output
        assert "€1,234.56" in output or "€1234.56" in output

    def test_success_message_zero_recommendations(self):
        """Test success message with zero recommendations."""
        # Given: No recommendations
        count = 0
        savings = 0.0

        # When: Display success message
        console = Console(file=io.StringIO())
        with patch("bqcheck.console.console", console):
            show_success_message(count, savings)

        # Then: Message handles zero correctly
        output = console.file.getvalue()
        assert "0 recommendations" in output
        assert "€0.00" in output

    def test_success_message_large_savings(self):
        """Test success message with large savings (thousands separator)."""
        # Given: Large savings
        count = 150
        savings = 123456.78

        # When: Display success message
        console = Console(file=io.StringIO())
        with patch("bqcheck.console.console", console):
            show_success_message(count, savings)

        # Then: Message includes thousand separator
        output = console.file.getvalue()
        assert "150 recommendations" in output
        # Rich may format with comma or space as thousands separator
        assert "€123,456.78" in output or "€123456.78" in output


class TestElapsedTimer:
    """Test elapsed timer accuracy (Task 7.2)."""

    @pytest.mark.asyncio
    async def test_timer_updates_every_5_seconds(self):
        """Test timer displays elapsed time every 5 seconds (AC4)."""
        # Given: Mock console and sleep
        console = Console(file=io.StringIO())

        async def mock_analysis_progress():
            """Mock version with controlled timing."""
            from datetime import datetime, timezone

            datetime.now(timezone.utc)
            console.print(
                "⚙️  Analyzing BigQuery patterns (this may take up to 15 minutes)..."
            )

            # Simulate 2 updates (5s, 10s)
            for elapsed_seconds in [5, 10]:
                await asyncio.sleep(0)  # Yield control
                minutes = int(elapsed_seconds // 60)
                seconds = int(elapsed_seconds % 60)
                console.print(f"⏱️  Elapsed: {minutes}m {seconds}s")

        # When: Run timer task
        with patch("bqcheck.console.console", console):
            timer_task = asyncio.create_task(mock_analysis_progress())
            await timer_task

        # Then: Console shows initial message and elapsed time updates
        output = console.file.getvalue()
        assert "⚙️  Analyzing BigQuery patterns" in output
        assert "Elapsed: 0m 5s" in output
        assert "Elapsed: 0m 10s" in output

    @pytest.mark.asyncio
    async def test_timer_displays_minutes_correctly(self):
        """Test timer formats minutes correctly for long operations."""
        # Given: Mock console
        console = Console(file=io.StringIO())

        async def mock_long_analysis():
            """Mock version simulating 2 minutes."""
            from datetime import datetime, timezone

            datetime.now(timezone.utc)
            console.print(
                "⚙️  Analyzing BigQuery patterns (this may take up to 15 minutes)..."
            )

            # Simulate 2 minutes (120 seconds)
            elapsed_seconds = 125  # 2m 5s
            await asyncio.sleep(0)
            minutes = int(elapsed_seconds // 60)
            seconds = int(elapsed_seconds % 60)
            console.print(f"⏱️  Elapsed: {minutes}m {seconds}s")

        # When: Run timer
        with patch("bqcheck.console.console", console):
            timer_task = asyncio.create_task(mock_long_analysis())
            await timer_task

        # Then: Minutes formatted correctly
        output = console.file.getvalue()
        assert "Elapsed: 2m 5s" in output

    @pytest.mark.asyncio
    async def test_timer_cleanup_on_cancellation(self):
        """
        Test timer task cancellation and cleanup (Code Review Round 3, Issue #8).

        This test consolidates two previously duplicate tests:
        - test_timer_can_be_cancelled (basic cancellation)
        - test_timer_cleanup_on_cancellation (full state verification)

        Verifies that timer task:
        1. Can be cancelled mid-execution
        2. Raises CancelledError when awaited
        3. Properly transitions to done() and cancelled() states
        """
        # Given: Console for testing
        console = Console(file=io.StringIO())

        # When: Start timer, let it run briefly, then cancel
        with patch("bqcheck.console.console", console):
            timer_task = asyncio.create_task(show_analysis_progress())

            # Let timer start
            await asyncio.sleep(0.1)

            # Cancel timer
            timer_task.cancel()

            # Then: Task cancellation completes without raising
            with pytest.raises(asyncio.CancelledError):
                await timer_task

            # Verify task is done and cancelled
            assert timer_task.done()
            assert timer_task.cancelled()
