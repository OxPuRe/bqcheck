"""Unit tests for error message formatters (Story 5.3, Task 7.3)."""

import io

from rich.console import Console

from bqcheck.error_handlers import (
    EXIT_AUTH_ERROR,
    EXIT_FILE_ERROR,
    EXIT_NETWORK_ERROR,
    handle_bigquery_forbidden_error,
    handle_bigquery_not_found_error,
    handle_bigquery_permission_error,
    handle_network_error,
    handle_timeout_error,
)


class TestBigQueryErrorMessages:
    """Test BigQuery error message generation (AC6)."""

    def test_permission_error_message_formatting(self):
        """Test BigQuery permission error message includes gcloud command (AC6)."""
        # Given: PermissionDenied error context
        project_id = "my-project"
        email = "user@example.com"
        console = Console(file=io.StringIO())

        # When: Handle permission error
        exit_code = handle_bigquery_permission_error(console, project_id, email)

        # Then: Exit code is AUTH_ERROR
        assert exit_code == EXIT_AUTH_ERROR

        # Then: Message includes gcloud command with placeholders filled
        output = console.file.getvalue()
        assert "❌ Error: Insufficient BigQuery permissions" in output
        assert "gcloud projects add-iam-policy-binding my-project" in output
        assert "--member=user:user@example.com" in output
        assert "--role=roles/bigquery.metadataViewer" in output

    def test_not_found_error_message(self):
        """Test BigQuery project not found error message."""
        # Given: Project ID
        project_id = "nonexistent-project"
        console = Console(file=io.StringIO())

        # When: Handle not found error
        exit_code = handle_bigquery_not_found_error(console, project_id)

        # Then: Exit code is FILE_ERROR
        assert exit_code == EXIT_FILE_ERROR

        # Then: Message includes project ID
        output = console.file.getvalue()
        assert "❌ Error: Project 'nonexistent-project' not found" in output
        assert "Verify the project ID is correct" in output

    def test_forbidden_error_message(self):
        """Test BigQuery access forbidden error message."""
        # Given: Project ID
        project_id = "forbidden-project"
        console = Console(file=io.StringIO())

        # When: Handle forbidden error
        exit_code = handle_bigquery_forbidden_error(console, project_id)

        # Then: Exit code is AUTH_ERROR
        assert exit_code == EXIT_AUTH_ERROR

        # Then: Message includes project ID
        output = console.file.getvalue()
        assert "❌ Error: Access denied to project 'forbidden-project'" in output
        assert "Ensure you have access to this project" in output


class TestNetworkErrorMessages:
    """Test network error message generation (AC7)."""

    def test_network_error_message_formatting(self):
        """Test network error message includes retry guidance (AC7)."""
        # Given: Console for testing
        console = Console(file=io.StringIO())

        # When: Handle network error
        exit_code = handle_network_error(console)

        # Then: Exit code is NETWORK_ERROR
        assert exit_code == EXIT_NETWORK_ERROR

        # Then: Message includes troubleshooting guidance
        output = console.file.getvalue()
        assert "❌ Error: Unable to reach analysis server" in output
        assert "Check your internet connection" in output
        assert "Retry the scan when connection is restored" in output
        assert "Your token was not consumed" in output

    def test_network_error_preserves_token(self):
        """Test network error message indicates token preservation."""
        # Given: Console for testing
        console = Console(file=io.StringIO())

        # When: Handle network error
        exit_code = handle_network_error(console)

        # Then: Returns correct exit code
        assert exit_code == EXIT_NETWORK_ERROR

        # Then: Message indicates token not consumed
        output = console.file.getvalue()
        assert "Your token was not consumed" in output


class TestTimeoutErrorMessages:
    """Test timeout error message generation (AC8)."""

    def test_timeout_error_message_formatting(self):
        """Test timeout error message includes large project guidance (AC8)."""
        # Given: Console for testing
        console = Console(file=io.StringIO())

        # When: Handle timeout error
        exit_code = handle_timeout_error(console)

        # Then: Exit code is NETWORK_ERROR
        assert exit_code == EXIT_NETWORK_ERROR

        # Then: Message includes large project guidance
        output = console.file.getvalue()
        assert "❌ Error: Sanity check timeout (>15 minutes)" in output
        assert "This may indicate a very large" in output
        assert "Contact support if the issue persists" in output
        assert "Your token was not consumed" in output

    def test_timeout_error_preserves_token(self):
        """Test timeout error message indicates token preservation."""
        # Given: Console for testing
        console = Console(file=io.StringIO())

        # When: Handle timeout error
        exit_code = handle_timeout_error(console)

        # Then: Returns correct exit code
        assert exit_code == EXIT_NETWORK_ERROR

        # Then: Message indicates token not consumed
        output = console.file.getvalue()
        assert "Your token was not consumed" in output


class TestExitCodes:
    """Test exit codes are correct (AC6, AC7, AC8)."""

    def test_permission_error_exit_code(self):
        """Test permission error returns AUTH_ERROR code."""
        console = Console(file=io.StringIO())
        exit_code = handle_bigquery_permission_error(
            console, "project", "email@example.com"
        )
        assert exit_code == 3

    def test_not_found_error_exit_code(self):
        """Test not found error returns FILE_ERROR code."""
        console = Console(file=io.StringIO())
        exit_code = handle_bigquery_not_found_error(console, "project")
        assert exit_code == 2

    def test_forbidden_error_exit_code(self):
        """Test forbidden error returns AUTH_ERROR code."""
        console = Console(file=io.StringIO())
        exit_code = handle_bigquery_forbidden_error(console, "project")
        assert exit_code == 3

    def test_network_error_exit_code(self):
        """Test network error returns NETWORK_ERROR code."""
        console = Console(file=io.StringIO())
        exit_code = handle_network_error(console)
        assert exit_code == 1

    def test_timeout_error_exit_code(self):
        """Test timeout error returns NETWORK_ERROR code."""
        console = Console(file=io.StringIO())
        exit_code = handle_timeout_error(console)
        assert exit_code == 1
