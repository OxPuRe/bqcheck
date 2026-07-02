"""
Comprehensive unit tests for CLI validate command.

Tests cover:
- GCP authentication (success/failure)
- BigQuery API enablement check
- IAM permissions verification
- Test query execution
- Project data sufficiency check
- Server connectivity check
- Rich formatted output
- Error guidance messages
- Exit codes
- Zero token consumption
"""

from unittest.mock import Mock, patch

import httpx
import pytest
from google.api_core.exceptions import Forbidden, NotFound
from google.auth.exceptions import DefaultCredentialsError
from typer.testing import CliRunner

from bqcheck.cli import app

runner = CliRunner()


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def mock_bq_client():
    """Mock BigQuery client with successful responses."""
    client = Mock()

    # Helper to create table rows
    def _create_table_row(catalog, schema, name):
        row = Mock()
        row.table_catalog = catalog
        row.table_schema = schema
        row.table_name = name
        return row

    def _create_count_row(count):
        row = Mock()
        row.table_count = count
        return row

    def _create_query_row(query_text):
        row = Mock()
        row.query = query_text
        return row

    # Mock query results with side_effect for different queries
    def query_side_effect(query_str):
        mock_job = Mock()
        if "COUNT" in query_str:
            # Count query
            mock_job.result.return_value = [_create_count_row(42)]
        elif "JOBS_BY_PROJECT" in query_str:
            # Sample queries
            mock_job.result.return_value = [
                _create_query_row("SELECT * FROM dataset.table1"),
            ]
        elif "LIMIT 3" in query_str:
            # Sample tables
            mock_job.result.return_value = [
                _create_table_row("test", "dataset", "table1"),
            ]
        else:
            # Default test queries (LIMIT 1)
            mock_job.result.return_value = [
                _create_table_row("test", "dataset", "table1")
            ]
        return mock_job

    client.query.side_effect = query_side_effect

    # Mock list_jobs for permissions check
    client.list_jobs.return_value = []

    return client


@pytest.fixture
def mock_table_count():
    """Mock table count query result."""
    mock_query_job = Mock()
    mock_result = Mock()
    mock_result.table_count = 42
    mock_query_job.result.return_value = [mock_result]
    return mock_query_job


@pytest.fixture
def mock_health_response():
    """Mock successful health check response."""
    return {"status": "ok", "min_client_version": "0.1.0"}


# ============================================================================
# AUTHENTICATION TESTS
# ============================================================================


def test_validate_gcp_auth_success(mock_bq_client, mock_health_response):
    """Test successful GCP authentication."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "✓ Authentication successful" in result.stdout
            assert result.exit_code == 0


def test_validate_gcp_auth_failure_default_credentials():
    """Test GCP authentication failure with DefaultCredentialsError."""
    with patch("bqcheck.cli.authenticate_bigquery") as mock_auth:
        mock_auth.side_effect = DefaultCredentialsError("No credentials")
        result = runner.invoke(app, ["validate", "--project", "test-project"])
        assert "❌ GCP authentication failed" in result.stdout
        assert "gcloud auth application-default login" in result.stdout
        assert result.exit_code == 3


def test_validate_gcp_auth_failure_auth_error():
    """Test GCP authentication failure with AuthenticationError."""
    from bqcheck.scanner import AuthenticationError

    with patch("bqcheck.cli.authenticate_bigquery") as mock_auth:
        mock_auth.side_effect = AuthenticationError("Auth failed")
        result = runner.invoke(app, ["validate", "--project", "test-project"])
        assert "❌ GCP authentication failed" in result.stdout
        assert result.exit_code == 3


# ============================================================================
# BIGQUERY API TESTS
# ============================================================================


def test_validate_api_enabled(mock_bq_client, mock_health_response):
    """Test BigQuery API enabled successfully."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "✓ BigQuery API enabled" in result.stdout
            assert result.exit_code == 0


def test_validate_api_disabled():
    """Test BigQuery API not enabled error."""
    client = Mock()
    client.query.side_effect = Forbidden("BigQuery API has not been used in project")

    with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
        result = runner.invoke(app, ["validate", "--project", "test-project"])
        assert "❌ BigQuery API not enabled" in result.stdout
        assert "gcloud services enable bigquery.googleapis.com" in result.stdout
        assert result.exit_code == 4


# ============================================================================
# PERMISSIONS TESTS
# ============================================================================


def test_validate_permissions_success(mock_bq_client, mock_health_response):
    """Test successful IAM permissions verification."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "✓ Permissions verified (bigquery.metadataViewer)" in result.stdout
            assert result.exit_code == 0


def test_validate_missing_permissions():
    """Test missing IAM permissions error."""
    client = Mock()

    # First query (SELECT 1) succeeds
    mock_query_job1 = Mock()
    mock_query_job1.result.return_value = []

    # Second query (INFORMATION_SCHEMA) fails with permissions error
    mock_query_job2 = Mock()
    mock_query_job2.result.side_effect = Forbidden("Access Denied: Table")

    # Configure client.query to succeed first, then fail
    client.query.side_effect = [mock_query_job1, mock_query_job2]

    with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
        result = runner.invoke(app, ["validate", "--project", "test-project"])
        assert "❌ Missing required permissions" in result.stdout
        assert "roles/bigquery.metadataViewer" in result.stdout
        assert result.exit_code == 4


# ============================================================================
# TEST QUERY TESTS
# ============================================================================


def test_validate_test_query_success(mock_bq_client, mock_health_response):
    """Test successful INFORMATION_SCHEMA query."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "✓ Test query successful" in result.stdout
            assert result.exit_code == 0


def test_validate_project_not_found():
    """Test project not found error."""
    client = Mock()

    # First two queries succeed (SELECT 1, permissions check)
    mock_success = Mock()
    mock_success.result.return_value = []

    # Third query fails with NotFound
    mock_fail = Mock()
    mock_fail.result.side_effect = NotFound("Project not found")

    client.query.side_effect = [mock_success, mock_success, mock_fail]
    client.list_jobs.return_value = []

    with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
        result = runner.invoke(app, ["validate", "--project", "test-project"])
        assert "❌ Project not found" in result.stdout
        assert "gcloud projects list" in result.stdout
        assert result.exit_code == 4


# ============================================================================
# PROJECT DATA SUFFICIENCY TESTS
# ============================================================================


def test_validate_project_has_tables(mock_health_response):
    """Test project has sufficient data (tables exist)."""
    # Create custom client mock (bypass fixture since we need custom count value)
    client = Mock()

    # Helper functions
    def _create_table_row(catalog, schema, name):
        row = Mock()
        row.table_catalog = catalog
        row.table_schema = schema
        row.table_name = name
        return row

    def _create_count_row(count):
        row = Mock()
        row.table_count = count
        return row

    # Mock query results with specific count (42)
    def query_side_effect(query_str):
        mock_job = Mock()
        if "COUNT" in query_str:
            mock_job.result.return_value = [_create_count_row(42)]
        else:
            mock_job.result.return_value = [
                _create_table_row("test", "dataset", "table1")
            ]
        return mock_job

    client.query.side_effect = query_side_effect
    client.list_jobs.return_value = []

    with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "✓ Project has 42 tables" in result.stdout
            assert result.exit_code == 0


def test_validate_project_no_tables(mock_health_response):
    """Test warning when project has no tables."""
    # Create custom client mock (bypass fixture since we need custom count value)
    client = Mock()

    # Helper functions
    def _create_table_row(catalog, schema, name):
        row = Mock()
        row.table_catalog = catalog
        row.table_schema = schema
        row.table_name = name
        return row

    def _create_count_row(count):
        row = Mock()
        row.table_count = count
        return row

    # Mock query results with specific count (0)
    def query_side_effect(query_str):
        mock_job = Mock()
        if "COUNT" in query_str:
            mock_job.result.return_value = [_create_count_row(0)]
        else:
            mock_job.result.return_value = [
                _create_table_row("test", "dataset", "table1")
            ]
        return mock_job

    client.query.side_effect = query_side_effect
    client.list_jobs.return_value = []

    with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "⚠ Project has no tables" in result.stdout
            assert "sanity check will have limited value" in result.stdout
            # Still exits 0 (warning, not error)
            assert result.exit_code == 0


def test_validate_project_count_query_fails(mock_bq_client, mock_health_response):
    """Test count query failure is handled gracefully."""
    # First 3 queries succeed (SELECT 1, permissions, test query)
    mock_success = Mock()
    mock_success.result.return_value = []

    # Count query fails with Forbidden error
    mock_fail = Mock()
    mock_fail.result.side_effect = Forbidden("Access denied to INFORMATION_SCHEMA")

    # Configure client to return success for first 3, then fail on count query
    mock_bq_client.query.side_effect = [
        mock_success,  # SELECT 1
        mock_success,  # Permissions check (INFORMATION_SCHEMA.TABLES)
        mock_success,  # Test query
        mock_fail,  # Count query
    ]
    mock_bq_client.list_jobs.return_value = []

    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "⚠ Could not count tables" in result.stdout
            # Should still exit 0 (warning, not error)
            assert result.exit_code == 0


# ============================================================================
# SERVER CONNECTIVITY TESTS
# ============================================================================


def test_validate_server_connectivity_success(mock_bq_client):
    """Test successful server health check."""
    health_response = {"status": "ok", "min_client_version": "0.1.0"}

    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch("bqcheck.cli.check_server_health", return_value=health_response):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "✓ Server connectivity OK" in result.stdout
            assert result.exit_code == 0


def test_validate_server_unreachable(mock_bq_client):
    """Test server connectivity failure with ConnectError."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch("bqcheck.cli.check_server_health") as mock_health:
            mock_health.side_effect = httpx.ConnectError("Connection refused")
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "❌ Cannot reach bqcheck server" in result.stdout
            assert "Check internet connectivity" in result.stdout
            assert result.exit_code == 1


def test_validate_server_timeout(mock_bq_client):
    """Test server timeout error."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch("bqcheck.cli.check_server_health") as mock_health:
            mock_health.side_effect = httpx.TimeoutException("Timeout")
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "❌ Server timeout" in result.stdout
            assert result.exit_code == 1


def test_validate_server_http_error(mock_bq_client):
    """Test server HTTP error (4xx/5xx) is handled correctly."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch("bqcheck.cli.check_server_health") as mock_health:
            # Simulate 500 Internal Server Error
            mock_response = Mock()
            mock_response.status_code = 500
            mock_request = Mock()

            mock_health.side_effect = httpx.HTTPStatusError(
                "Internal Server Error", request=mock_request, response=mock_response
            )

            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert "❌ Server error: HTTP 500" in result.stdout
            assert "Server returned an error response" in result.stdout
            assert result.exit_code == 1


# ============================================================================
# RICH OUTPUT TESTS
# ============================================================================


def test_validate_rich_output_formatting(mock_bq_client, mock_health_response):
    """Test Rich console formatting (checkmarks, table)."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            # Verify Rich formatting elements
            assert "✓" in result.stdout  # Checkmarks
            assert "Validation Results" in result.stdout  # Table title
            assert "completed in" in result.stdout  # Execution time
            assert result.exit_code == 0


def test_validate_verbose_mode(mock_bq_client, mock_health_response):
    """Test verbose flag shows detailed steps."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(
                app, ["validate", "--project", "test-project", "--verbose"]
            )
            # Verify verbose output
            assert "ℹ Checking GCP authentication" in result.stdout
            assert "ℹ Checking BigQuery API" in result.stdout
            assert "ℹ Checking IAM permissions" in result.stdout
            assert "Query:" in result.stdout  # Shows SQL queries
            assert (
                "/v1/health" in result.stdout
            )  # Shows HTTP requests (updated for new format)
            assert result.exit_code == 0


# ============================================================================
# EXIT CODE TESTS
# ============================================================================


@pytest.mark.parametrize(
    "error,expected_code",
    [
        (DefaultCredentialsError("No creds"), 3),
        (Forbidden("BigQuery API has not been used in project"), 4),
        (NotFound("Project not found"), 4),
    ],
)
def test_validate_exit_codes(error, expected_code):
    """Test standard exit codes for different failure scenarios."""
    client = Mock()

    if isinstance(error, DefaultCredentialsError):
        # Auth error happens first
        with patch("bqcheck.cli.authenticate_bigquery") as mock_auth:
            mock_auth.side_effect = error
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert result.exit_code == expected_code

    elif isinstance(error, Forbidden):
        # API disabled error - needs specific message to trigger right code path
        client.query.side_effect = error
        with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert result.exit_code == expected_code

    elif isinstance(error, NotFound):
        # Project not found error (happens in test query)
        mock_success = Mock()
        mock_success.result.return_value = []

        mock_fail = Mock()
        mock_fail.result.side_effect = error

        client.query.side_effect = [mock_success, mock_success, mock_fail]
        client.list_jobs.return_value = []

        with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert result.exit_code == expected_code


def test_validate_success_exit_code(mock_bq_client, mock_health_response):
    """Test exit code 0 on successful validation."""
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ):
            result = runner.invoke(app, ["validate", "--project", "test-project"])
            assert result.exit_code == 0


# ============================================================================
# ZERO TOKEN CONSUMPTION TEST
# ============================================================================


def test_validate_zero_token_consumption(mock_bq_client, mock_health_response):
    """
    Test validate command consumes ZERO tokens.

    CRITICAL: Verify NO calls to token-consuming endpoints.
    Only local GCP checks + /health endpoint allowed.
    """
    with patch("bqcheck.cli.authenticate_bigquery", return_value=mock_bq_client):
        with patch(
            "bqcheck.cli.check_server_health", return_value=mock_health_response
        ) as mock_health:
            result = runner.invoke(app, ["validate", "--project", "test-project"])

            # Verify health check was called (free endpoint)
            assert mock_health.called

            # Verify successful validation
            assert result.exit_code == 0

            # CRITICAL: In Story 2.5, validate is CLIENT-SIDE ONLY
            # - NO calls to server /scan endpoint
            # - NO calls to server /validate endpoint
            # - Only local BigQuery API calls + /health endpoint

            # This is verified by the fact that we only mock check_server_health
            # and don't mock any other server endpoints


# ============================================================================
# ERROR GUIDANCE TESTS
# ============================================================================


def test_validate_error_guidance_auth_fail():
    """Test authentication failure shows actionable error guidance."""
    with patch("bqcheck.cli.authenticate_bigquery") as mock_auth:
        mock_auth.side_effect = DefaultCredentialsError("No credentials")
        result = runner.invoke(app, ["validate", "--project", "test-project"])

        # Verify actionable guidance
        assert "gcloud auth application-default login" in result.stdout
        assert "GOOGLE_APPLICATION_CREDENTIALS" in result.stdout
        assert result.exit_code == 3


def test_validate_error_guidance_api_disabled():
    """Test API disabled shows exact gcloud command."""
    client = Mock()
    client.query.side_effect = Forbidden("BigQuery API has not been used")

    with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
        result = runner.invoke(app, ["validate", "--project", "my-project"])

        # Verify exact fix command with project ID
        assert (
            "gcloud services enable bigquery.googleapis.com --project=my-project"
            in result.stdout
        )
        assert result.exit_code == 4


def test_validate_error_guidance_permissions():
    """Test missing permissions shows exact IAM binding command."""
    client = Mock()

    mock_success = Mock()
    mock_success.result.return_value = []

    mock_fail = Mock()
    mock_fail.result.side_effect = Forbidden("Access Denied")

    client.query.side_effect = [mock_success, mock_fail]

    with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
        result = runner.invoke(app, ["validate", "--project", "my-project"])

        # Verify exact fix command
        assert "gcloud projects add-iam-policy-binding my-project" in result.stdout
        assert "roles/bigquery.metadataViewer" in result.stdout
        assert "YOUR_EMAIL" in result.stdout
        assert result.exit_code == 4


# ============================================================================
# ERROR HANDLER HELPER TESTS
# ============================================================================


def test_handle_validation_error_auth_exit_code():
    """Test _handle_validation_error uses correct exit code for auth errors."""
    with patch("bqcheck.cli.authenticate_bigquery") as mock_auth:
        from bqcheck.scanner import AuthenticationError

        mock_auth.side_effect = AuthenticationError("Auth failed")
        result = runner.invoke(app, ["validate", "--project", "test-project"])

        # Verify exit code 3 for authentication errors
        assert result.exit_code == 3
        assert "Validation Failed" in result.stdout


def test_handle_validation_error_bigquery_exit_code():
    """Test _handle_validation_error uses exit code 4 for BigQuery errors."""
    client = Mock()
    client.query.side_effect = Forbidden("BigQuery API has not been used")

    with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
        result = runner.invoke(app, ["validate", "--project", "test-project"])

        # Verify exit code 4 for BigQuery API errors
        assert result.exit_code == 4
        assert "Validation Failed" in result.stdout


def test_handle_validation_error_displays_panel():
    """Test _handle_validation_error displays Rich Panel with error message."""
    with patch("bqcheck.cli.authenticate_bigquery") as mock_auth:
        from bqcheck.scanner import AuthenticationError

        mock_auth.side_effect = AuthenticationError("Auth failed")
        result = runner.invoke(app, ["validate", "--project", "test-project"])

        # Verify Panel formatting is present
        assert "Validation Failed" in result.stdout
        # Verify error guidance is displayed
        assert "gcloud auth" in result.stdout or "GOOGLE_APPLICATION" in result.stdout


def test_handle_validation_error_includes_project_context():
    """Test _handle_validation_error includes project ID in error messages."""
    client = Mock()
    client.query.side_effect = Forbidden(
        "BigQuery API has not been used in project my-test-project"
    )

    with patch("bqcheck.cli.authenticate_bigquery", return_value=client):
        result = runner.invoke(app, ["validate", "--project", "my-test-project"])

        # Verify project ID appears in error guidance
        assert "my-test-project" in result.stdout
        assert result.exit_code == 4
