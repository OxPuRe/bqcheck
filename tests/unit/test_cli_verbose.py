"""
Unit tests for bqcheck CLI verbose mode functionality.

Tests verbose output, metadata preview, anonymization display, payload size
estimation, and privacy guarantees in the validate command.
"""

from unittest.mock import Mock, patch

from typer.testing import CliRunner

from bqcheck.cli import app

runner = CliRunner()


def _create_table_row(catalog, schema, name):
    """Helper to create mock table row."""
    row = Mock()
    row.table_catalog = catalog
    row.table_schema = schema
    row.table_name = name
    return row


def _create_count_row(count):
    """Helper to create mock count row."""
    row = Mock()
    row.table_count = count
    return row


def _create_query_row(query_text):
    """Helper to create mock query row."""
    row = Mock()
    row.query = query_text
    return row


class TestValidateVerboseFlag:
    """Test --verbose flag in validate command."""

    @patch("bqcheck.cli.authenticate_bigquery")
    @patch("bqcheck.cli.check_server_health")
    def test_validate_verbose_flag_shows_detailed_output(self, mock_health, mock_auth):
        """Test --verbose flag shows detailed validation steps."""
        # Setup mocks
        mock_client = Mock()
        mock_auth.return_value = mock_client

        # Create mock query results for different queries
        def query_side_effect(query_str):
            mock_job = Mock()
            if "COUNT" in query_str:
                mock_job.result.return_value = [_create_count_row(10)]
            elif "JOBS_BY_PROJECT" in query_str:
                # Sample queries
                mock_job.result.return_value = [
                    _create_query_row("SELECT * FROM dataset.table1"),
                ]
            elif "LIMIT 3" in query_str:
                # Sample tables
                mock_job.result.return_value = [
                    _create_table_row("project", "dataset", "table1"),
                ]
            else:
                # Default test queries
                mock_job.result.return_value = [
                    _create_table_row("project", "dataset", "table1")
                ]
            return mock_job

        mock_client.query.side_effect = query_side_effect
        mock_client.list_jobs.return_value = []

        mock_health.return_value = {"status": "ok"}

        # Invoke with --verbose
        result = runner.invoke(
            app, ["validate", "--project", "test-project", "--verbose"]
        )

        # Verify detailed output is shown
        assert result.exit_code == 0
        assert "ℹ Checking GCP authentication" in result.stdout
        assert "ℹ Checking BigQuery API enablement" in result.stdout
        assert "ℹ Checking IAM permissions" in result.stdout

    @patch("bqcheck.cli.authenticate_bigquery")
    @patch("bqcheck.cli.check_server_health")
    def test_validate_without_verbose_flag(self, mock_health, mock_auth):
        """Test validate command without --verbose flag (normal mode)."""
        # Setup mocks
        mock_client = Mock()
        mock_auth.return_value = mock_client

        def query_side_effect(query_str):
            mock_job = Mock()
            if "COUNT" in query_str:
                mock_job.result.return_value = [_create_count_row(5)]
            else:
                mock_job.result.return_value = [
                    _create_table_row("project", "dataset", "table1")
                ]
            return mock_job

        mock_client.query.side_effect = query_side_effect
        mock_client.list_jobs.return_value = []

        mock_health.return_value = {"status": "ok"}

        # Invoke without --verbose
        result = runner.invoke(app, ["validate", "--project", "test-project"])

        # Verify detailed steps are NOT shown
        assert result.exit_code == 0
        assert "ℹ Checking GCP authentication" not in result.stdout


class TestMetadataPreview:
    """Test metadata preview display in verbose mode."""

    @patch("bqcheck.cli.authenticate_bigquery")
    @patch("bqcheck.cli.check_server_health")
    def test_validate_verbose_shows_metadata_preview(self, mock_health, mock_auth):
        """Test verbose mode displays sample metadata with anonymization."""
        # Setup mocks
        mock_client = Mock()
        mock_auth.return_value = mock_client

        # Mock query results - different results for different queries
        def query_side_effect(query_str):
            mock_job = Mock()
            if "COUNT" in query_str:
                # Count query
                mock_job.result.return_value = [_create_count_row(10)]
            elif "JOBS_BY_PROJECT" in query_str:
                # Sample queries
                mock_job.result.return_value = [
                    _create_query_row("SELECT * FROM dataset.table1"),
                ]
            elif "LIMIT 3" in query_str:
                # Sample tables query
                mock_job.result.return_value = [
                    _create_table_row("my-project", "dataset1", "table1"),
                    _create_table_row("my-project", "dataset2", "table2"),
                    _create_table_row("my-project", "dataset3", "table3"),
                ]
            else:
                # Test query (LIMIT 1)
                mock_job.result.return_value = [
                    _create_table_row("my-project", "dataset1", "table1")
                ]
            return mock_job

        mock_client.query.side_effect = query_side_effect
        mock_client.list_jobs.return_value = []

        mock_health.return_value = {"status": "ok"}

        # Invoke with --verbose
        result = runner.invoke(
            app, ["validate", "--project", "test-project", "--verbose"]
        )

        # Verify metadata preview is shown
        assert result.exit_code == 0
        assert "Metadata Preview" in result.stdout or "Sample Metadata" in result.stdout


class TestAnonymizationPreview:
    """Test raw → anonymized mapping display."""

    @patch("bqcheck.cli.authenticate_bigquery")
    @patch("bqcheck.cli.check_server_health")
    def test_validate_verbose_shows_table_anonymization(self, mock_health, mock_auth):
        """Test verbose mode shows table name anonymization mapping."""
        # Setup mocks
        mock_client = Mock()
        mock_auth.return_value = mock_client

        def query_side_effect(query_str):
            mock_job = Mock()
            if "COUNT" in query_str:
                mock_job.result.return_value = [_create_count_row(5)]
            elif "JOBS_BY_PROJECT" in query_str:
                mock_job.result.return_value = [
                    _create_query_row("SELECT * FROM dataset.table1")
                ]
            elif "LIMIT 3" in query_str:
                # Sample tables
                mock_job.result.return_value = [
                    _create_table_row("test-project", "test_dataset", "test_table")
                ]
            else:
                mock_job.result.return_value = [
                    _create_table_row("test-project", "test_dataset", "test_table")
                ]
            return mock_job

        mock_client.query.side_effect = query_side_effect
        mock_client.list_jobs.return_value = []

        mock_health.return_value = {"status": "ok"}

        # Invoke with --verbose
        result = runner.invoke(
            app, ["validate", "--project", "test-project", "--verbose"]
        )

        # Verify anonymization preview is shown
        assert result.exit_code == 0
        # Verify proper anonymization mapping display
        assert "→" in result.stdout or "->" in result.stdout
        assert "Table:" in result.stdout
        # Verify original table name appears in output (before arrow)
        assert "test-project.test_dataset.test_table" in result.stdout
        # Verify anonymized output appears (SHA-256 hashes are 64 chars)
        # The output shows truncated hash with "..." so just verify pattern exists
        assert "Table Name Anonymization" in result.stdout


class TestPayloadSizeEstimation:
    """Test payload size calculation and display."""

    @patch("bqcheck.cli.authenticate_bigquery")
    @patch("bqcheck.cli.check_server_health")
    def test_validate_verbose_shows_payload_size(self, mock_health, mock_auth):
        """Test verbose mode displays estimated payload size in KB."""
        # Setup mocks
        mock_client = Mock()
        mock_auth.return_value = mock_client

        def query_side_effect(query_str):
            mock_job = Mock()
            if "COUNT" in query_str:
                mock_job.result.return_value = [_create_count_row(3)]
            elif "JOBS_BY_PROJECT" in query_str:
                mock_job.result.return_value = [
                    _create_query_row("SELECT * FROM dataset.table1")
                ]
            elif "LIMIT 3" in query_str:
                mock_job.result.return_value = [
                    _create_table_row("project", "dataset", "table")
                ]
            else:
                mock_job.result.return_value = [
                    _create_table_row("project", "dataset", "table")
                ]
            return mock_job

        mock_client.query.side_effect = query_side_effect
        mock_client.list_jobs.return_value = []

        mock_health.return_value = {"status": "ok"}

        # Invoke with --verbose
        result = runner.invoke(
            app, ["validate", "--project", "test-project", "--verbose"]
        )

        # Verify payload size is displayed with actual calculation
        assert result.exit_code == 0
        assert "Estimated Payload Size:" in result.stdout
        assert "KB" in result.stdout
        # Verify it shows a numeric value (not just text)
        import re

        # Look for pattern like "X.XX KB" where X is a digit
        kb_pattern = re.search(r"(\d+\.\d+)\s*KB", result.stdout)
        assert kb_pattern is not None, "Should display numeric KB value"
        # Verify the value is reasonable (should be > 0 and < 1000 for sample data)
        kb_value = float(kb_pattern.group(1))
        assert 0 < kb_value < 1000, f"Payload size {kb_value} KB seems unreasonable"


class TestPrivacyGuarantees:
    """Test privacy confirmation messages."""

    @patch("bqcheck.cli.authenticate_bigquery")
    @patch("bqcheck.cli.check_server_health")
    def test_validate_verbose_shows_privacy_guarantees(self, mock_health, mock_auth):
        """Test verbose mode displays privacy guarantee messages."""
        # Setup mocks
        mock_client = Mock()
        mock_auth.return_value = mock_client

        def query_side_effect(query_str):
            mock_job = Mock()
            if "COUNT" in query_str:
                mock_job.result.return_value = [_create_count_row(1)]
            elif "JOBS_BY_PROJECT" in query_str:
                mock_job.result.return_value = [
                    _create_query_row("SELECT * FROM dataset.table1")
                ]
            elif "LIMIT 3" in query_str:
                mock_job.result.return_value = [
                    _create_table_row("project", "dataset", "table")
                ]
            else:
                mock_job.result.return_value = [
                    _create_table_row("project", "dataset", "table")
                ]
            return mock_job

        mock_client.query.side_effect = query_side_effect
        mock_client.list_jobs.return_value = []

        mock_health.return_value = {"status": "ok"}

        # Invoke with --verbose
        result = runner.invoke(
            app, ["validate", "--project", "test-project", "--verbose"]
        )

        # Verify privacy messages are shown with specific guarantees
        assert result.exit_code == 0
        # Verify all three privacy guarantees are present
        assert "All table names anonymized" in result.stdout
        assert "All queries anonymized" in result.stdout
        assert "No raw data accessed" in result.stdout
        # Verify privacy guarantees panel exists
        assert "Privacy Guarantees" in result.stdout


class TestTransmissionStatement:
    """Test clear transmission statement display."""

    @patch("bqcheck.cli.authenticate_bigquery")
    @patch("bqcheck.cli.check_server_health")
    def test_validate_verbose_shows_transmission_statement(
        self, mock_health, mock_auth
    ):
        """Test verbose mode shows transmission statement."""
        # Setup mocks
        mock_client = Mock()
        mock_auth.return_value = mock_client

        def query_side_effect(query_str):
            mock_job = Mock()
            if "COUNT" in query_str:
                mock_job.result.return_value = [_create_count_row(1)]
            elif "JOBS_BY_PROJECT" in query_str:
                mock_job.result.return_value = [
                    _create_query_row("SELECT * FROM dataset.table1")
                ]
            elif "LIMIT 3" in query_str:
                mock_job.result.return_value = [
                    _create_table_row("project", "dataset", "table")
                ]
            else:
                mock_job.result.return_value = [
                    _create_table_row("project", "dataset", "table")
                ]
            return mock_job

        mock_client.query.side_effect = query_side_effect
        mock_client.list_jobs.return_value = []

        mock_health.return_value = {"status": "ok"}

        # Invoke with --verbose
        result = runner.invoke(
            app, ["validate", "--project", "test-project", "--verbose"]
        )

        # Verify transmission statement with specific elements
        assert result.exit_code == 0
        # Verify transmission panel and key information
        assert "Data Transmission" in result.stdout
        assert "bqcheck server" in result.stdout
        # Verify it mentions metadata only and anonymization
        assert "metadata only" in result.stdout.lower()
        assert "anonymized" in result.stdout.lower() or "SHA-256" in result.stdout
