"""
Unit tests for scan CLI command (Story 3.4).

Tests cover:
- AC1: Execute scan with token management
- AC4: Tokens never logged
- AC5: Master key not transmitted during scan
- AC7: Simulation notice displayed
"""

import json
import logging
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bqaudit.cli import app
from bqaudit.constants import ExitCode

runner = CliRunner()


@pytest.fixture
def mock_credentials(tmp_path: Path) -> dict:
    """Create mock credentials for testing."""
    credentials = {
        "master_key": "VALID-TEST-KEY-123",
        "ephemeral_token": "test-token-xyz-789",
        "token_pool_balance": 10,
        "server_url": "https://api.bqaudit.com",
        "activated_at": "2024-01-01T00:00:00+00:00",
    }

    # Create credentials file
    creds_dir = tmp_path / ".bqaudit"
    creds_dir.mkdir(parents=True, exist_ok=True)
    creds_file = creds_dir / "credentials.json"
    creds_file.write_text(json.dumps(credentials))
    creds_file.chmod(0o600)

    return credentials


@pytest.fixture
def mock_creds_path(tmp_path: Path, monkeypatch):
    """Mock CredentialStore path to use tmp_path."""
    creds_path = tmp_path / ".bqaudit" / "credentials.json"

    # Mock the _get_credentials_path method to return our test path
    monkeypatch.setattr(
        "bqaudit.license.storage.CredentialStore._get_credentials_path",
        lambda: creds_path,
    )
    return creds_path


@pytest.fixture
def mock_bq_validation(monkeypatch):
    """Mock BigQuery multi-project validation to avoid real API calls."""
    # Mock the validation function
    monkeypatch.setattr(
        "bqaudit.scanner.bigquery_client.validate_multi_project_permissions",
        lambda storage_project, query_project=None: None,
    )
    # Force simulated scan mode for unit tests
    monkeypatch.setenv("BQAUDIT_REAL_SCAN", "false")


class TestScanCommand:
    """Test scan command with token management."""

    def test_scan_without_credentials_fails(self, tmp_path, mock_creds_path):
        """AC1: Scan fails if no credentials exist."""
        result = runner.invoke(app, ["scan", "--project", "test-project"])

        assert result.exit_code == ExitCode.FILE_ERROR
        assert "No active license found" in result.stdout
        assert "bqaudit license activate" in result.stdout

    def test_scan_with_credentials_executes_simulated_scan(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """AC1: Scan loads credentials and executes simulated scan."""
        # Create credentials file
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        result = runner.invoke(app, ["scan", "--project", "test-project"])

        # Should succeed
        assert result.exit_code == 0

        # Should show simulation messages (AC7)
        assert "[SIMULATED]" in result.stdout
        assert "test-project" in result.stdout

    def test_scan_displays_simulation_notice(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """AC7: Clear simulation notice displayed to user."""
        # Create credentials file
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        result = runner.invoke(app, ["scan", "--project", "my-gcp-project"])

        # AC7: Simulation notice
        assert "[SIMULATED]" in result.stdout
        assert "Scanning BigQuery project" in result.stdout
        assert "my-gcp-project" in result.stdout

        # AC7: Guidance about Epic 3/4
        assert "Epic 3" in result.stdout or "simulated scan" in result.stdout.lower()
        assert "Epic 4" in result.stdout or "future" in result.stdout.lower()

    def test_scan_success_displays_balance(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """AC1: Scan success displays token pool balance."""
        # Create credentials file
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        result = runner.invoke(app, ["scan", "--project", "test-project"])

        assert result.exit_code == 0
        assert "Scan completed successfully" in result.stdout
        assert "scans remaining" in result.stdout

    def test_scan_tokens_never_logged(
        self, tmp_path, mock_credentials, mock_creds_path, caplog, mock_bq_validation
    ):
        """AC4: Ephemeral tokens NEVER appear in logs."""
        # Create credentials file
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Capture ALL log levels
        with caplog.at_level(logging.DEBUG):
            runner.invoke(app, ["scan", "--project", "test-project"])

        # AC4: Token NEVER in logs
        ephemeral_token = mock_credentials["ephemeral_token"]
        for record in caplog.records:
            assert ephemeral_token not in record.message, (
                f"Token found in log: {record.message}"
            )
            # Also check that renewed tokens don't appear
            assert "test-token" not in record.message or "***" in record.message

    def test_scan_master_key_never_logged(
        self, tmp_path, mock_credentials, mock_creds_path, caplog, mock_bq_validation
    ):
        """AC5: Master key NEVER appears in logs."""
        # Create credentials file
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Capture ALL log levels
        with caplog.at_level(logging.DEBUG):
            runner.invoke(app, ["scan", "--project", "test-project"])

        # AC5: Master key NEVER in logs
        master_key = mock_credentials["master_key"]
        for record in caplog.records:
            assert master_key not in record.message, (
                f"Master key found in log: {record.message}"
            )

    def test_scan_decrements_token_balance(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """AC1: Successful scan decrements token pool balance by 1."""
        # Create credentials file with balance=10
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Run scan
        result = runner.invoke(app, ["scan", "--project", "test-project"])
        assert result.exit_code == 0

        # Load updated credentials
        updated_creds = json.loads(mock_creds_path.read_text())

        # Balance should be decremented by 1
        assert updated_creds["token_pool_balance"] == 9

    def test_scan_renews_token_after_success(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """AC3: Token renewed after successful scan."""
        # Create credentials file
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        original_token = mock_credentials["ephemeral_token"]
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Run scan
        result = runner.invoke(app, ["scan", "--project", "test-project"])
        assert result.exit_code == 0

        # Load updated credentials
        updated_creds = json.loads(mock_creds_path.read_text())

        # Token should be renewed (different from original)
        assert updated_creds["ephemeral_token"] != original_token
        assert updated_creds["ephemeral_token"].startswith("mock-renewed-token-")

    def test_scan_prevented_when_balance_zero(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """AC1 (Story 3.5): Scan prevented with balance = 0, exit code 4."""
        # Arrange: Set balance to 0
        mock_credentials["token_pool_balance"] = 0
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Act
        result = runner.invoke(app, ["scan", "--project", "test-project"])

        # Assert
        assert result.exit_code == 4  # Specific depletion exit code
        assert "Token pool depleted" in result.stdout
        assert "0 scans remaining" in result.stdout
        assert "bqaudit.com/pricing" in result.stdout
        # Verify scan NOT executed
        assert "[SIMULATED]" not in result.stdout

    def test_warning_displayed_for_last_token(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """AC2 (Story 3.5): Warning shown when using last token."""
        # Arrange: Set balance to 1
        mock_credentials["token_pool_balance"] = 1
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Act
        result = runner.invoke(app, ["scan", "--project", "test-project"])

        # Assert
        assert result.exit_code == 0  # Scan succeeded
        assert "This was your last token" in result.stdout
        assert "Purchase more tokens" in result.stdout
        assert "bqaudit.com/pricing" in result.stdout

        # Verify balance now 0
        updated_creds = json.loads(mock_creds_path.read_text())
        assert updated_creds["token_pool_balance"] == 0

    def test_scan_handles_negative_balance_edge_case(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """
        Edge case: Scan handles corrupted negative balance gracefully.

        While Pydantic validates ge=0, this tests defensive behavior
        if balance somehow becomes negative (data corruption, manual edit).
        """
        # Arrange: Create credentials with negative balance (bypass Pydantic)
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        # Write directly to bypass Pydantic validation
        corrupted_creds = {
            "master_key": "VALID-TEST-KEY-123",
            "ephemeral_token": "test-token-xyz-789",
            "token_pool_balance": -5,  # Invalid negative balance
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2024-01-01T00:00:00+00:00",
        }
        mock_creds_path.write_text(json.dumps(corrupted_creds))
        mock_creds_path.chmod(0o600)

        # Act
        result = runner.invoke(app, ["scan", "--project", "test-project"])

        # Assert: Should fail gracefully (either Pydantic validation error
        # or scan prevention)
        # Exit code should NOT be 0 (should not allow scan with negative balance)
        assert result.exit_code != 0
        # Should either show validation error, invalid data message,
        # or token depletion message
        assert (
            "validation error" in result.stdout.lower()
            or "invalid data" in result.stdout.lower()
            or "depleted" in result.stdout.lower()
        )


class TestScanMultiProjectSupport:
    """Test multi-project scanning with --query-project flag."""

    def test_scan_accepts_query_project_parameter(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """Test that --query-project parameter is accepted."""
        # Create credentials file
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        result = runner.invoke(
            app,
            [
                "scan",
                "--project",
                "storage-project",
                "--query-project",
                "query-project",
            ],
        )

        # Should succeed (simulated mode doesn't validate actual projects)
        assert result.exit_code == 0
        assert "storage-project" in result.stdout

    def test_scan_with_query_project_short_flag(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """Test that -q short flag works for --query-project."""
        # Create credentials file
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        result = runner.invoke(
            app, ["scan", "-p", "storage-project", "-q", "query-project"]
        )

        # Should succeed
        assert result.exit_code == 0

    def test_scan_works_without_query_project(
        self, tmp_path, mock_credentials, mock_creds_path, mock_bq_validation
    ):
        """Test that scan works without --query-project (single-project mode)."""
        # Create credentials file
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        result = runner.invoke(app, ["scan", "--project", "my-project"])

        # Should succeed in single-project mode
        assert result.exit_code == 0
        assert "my-project" in result.stdout
