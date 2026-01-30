"""
Unit tests for license status and validate commands (Story 3.5).

Tests cover:
- AC3: License status shows depletion
- AC4: Validate command works with depleted pool
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bqaudit.cli import app

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
        lambda: creds_path
    )
    return creds_path


class TestLicenseStatusDepletion:
    """Test license status command with depletion."""

    def test_license_status_shows_depletion(
        self, tmp_path, mock_credentials, mock_creds_path
    ):
        """AC3 (Story 3.5): License status highlights depletion."""
        # Arrange: Set balance to 0
        mock_credentials["token_pool_balance"] = 0
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Act
        result = runner.invoke(app, ["license", "status"])

        # Assert
        assert result.exit_code == 0
        assert "0 scans remaining (DEPLETED)" in result.stdout
        assert "bqaudit.com/pricing" in result.stdout

    def test_license_status_normal_when_balance_positive(
        self, tmp_path, mock_credentials, mock_creds_path
    ):
        """License status normal display when balance > 0."""
        # Arrange: Balance = 10
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Act
        result = runner.invoke(app, ["license", "status"])

        # Assert
        assert result.exit_code == 0
        assert "10 scans remaining" in result.stdout
        assert "DEPLETED" not in result.stdout


class TestValidateCommandWithDepletion:
    """Test validate command works even when token pool depleted."""

    def test_validate_doesnt_check_token_balance(
        self, tmp_path, mock_credentials, mock_creds_path
    ):
        """
        AC4 (Story 3.5): Validate command doesn't check token balance.

        This test verifies that validate command doesn't fail with exit code 4
        when balance = 0, unlike scan command which does check balance.

        Full integration test for validate is in test_token_depletion_flow.py.
        """
        # Arrange: Set balance to 0
        mock_credentials["token_pool_balance"] = 0
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Act
        result = runner.invoke(app, ["validate", "--project", "test-project"])

        # Assert: validate doesn't exit with code 4 due to token balance check
        # It may fail for other reasons (BigQuery API not enabled, etc.)
        # but it should NOT fail specifically because of token depletion
        if result.exit_code == 4:
            assert "Token pool depleted" not in result.stdout, (
                "Validate command should not check token balance (AC4)"
            )

        # Verify balance unchanged (validate doesn't consume tokens)
        updated_creds = json.loads(mock_creds_path.read_text())
        assert updated_creds["token_pool_balance"] == 0
