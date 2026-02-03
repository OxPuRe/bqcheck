"""
Integration test for full token depletion flow (Story 3.5).

Tests the complete lifecycle:
1. Use last token (balance=1) → warning
2. Try to scan again → prevented (exit code 4)
3. Validate still works
"""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from typer.testing import CliRunner

from bqaudit.cli import app
from bqaudit.scanner.encryption import IdentifierEncryptor

runner = CliRunner()


@pytest.fixture
def mock_credentials(tmp_path: Path) -> dict:
    """Create mock credentials for testing."""
    credentials = {
        "master_key": "VALID-TEST-KEY-123",
        "ephemeral_token": "test-token-xyz-789",
        "token_pool_balance": 1,  # Start with 1 token
        "server_url": "https://api.bqaudit.com",
        "activated_at": "2024-01-01T00:00:00+00:00",
        "encryption_key": IdentifierEncryptor.key_to_base64(
            IdentifierEncryptor.generate_key()
        ),
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


def test_full_depletion_flow(tmp_path, mock_credentials, mock_creds_path, monkeypatch):
    """
    Integration: Use last token → warning → prevent next scan → validate works.

    This tests the complete token depletion lifecycle across multiple commands.
    """
    monkeypatch.setenv("BQAUDIT_REAL_MODE", "false")  # Use mock mode

    # Arrange: Create credentials with balance = 1
    mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
    mock_creds_path.write_text(json.dumps(mock_credentials))
    mock_creds_path.chmod(0o600)

    # Mock BigQuery authentication and server communication
    with patch("bqaudit.scanner.authenticate_bigquery") as mock_auth:
        with patch(
            "bqaudit.scanner.metadata_extractor.extract_table_metadata"
        ) as mock_tables:
            with patch(
                "bqaudit.scanner.metadata_extractor.extract_query_metadata"
            ) as mock_queries:
                with patch(
                    "bqaudit.scanner.metadata_extractor.extract_access_patterns"
                ) as mock_access:
                    with patch(
                        "bqaudit.scanner.metadata_extractor.extract_table_schemas"
                    ) as mock_schemas:
                        with patch("httpx.AsyncClient.post") as mock_post:
                            # Setup mocks
                            mock_auth.return_value = Mock()
                            mock_tables.return_value = []
                            mock_queries.return_value = []
                            mock_access.return_value = []
                            mock_schemas.return_value = {}

                            # Mock server response
                            mock_response = Mock()
                            mock_response.status_code = 200
                            mock_response.json.return_value = {
                                "status": "success",
                                "token_pool_balance": 0,  # Will be 0 after using last token
                            }
                            mock_post.return_value = mock_response

                            # Act 1: Use last token
                            result1 = runner.invoke(app, ["scan", "--project", "test-project"])

                            # Assert 1: Scan succeeded with warning
                            assert result1.exit_code == 0
                            assert "This was your last token" in result1.stdout
                            assert "Purchase more tokens" in result1.stdout

                            # Verify balance is now 0
                            updated_creds = json.loads(mock_creds_path.read_text())
                            assert updated_creds["token_pool_balance"] == 0

                            # Act 2: Try to scan again
                            result2 = runner.invoke(app, ["scan", "--project", "test-project"])

                            # Assert 2: Scan prevented with exit code 4
                            assert result2.exit_code == 4
                            assert "Token pool depleted" in result2.stdout
                            assert "0 scans remaining" in result2.stdout
                            assert "bqaudit.com/pricing" in result2.stdout

                            # Act 3: Validate still attempts to run (doesn't check token balance)
                            # Note: validate will likely fail due to actual BigQuery API calls,
                            # but the key is that it doesn't fail with exit code 4 (token depletion)
                            result3 = runner.invoke(app, ["validate", "--project", "test-project"])

                            # Assert 3: Validation doesn't fail due to token balance check
                            # The critical test is that it doesn't show "Token pool depleted" error
                            assert "Token pool depleted" not in result3.stdout
                            # Validation attempts to run (doesn't get blocked by token check)
                            assert "Starting BigQuery Validation" in result3.stdout

                            # Verify balance still 0 (validate doesn't consume tokens even when it fails)
                            final_creds = json.loads(mock_creds_path.read_text())
                            assert final_creds["token_pool_balance"] == 0

    # Act 4: Check license status shows depletion (outside BigQuery mock context)
    result4 = runner.invoke(app, ["license", "status"])

    # Assert 4: Status shows DEPLETED
    assert result4.exit_code == 0
    assert "0 scans remaining (DEPLETED)" in result4.stdout
    assert "bqaudit.com/pricing" in result4.stdout
