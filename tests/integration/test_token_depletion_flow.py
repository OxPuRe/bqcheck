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

from bqcheck.cli import app
from bqcheck.scanner.encryption import IdentifierEncryptor

runner = CliRunner()


@pytest.fixture
def mock_credentials(tmp_path: Path) -> dict:
    """Create mock credentials for testing."""
    credentials = {
        "master_key": "VALID-TEST-KEY-123",
        "ephemeral_token": "test-token-xyz-789",
        "token_pool_balance": 1,  # Start with 1 token
        "server_url": "https://api.bqcheck.com",
        "activated_at": "2024-01-01T00:00:00+00:00",
        "encryption_key": IdentifierEncryptor.key_to_base64(
            IdentifierEncryptor.generate_key()
        ),
    }

    # Create credentials file
    creds_dir = tmp_path / ".bqcheck"
    creds_dir.mkdir(parents=True, exist_ok=True)
    creds_file = creds_dir / "credentials.json"
    creds_file.write_text(json.dumps(credentials))
    creds_file.chmod(0o600)

    return credentials


@pytest.fixture
def mock_creds_path(tmp_path: Path, monkeypatch):
    """Mock CredentialStore path to use tmp_path."""
    creds_path = tmp_path / ".bqcheck" / "credentials.json"

    # Mock the _get_credentials_path method to return our test path
    monkeypatch.setattr(
        "bqcheck.license.storage.CredentialStore._get_credentials_path",
        lambda: creds_path,
    )
    return creds_path


def test_full_depletion_flow(tmp_path, mock_credentials, mock_creds_path, monkeypatch):
    """
    Integration: Use last token → warning → prevent next scan → validate works.

    This tests the complete token depletion lifecycle across multiple commands.
    """
    monkeypatch.setenv("BQCHECK_REAL_MODE", "false")  # Use mock mode

    # Arrange: Create credentials with balance = 1
    mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
    mock_creds_path.write_text(json.dumps(mock_credentials))
    mock_creds_path.chmod(0o600)

    # Mock BigQuery authentication and server communication
    mock_bq_client = Mock()
    mock_bq_client.list_datasets.return_value = []

    # Mock HTTP response from server
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "status": "success",
        "token_pool_balance": 0,  # Will be 0 after using last token
        "recommendations": [],
        "summary": {
            "total_recommendations": 0,
            "total_potential_savings_eur": 0.0,
            "high_priority_count": 0,
            "medium_priority_count": 0,
            "low_priority_count": 0,
            "categories_breakdown": {},
        },
        "check_id": "test-check-id-123",
        "new_ephemeral_token": "new-token-456",
    }

    # Mock AsyncClient to return our mock response
    from unittest.mock import AsyncMock

    mock_async_client = Mock()
    mock_async_client.post = AsyncMock(return_value=mock_http_response)
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=None)

    with patch(
        "bqcheck.scanner.bigquery_client.authenticate_bigquery",
        return_value=mock_bq_client,
    ):
        with patch(
            "bqcheck.scanner.authenticate_bigquery", return_value=mock_bq_client
        ):
            with patch(
                "bqcheck.scanner.metadata_extractor.extract_table_metadata",
                return_value=[],
            ):
                with patch(
                    "bqcheck.scanner.metadata_extractor.extract_query_metadata",
                    return_value=[],
                ):
                    with patch(
                        "bqcheck.scanner.metadata_extractor.extract_access_patterns",
                        return_value=[],
                    ):
                        with patch(
                            "bqcheck.scanner.metadata_extractor.extract_table_schemas",
                            return_value={},
                        ):
                            with patch(
                                "bqcheck.scanner.metadata_extractor.extract_materialized_view_definitions",
                                return_value=[],
                            ):
                                with patch(
                                    "httpx.AsyncClient",
                                    return_value=mock_async_client,
                                ):
                                    # Act 1: Use last token
                                    result1 = runner.invoke(
                                        app, ["scan", "--project", "test-project"]
                                    )

                                    # Assert 1: Scan succeeded with warning
                                    assert result1.exit_code == 0
                                    assert "This was your last token" in result1.stdout
                                    assert "Purchase more tokens" in result1.stdout

                                    # Verify balance is now 0
                                    updated_creds = json.loads(
                                        mock_creds_path.read_text()
                                    )
                                    assert updated_creds["token_pool_balance"] == 0

                                    # Act 2: Try to scan again
                                    result2 = runner.invoke(
                                        app, ["scan", "--project", "test-project"]
                                    )

                                    # Assert 2: Scan prevented with exit code 4
                                    assert result2.exit_code == 4
                                    assert "Token pool depleted" in result2.stdout
                                    assert "0 scans remaining" in result2.stdout
                                    assert "bqcheck.com/pricing" in result2.stdout

                                    # Act 3: Validate still attempts to run
                                    result3 = runner.invoke(
                                        app, ["validate", "--project", "test-project"]
                                    )

                                    # Assert 3: Validation doesn't fail due to token balance check
                                    assert "Token pool depleted" not in result3.stdout
                                    assert (
                                        "Starting BigQuery Validation" in result3.stdout
                                    )

                                    # Verify balance still 0
                                    final_creds = json.loads(
                                        mock_creds_path.read_text()
                                    )
                                    assert final_creds["token_pool_balance"] == 0

    # Act 4: Check license status shows depletion (outside BigQuery mock context)
    result4 = runner.invoke(app, ["license", "status"])

    # Assert 4: Status shows DEPLETED
    assert result4.exit_code == 0
    assert "0 scans remaining (DEPLETED)" in result4.stdout
    assert "bqcheck.com/pricing" in result4.stdout
