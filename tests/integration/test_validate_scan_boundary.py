"""
Integration test for validate/scan boundary with token depletion.

This test validates the critical distinction between validate and scan commands
when the token pool is depleted (balance = 0):

- validate: Should succeed (does NOT consume tokens)
- scan: Should fail with exit code 4 (requires tokens)

Story 3.5, AC4: "Validate command still works (no token consumed)"
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from typer.testing import CliRunner

from bqaudit.cli import app
from bqaudit.scanner.encryption import IdentifierEncryptor

runner = CliRunner()


def test_validate_succeeds_but_scan_fails_when_token_depleted(tmp_path: Path):
    """
    Integration test: validate works, scan fails when balance=0.

    This validates the critical boundary between validate (pre-flight check)
    and scan (actual audit execution) when token pool is depleted.
    """
    # Setup: Create credentials with balance = 0
    mock_creds_path = tmp_path / ".bqaudit" / "credentials.json"
    mock_creds_path.parent.mkdir(parents=True, exist_ok=True)

    mock_credentials = {
        "master_key": "VALID-DEPLETED-KEY",
        "token_pool_balance": 0,  # DEPLETED
        "ephemeral_token": "mock-token-xyz",
        "server_url": "https://api.bqaudit.com",
        "activated_at": "2024-01-01T00:00:00+00:00",
        "used_tokens": [],
        "encryption_key": IdentifierEncryptor.key_to_base64(
            IdentifierEncryptor.generate_key()
        ),
    }

    mock_creds_path.write_text(json.dumps(mock_credentials))
    mock_creds_path.chmod(0o600)

    # Patch HOME to use tmp_path
    with patch.dict("os.environ", {"HOME": str(tmp_path)}):
        # ACT 1: Run validate command (should succeed despite balance=0)
        validate_result = runner.invoke(app, ["validate", "--project", "test-project"])

        # ASSERT 1: Validate succeeds (or fails for other reasons,
        # but NOT token depletion)
        # Exit code should NOT be 4 (token depletion code)
        assert validate_result.exit_code != 4, (
            f"Validate should not fail due to token depletion. "
            f"Got exit code: {validate_result.exit_code}\n"
            f"Output: {validate_result.stdout}"
        )

        # Verify balance is still 0 (validate didn't consume token)
        updated_creds_1 = json.loads(mock_creds_path.read_text())
        assert updated_creds_1["token_pool_balance"] == 0, (
            "Validate command should not consume tokens"
        )

        # ACT 2: Run scan command (should fail with exit code 4)
        scan_result = runner.invoke(app, ["scan", "--project", "test-project"])

        # ASSERT 2: Scan fails with token depletion error
        assert scan_result.exit_code == 4, (
            f"Scan should fail with exit code 4 (token depletion). "
            f"Got: {scan_result.exit_code}\n"
            f"Output: {scan_result.stdout}"
        )

        assert "Token pool depleted" in scan_result.stdout, (
            "Scan should display token depletion message"
        )

        assert "0 scans remaining" in scan_result.stdout, (
            "Scan should show current balance (0)"
        )

        # Verify balance is still 0 (scan didn't execute)
        updated_creds_2 = json.loads(mock_creds_path.read_text())
        assert updated_creds_2["token_pool_balance"] == 0, (
            "Failed scan should not consume token"
        )


def test_validate_and_scan_both_work_when_tokens_available(tmp_path: Path):
    """
    Integration test: Both validate and scan work when balance > 0.

    This validates normal operation when tokens are available.
    """
    # Setup: Create credentials with balance = 5
    mock_creds_path = tmp_path / ".bqaudit" / "credentials.json"
    mock_creds_path.parent.mkdir(parents=True, exist_ok=True)

    mock_credentials = {
        "master_key": "VALID-KEY-ABC",
        "token_pool_balance": 5,  # Tokens available
        "ephemeral_token": "mock-token-xyz",
        "server_url": "https://api.bqaudit.com",
        "activated_at": "2024-01-01T00:00:00+00:00",
        "used_tokens": [],
        "encryption_key": IdentifierEncryptor.key_to_base64(
            IdentifierEncryptor.generate_key()
        ),
    }

    mock_creds_path.write_text(json.dumps(mock_credentials))
    mock_creds_path.chmod(0o600)

    # Mock BigQuery client
    mock_bq_client = Mock()
    mock_bq_client.list_datasets.return_value = []

    # Mock HTTP response
    mock_http_response = Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "status": "success",
        "token_pool_balance": 4,
        "recommendations": [],
        "summary": {
            "total_recommendations": 0,
            "total_potential_savings_eur": 0.0,
            "high_priority_count": 0,
            "medium_priority_count": 0,
            "low_priority_count": 0,
            "categories_breakdown": {},
        },
        "audit_id": "test-audit-id-123",
        "new_ephemeral_token": "new-token-456",
    }

    # Mock AsyncClient
    mock_async_client = Mock()
    mock_async_client.post = AsyncMock(return_value=mock_http_response)
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=None)

    # Patch HOME to use tmp_path
    with patch.dict("os.environ", {"HOME": str(tmp_path)}):
        # Patch BigQuery and HTTP for scan
        with patch(
            "bqaudit.scanner.bigquery_client.authenticate_bigquery",
            return_value=mock_bq_client,
        ):
            with patch(
                "bqaudit.scanner.authenticate_bigquery", return_value=mock_bq_client
            ):
                with patch(
                    "bqaudit.scanner.metadata_extractor.extract_table_metadata",
                    return_value=[],
                ):
                    with patch(
                        "bqaudit.scanner.metadata_extractor.extract_query_metadata",
                        return_value=[],
                    ):
                        with patch(
                            "bqaudit.scanner.metadata_extractor.extract_access_patterns",
                            return_value=[],
                        ):
                            with patch(
                                "bqaudit.scanner.metadata_extractor.extract_table_schemas",
                                return_value={},
                            ):
                                with patch(
                                    "httpx.AsyncClient", return_value=mock_async_client
                                ):
                                    # ACT 1: Run validate (should succeed)
                                    validate_result = runner.invoke(
                                        app, ["validate", "--project", "test-project"]
                                    )

                                    # ASSERT 1: Validate doesn't fail due to token issues
                                    assert validate_result.exit_code != 4, (
                                        "Validate should not check token balance"
                                    )

                                    # Verify balance unchanged (validate doesn't consume)
                                    creds_after_validate = json.loads(
                                        mock_creds_path.read_text()
                                    )
                                    assert (
                                        creds_after_validate["token_pool_balance"] == 5
                                    ), "Validate should not consume tokens"

                                    # ACT 2: Run scan (should succeed and consume 1 token)
                                    scan_result = runner.invoke(
                                        app, ["scan", "--project", "test-project"]
                                    )

                                    # ASSERT 2: Scan succeeds
                                    assert scan_result.exit_code == 0, (
                                        f"Scan should succeed with available tokens. "
                                        f"Got exit code: {scan_result.exit_code}\n"
                                        f"Output: {scan_result.stdout}"
                                    )

                                    # Verify balance decremented by 1
                                    creds_after_scan = json.loads(
                                        mock_creds_path.read_text()
                                    )
                                    assert (
                                        creds_after_scan["token_pool_balance"] == 4
                                    ), "Scan should consume exactly 1 token"
