"""
Unit tests for ScanExecutor (Story 3.4, Task 2).

Tests cover:
- AC1: Execute scan with token management
- AC2: Atomic token consumption - failure preserves token
- AC3: Token auto-renewal after success
- AC6: Atomic credential update
"""

import json
from pathlib import Path
from unittest import mock

import pytest

from bqaudit.api.client import BQAuditAPIClient
from bqaudit.license.storage import CredentialStore
from bqaudit.scanner.encryption import IdentifierEncryptor


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
def test_credentials(mock_creds_path):
    """Create test credentials file."""
    credentials = {
        "master_key": "VALID-TEST-KEY-123",
        "ephemeral_token": "test-token-original",
        "token_pool_balance": 10,
        "server_url": "https://api.bqaudit.com",
        "activated_at": "2024-01-01T00:00:00+00:00",
        "encryption_key": IdentifierEncryptor.key_to_base64(
            IdentifierEncryptor.generate_key()
        ),
    }

    # Save credentials
    mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
    mock_creds_path.write_text(json.dumps(credentials))
    mock_creds_path.chmod(0o600)

    return credentials


@pytest.fixture
def mock_real_scan_mode(monkeypatch):
    """Force simulated scan mode and mock validation for unit tests."""
    monkeypatch.setenv("BQAUDIT_REAL_SCAN", "false")
    monkeypatch.setattr(
        "bqaudit.scanner.bigquery_client.validate_multi_project_permissions",
        lambda storage_project, query_project=None: None,
    )


@pytest.fixture
def mock_bigquery_and_server():
    """Mock BigQuery authentication and server responses for scan tests."""
    from unittest.mock import AsyncMock

    mock_bq_client = mock.Mock()
    mock_bq_client.list_datasets.return_value = []

    mock_http_response = mock.Mock()
    mock_http_response.status_code = 200
    mock_http_response.json.return_value = {
        "status": "success",
        "token_pool_balance": 49,
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

    # Mock AsyncClient to return our mock response
    mock_async_client = mock.Mock()
    mock_async_client.post = AsyncMock(return_value=mock_http_response)
    mock_async_client.__aenter__ = AsyncMock(return_value=mock_async_client)
    mock_async_client.__aexit__ = AsyncMock(return_value=None)

    patches = [
        mock.patch(
            "bqaudit.scanner.bigquery_client.authenticate_bigquery",
            return_value=mock_bq_client,
        ),
        mock.patch(
            "bqaudit.scanner.authenticate_bigquery", return_value=mock_bq_client
        ),
        mock.patch(
            "bqaudit.scanner.metadata_extractor.extract_table_metadata",
            return_value=[],
        ),
        mock.patch(
            "bqaudit.scanner.metadata_extractor.extract_query_metadata",
            return_value=[],
        ),
        mock.patch(
            "bqaudit.scanner.metadata_extractor.extract_access_patterns",
            return_value=[],
        ),
        mock.patch(
            "bqaudit.scanner.metadata_extractor.extract_table_schemas",
            return_value={},
        ),
        mock.patch("httpx.AsyncClient", return_value=mock_async_client),
    ]

    with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[
        6
    ]:
        yield mock_http_response


class TestScanExecutor:
    """Test ScanExecutor token lifecycle management."""

    def test_executor_imports(self):
        """Verify ScanExecutor can be imported."""
        from bqaudit.scan.executor import ScanExecutor

        assert ScanExecutor is not None

    def test_execute_scan_with_valid_credentials(
        self, test_credentials, mock_creds_path, mock_bigquery_and_server
    ):
        """AC1: Execute scan loads credentials and runs simulated scan."""
        from bqaudit.scan.executor import ScanExecutor

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        result = executor.execute_scan_with_tokens("test-project")

        # Should succeed
        assert result.success is True
        assert result.project_id == "test-project"
        assert result.simulated is False  # Real scan with mocked dependencies

    def test_scan_success_renews_token(
        self, test_credentials, mock_creds_path, mock_bigquery_and_server
    ):
        """AC3: Successful scan renews ephemeral token."""
        from bqaudit.scan.executor import ScanExecutor

        original_token = test_credentials["ephemeral_token"]

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        executor.execute_scan_with_tokens("test-project")

        # Load updated credentials
        updated_creds = CredentialStore.load()

        # Token should be renewed (different from original)
        assert updated_creds["ephemeral_token"] != original_token
        assert updated_creds["ephemeral_token"] == "new-token-456"

    def test_scan_success_decrements_balance(
        self, test_credentials, mock_creds_path, mock_bigquery_and_server
    ):
        """AC1: Successful scan decrements token pool balance by 1."""
        from bqaudit.scan.executor import ScanExecutor

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        executor.execute_scan_with_tokens("test-project")

        # Load updated credentials
        updated_creds = CredentialStore.load()

        # Balance decremented by 1
        assert updated_creds["token_pool_balance"] == 9

    def test_scan_failure_preserves_token(
        self, test_credentials, mock_creds_path, mock_bigquery_and_server
    ):
        """AC2: CRITICAL - Scan failure preserves token and balance."""
        from bqaudit.scan.executor import ScanError, ScanExecutor

        original_token = test_credentials["ephemeral_token"]
        original_balance = test_credentials["token_pool_balance"]

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Mock the execute_real_scan method to simulate failure with ScanError
        with mock.patch.object(
            executor,
            "execute_real_scan",
            side_effect=ScanError(exit_code=1, message="Simulated scan failure"),
        ):
            # Execute scan - should exit with code 1 due to ScanError
            with pytest.raises(SystemExit) as exc_info:
                executor.execute_scan_with_tokens("test-project")
            assert exc_info.value.code == 1

        # Load credentials - should be UNCHANGED
        updated_creds = CredentialStore.load()

        # AC2: Token preserved (not consumed)
        assert updated_creds["ephemeral_token"] == original_token

        # AC2: Balance unchanged
        assert updated_creds["token_pool_balance"] == original_balance

    def test_atomic_credential_update_on_failure(
        self, test_credentials, mock_creds_path, mock_bigquery_and_server
    ):
        """AC6: Credential update failure preserves original credentials."""
        from bqaudit.scan.executor import ScanExecutor

        original_token = test_credentials["ephemeral_token"]
        original_balance = test_credentials["token_pool_balance"]

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Mock CredentialStore.update to fail
        with mock.patch(
            "bqaudit.license.storage.CredentialStore.update",
            side_effect=IOError("Simulated write failure"),
        ):
            with pytest.raises(IOError):
                executor.execute_scan_with_tokens("test-project")

        # Original credentials should be preserved
        preserved_creds = CredentialStore.load()
        assert preserved_creds["ephemeral_token"] == original_token
        assert preserved_creds["token_pool_balance"] == original_balance

    def test_token_renewal_after_scan(
        self, test_credentials, mock_creds_path, mock_bigquery_and_server
    ):
        """AC3: Token renewal returns new token different from old."""
        from bqaudit.scan.executor import ScanExecutor

        # Mock different responses for each scan
        mock_bigquery_and_server.json.side_effect = [
            {
                "status": "success",
                "token_pool_balance": 49,
                "recommendations": [],
                "summary": {
                    "total_recommendations": 0,
                    "total_potential_savings_eur": 0.0,
                    "high_priority_count": 0,
                    "medium_priority_count": 0,
                    "low_priority_count": 0,
                    "categories_breakdown": {},
                },
                "audit_id": "test-audit-id-1",
                "new_ephemeral_token": "token-1",
            },
            {
                "status": "success",
                "token_pool_balance": 48,
                "recommendations": [],
                "summary": {
                    "total_recommendations": 0,
                    "total_potential_savings_eur": 0.0,
                    "high_priority_count": 0,
                    "medium_priority_count": 0,
                    "low_priority_count": 0,
                    "categories_breakdown": {},
                },
                "audit_id": "test-audit-id-2",
                "new_ephemeral_token": "token-2",
            },
        ]

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Execute 2 scans
        executor.execute_scan_with_tokens("test-project-1")
        creds1 = CredentialStore.load()
        token1 = creds1["ephemeral_token"]

        executor.execute_scan_with_tokens("test-project-2")
        creds2 = CredentialStore.load()
        token2 = creds2["ephemeral_token"]

        # Each renewal should produce a DIFFERENT token
        assert token1 != token2
        assert token1 != test_credentials["ephemeral_token"]
        assert token2 != test_credentials["ephemeral_token"]

    def test_credentials_file_permissions_preserved(
        self, test_credentials, mock_creds_path, mock_bigquery_and_server
    ):
        """AC6: Credentials file maintains chmod 600 after update."""
        from bqaudit.scan.executor import ScanExecutor

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Execute scan (triggers credential update)
        executor.execute_scan_with_tokens("test-project")

        # Verify file permissions are still 600
        import stat

        file_mode = mock_creds_path.stat().st_mode
        permissions = stat.filemode(file_mode)

        # Should be -rw------- (owner read/write only)
        assert permissions == "-rw-------"

    def test_single_use_token_tracking(
        self, test_credentials, mock_creds_path, mock_bigquery_and_server
    ):
        """AC8: Old tokens marked as used (client-side tracking)."""
        from bqaudit.scan.executor import ScanExecutor

        original_token = test_credentials["ephemeral_token"]

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Execute scan
        executor.execute_scan_with_tokens("test-project")

        # Load updated credentials
        updated_creds = CredentialStore.load()

        # Verify used_tokens tracking exists
        assert "used_tokens" in updated_creds
        assert len(updated_creds["used_tokens"]) >= 1

        # Code Review Round 8, Issue #7: Token stored as SHA-256 hash, not truncated
        import hashlib

        expected_hash = hashlib.sha256(original_token.encode("utf-8")).hexdigest()
        used_token_hashes = [ut["token_hash"] for ut in updated_creds["used_tokens"]]
        assert expected_hash in used_token_hashes


class TestMultiProjectPermissionValidation:
    """Test multi-project permission validation before token consumption."""

    def test_validation_function_exists(self):
        """Verify validate_multi_project_permissions can be imported."""
        from bqaudit.scanner.bigquery_client import validate_multi_project_permissions

        assert validate_multi_project_permissions is not None

    def test_validation_with_mock_projects(
        self, test_credentials, mock_creds_path, mock_real_scan_mode
    ):
        """Test that validation runs before scan execution."""
        from bqaudit.scan.executor import ScanExecutor

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Mock validate_multi_project_permissions to avoid real BQ calls
        with mock.patch(
            "bqaudit.scanner.bigquery_client.validate_multi_project_permissions"
        ) as mock_validate:
            executor.execute_scan_with_tokens(
                "storage-project", query_project="query-project"
            )

            # Validation should be called with both projects
            mock_validate.assert_called_once_with("storage-project", "query-project")

    def test_validation_with_single_project(
        self, test_credentials, mock_creds_path, mock_real_scan_mode
    ):
        """Test that validation works with single project (no query_project)."""
        from bqaudit.scan.executor import ScanExecutor

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Mock validate_multi_project_permissions
        with mock.patch(
            "bqaudit.scanner.bigquery_client.validate_multi_project_permissions"
        ) as mock_validate:
            executor.execute_scan_with_tokens("my-project")

            # Validation should be called with project and None
            mock_validate.assert_called_once_with("my-project", None)

    def test_permission_error_prevents_token_consumption(
        self, test_credentials, mock_creds_path
    ):
        """CRITICAL: Permission errors prevent token consumption."""
        from bqaudit.scan.executor import ScanExecutor
        from bqaudit.scanner.bigquery_client import PermissionError as BQPermissionError

        original_balance = test_credentials["token_pool_balance"]

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Mock validation to raise PermissionError
        with mock.patch(
            "bqaudit.scanner.bigquery_client.validate_multi_project_permissions",
            side_effect=BQPermissionError("Missing permissions on query-project"),
        ):
            # Should exit with code 3 (caught by sys.exit in executor)
            with pytest.raises(SystemExit) as exc_info:
                executor.execute_scan_with_tokens(
                    "storage-project", query_project="query-project"
                )
            assert exc_info.value.code == 3

        # CRITICAL: Token balance should NOT be decremented
        updated_creds = CredentialStore.load()
        assert updated_creds["token_pool_balance"] == original_balance

    def test_project_not_found_prevents_token_consumption(
        self, test_credentials, mock_creds_path
    ):
        """CRITICAL: Project not found errors prevent token consumption."""
        from bqaudit.scan.executor import ScanExecutor
        from bqaudit.scanner.bigquery_client import ProjectNotFoundError

        original_balance = test_credentials["token_pool_balance"]

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Mock validation to raise ProjectNotFoundError
        with mock.patch(
            "bqaudit.scanner.bigquery_client.validate_multi_project_permissions",
            side_effect=ProjectNotFoundError("Project 'fake-project' not found"),
        ):
            # Should exit with code 2
            with pytest.raises(SystemExit) as exc_info:
                executor.execute_scan_with_tokens(
                    "storage-project", query_project="fake-project"
                )
            assert exc_info.value.code == 2

        # CRITICAL: Token balance should NOT be decremented
        updated_creds = CredentialStore.load()
        assert updated_creds["token_pool_balance"] == original_balance

    def test_successful_validation_allows_scan(
        self, test_credentials, mock_creds_path, mock_real_scan_mode
    ):
        """Test that successful validation allows scan to proceed."""
        from bqaudit.scan.executor import ScanExecutor

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Mock successful validation
        with mock.patch(
            "bqaudit.scanner.bigquery_client.validate_multi_project_permissions"
        ):
            result = executor.execute_scan_with_tokens(
                "storage-project", query_project="query-project"
            )

            # Scan should succeed
            assert result.success is True

        # Token should be consumed
        updated_creds = CredentialStore.load()
        assert updated_creds["token_pool_balance"] == 9
