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
    }

    # Save credentials
    mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
    mock_creds_path.write_text(json.dumps(credentials))
    mock_creds_path.chmod(0o600)

    return credentials


class TestScanExecutor:
    """Test ScanExecutor token lifecycle management."""

    def test_executor_imports(self):
        """Verify ScanExecutor can be imported."""
        from bqaudit.scan.executor import ScanExecutor

        assert ScanExecutor is not None

    def test_execute_scan_with_valid_credentials(
        self, test_credentials, mock_creds_path
    ):
        """AC1: Execute scan loads credentials and runs simulated scan."""
        from bqaudit.scan.executor import ScanExecutor

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        result = executor.execute_scan_with_tokens("test-project")

        # Should succeed
        assert result.success is True
        assert result.project_id == "test-project"
        assert result.simulated is True

    def test_scan_success_renews_token(self, test_credentials, mock_creds_path):
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
        assert updated_creds["ephemeral_token"].startswith("mock-renewed-token-")

    def test_scan_success_decrements_balance(self, test_credentials, mock_creds_path):
        """AC1: Successful scan decrements token pool balance by 1."""
        from bqaudit.scan.executor import ScanExecutor

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        executor.execute_scan_with_tokens("test-project")

        # Load updated credentials
        updated_creds = CredentialStore.load()

        # Balance decremented by 1
        assert updated_creds["token_pool_balance"] == 9

    def test_scan_failure_preserves_token(self, test_credentials, mock_creds_path):
        """AC2: CRITICAL - Scan failure preserves token and balance."""
        from bqaudit.scan.executor import ScanExecutor

        original_token = test_credentials["ephemeral_token"]
        original_balance = test_credentials["token_pool_balance"]

        api_client = BQAuditAPIClient(mock_mode=True)
        executor = ScanExecutor(api_client)

        # Mock executor to simulate scan failure
        with mock.patch.object(
            executor,
            "_execute_simulated_scan",
            side_effect=RuntimeError("Simulated scan failure"),
        ):
            with pytest.raises(RuntimeError, match="Simulated scan failure"):
                executor.execute_scan_with_tokens("test-project")

        # Load credentials - should be UNCHANGED
        updated_creds = CredentialStore.load()

        # AC2: Token preserved (not consumed)
        assert updated_creds["ephemeral_token"] == original_token

        # AC2: Balance unchanged
        assert updated_creds["token_pool_balance"] == original_balance

    def test_atomic_credential_update_on_failure(
        self, test_credentials, mock_creds_path
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

    def test_token_renewal_after_scan(self, test_credentials, mock_creds_path):
        """AC3: Token renewal returns new token different from old."""
        from bqaudit.scan.executor import ScanExecutor

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
        self, test_credentials, mock_creds_path
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

    def test_single_use_token_tracking(self, test_credentials, mock_creds_path):
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
