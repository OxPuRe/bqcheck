"""Unit tests for license activation logic."""

import json
import pytest
from pathlib import Path

from bqaudit.api.exceptions import InvalidLicenseKeyError, NetworkError
from bqaudit.license.activate import activate_license
from bqaudit.license.storage import CredentialStore


class TestActivateLicense:
    """Test suite for activate_license() function."""

    def test_activate_success_saves_credentials(self, tmp_path, monkeypatch):
        """AC1: Test successful activation saves credentials."""
        monkeypatch.setenv("HOME", str(tmp_path))

        result = activate_license("VALID-TEST-KEY-123", mock_mode=True)

        # Verify credentials file created
        cred_file = tmp_path / ".bqaudit" / "credentials.json"
        assert cred_file.exists()

        # Verify chmod 600
        mode = cred_file.stat().st_mode
        assert oct(mode)[-3:] == "600"

        # Verify credentials content
        credentials = json.loads(cred_file.read_text())
        assert credentials["master_key"] == "VALID-TEST-KEY-123"
        assert credentials["token_pool_balance"] == 50
        assert credentials["ephemeral_token"] == "mock-ephemeral-token-xyz"

        # Verify return value
        assert result["token_pool_balance"] == 50

    def test_activate_invalid_key_no_file_created(self, tmp_path, monkeypatch):
        """AC2: Test invalid key does NOT create credentials file."""
        monkeypatch.setenv("HOME", str(tmp_path))

        with pytest.raises(InvalidLicenseKeyError):
            activate_license("INVALID-KEY", mock_mode=True)

        # Verify NO credentials file created
        cred_file = tmp_path / ".bqaudit" / "credentials.json"
        assert not cred_file.exists()

    def test_activate_network_error_no_file_created(self, tmp_path, monkeypatch):
        """AC3: Test network error does NOT create credentials file."""
        monkeypatch.setenv("HOME", str(tmp_path))

        with pytest.raises(NetworkError):
            activate_license("NETWORK-ERROR-TEST", mock_mode=True)

        # Verify NO credentials file created
        cred_file = tmp_path / ".bqaudit" / "credentials.json"
        assert not cred_file.exists()

    def test_activate_raises_if_credentials_exist(self, tmp_path, monkeypatch):
        """AC4: Test activation fails if credentials already exist."""
        monkeypatch.setenv("HOME", str(tmp_path))

        # First activation
        activate_license("VALID-FIRST-KEY", mock_mode=True)

        # Second activation should fail
        with pytest.raises(FileExistsError) as exc_info:
            activate_license("VALID-SECOND-KEY", mock_mode=True)

        assert "already activated" in str(exc_info.value).lower()
        assert "license revoke" in str(exc_info.value).lower()

        # Verify original credentials unchanged
        credentials = CredentialStore.load()
        assert credentials["master_key"] == "VALID-FIRST-KEY"

    def test_activate_all_required_fields_present(self, tmp_path, monkeypatch):
        """AC6: Test all required credential fields are present."""
        monkeypatch.setenv("HOME", str(tmp_path))

        activate_license("VALID-TEST-KEY", mock_mode=True)

        credentials = CredentialStore.load()

        # Verify all required fields
        assert "master_key" in credentials
        assert "token_pool_balance" in credentials
        assert "ephemeral_token" in credentials
        assert "server_url" in credentials
        assert "activated_at" in credentials

        # Verify correct types
        assert isinstance(credentials["master_key"], str)
        assert isinstance(credentials["token_pool_balance"], int)
        assert isinstance(credentials["ephemeral_token"], str)
        assert isinstance(credentials["server_url"], str)
        assert isinstance(credentials["activated_at"], str)  # ISO8601 string
