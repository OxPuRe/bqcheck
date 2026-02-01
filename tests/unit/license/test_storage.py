"""Unit tests for credential storage module."""

import json

import pytest

from bqaudit.license.storage import (
    CredentialNotFoundError,
    CredentialStore,
    UnsafePermissionsError,
)


class TestCredentialStore:
    """Test suite for CredentialStore class."""

    def test_save_creates_directory_if_not_exists(self, tmp_path, monkeypatch):
        """Test that save() creates ~/.bqaudit directory if needed."""
        monkeypatch.setenv("HOME", str(tmp_path))

        credentials = {
            "master_key": "TEST-KEY",
            "token_pool_balance": 50,
            "ephemeral_token": "token123",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }

        CredentialStore.save(credentials)

        cred_dir = tmp_path / ".bqaudit"
        assert cred_dir.exists()
        assert cred_dir.is_dir()

    def test_save_creates_file_with_chmod_600(self, tmp_path, monkeypatch):
        """AC5: Verify credentials file created with chmod 600."""
        monkeypatch.setenv("HOME", str(tmp_path))

        credentials = {
            "master_key": "TEST-KEY",
            "token_pool_balance": 50,
            "ephemeral_token": "token123",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }

        CredentialStore.save(credentials)

        cred_file = tmp_path / ".bqaudit" / "credentials.json"
        assert cred_file.exists()

        # Verify chmod 600 (owner read/write only)
        mode = cred_file.stat().st_mode
        # Last 3 octal digits should be 600
        assert oct(mode)[-3:] == "600"

    def test_save_writes_valid_json(self, tmp_path, monkeypatch):
        """AC6: Verify credential file contains valid JSON."""
        monkeypatch.setenv("HOME", str(tmp_path))

        credentials = {
            "master_key": "TEST-KEY",
            "token_pool_balance": 50,
            "ephemeral_token": "token123",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }

        CredentialStore.save(credentials)

        cred_file = tmp_path / ".bqaudit" / "credentials.json"
        loaded = json.loads(cred_file.read_text())

        assert loaded["master_key"] == "TEST-KEY"
        assert loaded["token_pool_balance"] == 50
        assert loaded["ephemeral_token"] == "token123"

    def test_save_atomic_write(self, tmp_path, monkeypatch):
        """Test that save uses atomic write pattern (temp file + rename)."""
        monkeypatch.setenv("HOME", str(tmp_path))

        credentials = {
            "master_key": "TEST",
            "token_pool_balance": 50,
            "ephemeral_token": "token123",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }
        CredentialStore.save(credentials)

        # After successful save, temp file should not exist
        temp_file = tmp_path / ".bqaudit" / "credentials.tmp"
        assert not temp_file.exists()

        # Final file should exist
        final_file = tmp_path / ".bqaudit" / "credentials.json"
        assert final_file.exists()

    def test_load_returns_credentials(self, tmp_path, monkeypatch):
        """Test that load() returns stored credentials."""
        monkeypatch.setenv("HOME", str(tmp_path))

        credentials = {
            "master_key": "TEST-KEY",
            "token_pool_balance": 50,
            "ephemeral_token": "token123",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }

        CredentialStore.save(credentials)
        loaded = CredentialStore.load()

        # Story 3.4 added used_tokens field with default=[]
        # Note: activated_at is serialized to 'Z' format by field_serializer
        expected = {
            **credentials,
            "activated_at": "2026-01-30T10:00:00Z",  # Serialized to Z format
            "used_tokens": [],
        }
        assert loaded == expected

    def test_load_raises_if_file_not_exists(self, tmp_path, monkeypatch):
        """Test that load() raises CredentialNotFoundError if no file."""
        monkeypatch.setenv("HOME", str(tmp_path))

        with pytest.raises(CredentialNotFoundError):
            CredentialStore.load()

    def test_load_auto_fixes_unsafe_permissions(self, tmp_path, monkeypatch):
        """AC5 (Round 6, Issue #5): Test that load() auto-fixes unsafe permissions."""
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create credentials file with unsafe permissions
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(parents=True)
        cred_file = cred_dir / "credentials.json"

        # Need complete credentials to avoid ValidationError after auto-fix
        credentials = {
            "master_key": "TEST-KEY-123",
            "token_pool_balance": 50,
            "ephemeral_token": "token123",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }
        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o644)  # Unsafe: group/other can read

        # Should auto-fix permissions and load successfully
        result = CredentialStore.load()

        assert result["master_key"] == "TEST-KEY-123"
        # Verify permissions were corrected to 0o600
        assert cred_file.stat().st_mode & 0o777 == 0o600

    def test_exists_returns_true_if_file_exists(self, tmp_path, monkeypatch):
        """Test exists() returns True when credentials file exists."""
        monkeypatch.setenv("HOME", str(tmp_path))

        credentials = {
            "master_key": "TEST",
            "token_pool_balance": 50,
            "ephemeral_token": "token123",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }
        CredentialStore.save(credentials)

        assert CredentialStore.exists() is True

    def test_exists_returns_false_if_file_not_exists(self, tmp_path, monkeypatch):
        """Test exists() returns False when credentials file doesn't exist."""
        monkeypatch.setenv("HOME", str(tmp_path))

        assert CredentialStore.exists() is False

    def test_delete_removes_file(self, tmp_path, monkeypatch):
        """Test delete() removes credentials file."""
        monkeypatch.setenv("HOME", str(tmp_path))

        credentials = {
            "master_key": "TEST",
            "token_pool_balance": 50,
            "ephemeral_token": "token123",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }
        CredentialStore.save(credentials)

        assert CredentialStore.exists() is True

        CredentialStore.delete()

        assert CredentialStore.exists() is False

    def test_update_updates_credentials(self, tmp_path, monkeypatch):
        """Test update() modifies existing credentials."""
        monkeypatch.setenv("HOME", str(tmp_path))

        initial = {
            "master_key": "TEST",
            "token_pool_balance": 50,
            "ephemeral_token": "token123",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }
        CredentialStore.save(initial)

        updated = {
            "master_key": "TEST",
            "token_pool_balance": 49,
            "ephemeral_token": "token456",
            "server_url": "https://api.bqaudit.com",
            "activated_at": "2026-01-30T10:00:00+00:00",
        }
        CredentialStore.update(updated)

        loaded = CredentialStore.load()
        assert loaded["token_pool_balance"] == 49
