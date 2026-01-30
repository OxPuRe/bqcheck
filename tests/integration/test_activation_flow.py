"""Integration tests for end-to-end activation flow."""

import json
import pytest
from typer.testing import CliRunner

from bqaudit.cli import app
from bqaudit.license.storage import CredentialStore


runner = CliRunner()


class TestActivationFlowIntegration:
    """Integration tests for complete activation workflow."""

    def test_end_to_end_activation_flow(self, tmp_path, monkeypatch):
        """
        Integration test: End-to-end activation flow.

        Steps:
        1. Activate license
        2. Verify credentials file exists
        3. Verify file has chmod 600
        4. Verify credentials can be loaded
        5. Verify all fields present
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Step 1: Activate license
        result = runner.invoke(
            app, ["license", "activate", "VALID-INTEGRATION-TEST-KEY"]
        )

        assert result.exit_code == 0
        assert "activated successfully" in result.stdout.lower()
        assert "50 scans remaining" in result.stdout

        # Step 2: Verify credentials file exists
        cred_file = tmp_path / ".bqaudit" / "credentials.json"
        assert cred_file.exists()

        # Step 3: Verify chmod 600
        mode = cred_file.stat().st_mode
        assert oct(mode)[-3:] == "600"

        # Step 4: Verify credentials can be loaded
        credentials = CredentialStore.load()

        # Step 5: Verify all required fields
        assert credentials["master_key"] == "VALID-INTEGRATION-TEST-KEY"
        assert credentials["token_pool_balance"] == 50
        assert credentials["ephemeral_token"] == "mock-ephemeral-token-xyz"
        assert "api.bqaudit.com" in credentials["server_url"]
        assert credentials["activated_at"] is not None

    def test_prevent_reactivation_flow(self, tmp_path, monkeypatch):
        """
        Integration test: Prevent re-activation if credentials exist.

        AC4: Credentials already exist scenario
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # First activation
        result1 = runner.invoke(app, ["license", "activate", "VALID-FIRST-KEY"])
        assert result1.exit_code == 0

        # Second activation should be prevented
        result2 = runner.invoke(app, ["license", "activate", "VALID-SECOND-KEY"])
        assert result2.exit_code == 0  # Graceful exit
        assert "already activated" in result2.stdout.lower()
        assert "license revoke" in result2.stdout.lower()

        # Verify original credentials unchanged
        credentials = CredentialStore.load()
        assert credentials["master_key"] == "VALID-FIRST-KEY"

    def test_invalid_key_error_flow(self, tmp_path, monkeypatch):
        """
        Integration test: Invalid license key error handling.

        AC2: Invalid license key scenario
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        result = runner.invoke(app, ["license", "activate", "INVALID-KEY-BAD"])

        # Should exit with error
        assert result.exit_code == 1
        assert "invalid license key" in result.stdout.lower()

        # Verify NO credentials file created
        cred_file = tmp_path / ".bqaudit" / "credentials.json"
        assert not cred_file.exists()

    def test_network_error_flow(self, tmp_path, monkeypatch):
        """
        Integration test: Network error handling.

        AC3: Network failure scenario
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        result = runner.invoke(app, ["license", "activate", "NETWORK-ERROR-TEST"])

        # Should exit with error
        assert result.exit_code == 1
        assert "network" in result.stdout.lower()

        # Verify NO credentials file created
        cred_file = tmp_path / ".bqaudit" / "credentials.json"
        assert not cred_file.exists()

    def test_master_key_masking_in_output(self, tmp_path, monkeypatch):
        """
        Integration test: Master key masking in CLI output.

        AC7: Tokens never logged - master key masked
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        result = runner.invoke(
            app, ["license", "activate", "VALID-ABC-XYZ-123-SECRET"]
        )

        assert result.exit_code == 0

        # Full key should NOT appear in output
        assert "VALID-ABC-XYZ-123-SECRET" not in result.stdout

        # Masked key should appear
        assert "VALID-ABC-***" in result.stdout

    @pytest.mark.parametrize(
        "invalid_key",
        [
            "INVALID-BAD-KEY",
            "WRONG-LICENSE",
            "BAD-TOKEN-123",
        ],
    )
    def test_various_invalid_keys(self, tmp_path, monkeypatch, invalid_key):
        """Test that various invalid key formats are rejected."""
        monkeypatch.setenv("HOME", str(tmp_path))

        result = runner.invoke(app, ["license", "activate", invalid_key])

        assert result.exit_code == 1
        assert "invalid license key" in result.stdout.lower()

        # No credentials file created
        cred_file = tmp_path / ".bqaudit" / "credentials.json"
        assert not cred_file.exists()
