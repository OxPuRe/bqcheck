"""Unit tests for license status CLI command."""

import json

from typer.testing import CliRunner

from bqcheck.cli import app
from bqcheck.constants import ExitCode
from tests.conftest import create_test_credentials

runner = CliRunner()


class TestLicenseStatusCLI:
    """Test suite for `bqcheck license status` command."""

    def test_status_display_valid_credentials(self, tmp_path, monkeypatch):
        """
        AC1: Display formatted status for valid credentials.

        Tests that when valid credentials exist, the status command displays:
        - License Status: Active
        - Masked master key (first 2 segments only)
        - Token pool balance
        - Activation timestamp
        - Server URL
        - Exit code 0
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create valid credentials file
        cred_dir = tmp_path / ".bqcheck"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = create_test_credentials(
            master_key="ABC-XYZ-123-DEF-456",
            token_pool_balance=47,
            ephemeral_token="token-xyz",
            activated_at="2026-01-28T10:30:00+00:00",
        )

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o600)

        # Run status command
        result = runner.invoke(app, ["license", "status"])

        # AC1: Verify exit code and output
        assert result.exit_code == 0
        assert "License Status: Active" in result.stdout
        assert "ABC-XYZ-***" in result.stdout  # Masked (AC5)
        assert "ABC-XYZ-123" not in result.stdout  # Full key not shown
        assert "47 scans remaining" in result.stdout
        assert "api.bqcheck.com" in result.stdout

    def test_status_no_credentials_found(self, tmp_path, monkeypatch):
        """
        AC2: Display activation instructions when no credentials exist.

        Tests that when credentials file doesn't exist:
        - Error message shown: "No active license found"
        - Activation instructions provided
        - Link to pricing page shown
        - Exit code 1
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # No credentials file created

        result = runner.invoke(app, ["license", "status"])

        # AC2: Verify error message and instructions
        assert result.exit_code == ExitCode.FILE_ERROR
        assert "No active license found" in result.stdout
        assert "bqcheck license activate" in result.stdout
        assert "https://bqcheck.com/pricing" in result.stdout

    def test_status_auto_fixes_unsafe_permissions(self, tmp_path, monkeypatch):
        """
        AC3 (Round 6, Issue #5): Auto-fix unsafe file permissions.

        Tests that when credentials file has permissions != 600:
        - Permissions are automatically corrected to 0o600
        - Status is displayed successfully
        - Exit code 0
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create credentials with wrong permissions (644 - group/other can read)
        cred_dir = tmp_path / ".bqcheck"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        credentials = create_test_credentials(
            master_key="ABC-XYZ-123",
            activated_at="2026-01-28T10:30:00+00:00",
        )

        cred_file.write_text(json.dumps(credentials, indent=2))
        cred_file.chmod(0o644)  # Wrong permissions!

        result = runner.invoke(app, ["license", "status"])

        # AC3 (updated): Verify auto-fix succeeded
        assert result.exit_code == 0
        assert "License Status: Active" in result.stdout
        assert "ABC-XYZ-***" in result.stdout  # Credentials shown (masked)
        # Verify permissions were corrected
        assert cred_file.stat().st_mode & 0o777 == 0o600

    def test_status_corrupted_json(self, tmp_path, monkeypatch):
        """
        AC4: Handle corrupted credentials (invalid JSON).

        Tests that when credentials file contains invalid JSON:
        - Corruption error message shown
        - Re-activation instructions provided
        - Exit code 1
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create credentials with invalid JSON
        cred_dir = tmp_path / ".bqcheck"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        cred_file.write_text("{invalid json syntax here")
        cred_file.chmod(0o600)

        result = runner.invoke(app, ["license", "status"])

        # AC4: Verify corruption error
        assert result.exit_code == ExitCode.FILE_ERROR
        assert "corrupted" in result.stdout.lower()
        assert "re-activate" in result.stdout.lower()

    def test_status_missing_required_fields(self, tmp_path, monkeypatch):
        """
        AC4: Handle corrupted credentials (missing required fields).

        Tests that when credentials file has valid JSON but missing fields:
        - Corruption error message shown
        - Re-activation instructions provided
        - Exit code 1
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Create credentials with missing fields
        cred_dir = tmp_path / ".bqcheck"
        cred_dir.mkdir(mode=0o700)
        cred_file = cred_dir / "credentials.json"

        # Missing token_pool_balance and ephemeral_token
        incomplete_credentials = {
            "master_key": "ABC-XYZ-123",
            "server_url": "https://api.bqcheck.com",
        }

        cred_file.write_text(json.dumps(incomplete_credentials, indent=2))
        cred_file.chmod(0o600)

        result = runner.invoke(app, ["license", "status"])

        # AC4: Verify corruption error
        assert result.exit_code == ExitCode.FILE_ERROR
        assert "corrupted" in result.stdout.lower()
        assert "re-activate" in result.stdout.lower()

    def test_master_key_never_shows_full(self, tmp_path, monkeypatch):
        """
        AC5: Verify master key is always masked in status output.

        Tests various master key formats to ensure full key never displayed.
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        test_keys = [
            ("ABC-XYZ-123", "ABC-XYZ-***"),
            ("VALID-TEST-KEY-456", "VALID-TEST-***"),
            ("SK-LIVE-SECRET-123-456-789", "SK-LIVE-***"),
        ]

        for full_key, expected_masked in test_keys:
            # Create credentials
            cred_dir = tmp_path / ".bqcheck"
            cred_dir.mkdir(mode=0o700, exist_ok=True)
            cred_file = cred_dir / "credentials.json"

            credentials = create_test_credentials(
                master_key=full_key,
                activated_at="2026-01-28T10:30:00+00:00",
            )

            cred_file.write_text(json.dumps(credentials, indent=2))
            cred_file.chmod(0o600)

            result = runner.invoke(app, ["license", "status"])

            # Verify masking
            assert result.exit_code == 0
            assert expected_masked in result.stdout
            assert full_key not in result.stdout  # Full key NEVER shown
