"""Unit tests for license activate CLI command."""

from typer.testing import CliRunner

from bqaudit.cli import app

runner = CliRunner()


class TestLicenseActivateCommand:
    """Test suite for 'bqaudit license activate' command."""

    def test_license_command_group_exists(self):
        """Test that 'license' command group is registered in CLI."""
        result = runner.invoke(app, ["license", "--help"])
        assert result.exit_code == 0
        assert "license" in result.stdout.lower()

    def test_activate_subcommand_exists(self):
        """Test that 'activate' subcommand exists under 'license'."""
        result = runner.invoke(app, ["license", "activate", "--help"])
        assert result.exit_code == 0
        assert "activate" in result.stdout.lower()

    def test_activate_requires_master_key_argument(self):
        """Test that activate command requires master key argument."""
        result = runner.invoke(app, ["license", "activate"])
        # Should fail if no master key provided
        assert result.exit_code != 0

    def test_activate_with_master_key_calls_activation_logic(
        self, tmp_path, monkeypatch
    ):
        """Test that activate command with key calls activation logic."""
        # Set credentials path to temp location
        monkeypatch.setenv("HOME", str(tmp_path))
        monkeypatch.setenv("BQAUDIT_REAL_MODE", "false")  # Use mock mode

        # Use VALID- prefix for mock success
        result = runner.invoke(app, ["license", "activate", "VALID-TEST-KEY-123"])

        # Debug output if fail
        if result.exit_code != 0:
            print(f"Exit code: {result.exit_code}")
            print(f"stdout: {result.stdout}")
            if result.exception:
                print(f"Exception: {result.exception}")

        # Should succeed with VALID- prefix
        assert result.exit_code == 0
        assert "activated successfully" in result.stdout.lower()

    def test_activate_prevents_reactivation_if_credentials_exist(
        self, tmp_path, monkeypatch
    ):
        """AC4: Prevent re-activation if credentials already exist."""
        # Create mock credentials file
        cred_dir = tmp_path / ".bqaudit"
        cred_dir.mkdir(parents=True)
        cred_file = cred_dir / "credentials.json"
        cred_file.write_text('{"master_key": "EXISTING-KEY"}')
        cred_file.chmod(0o600)

        monkeypatch.setenv("HOME", str(tmp_path))

        result = runner.invoke(app, ["license", "activate", "NEW-KEY"])

        # AC4: Should not allow re-activation
        assert result.exit_code == 0  # Exit gracefully
        assert "already activated" in result.stdout.lower()
        assert "license revoke" in result.stdout.lower()

        # Verify credentials unchanged
        assert cred_file.read_text() == '{"master_key": "EXISTING-KEY"}'
