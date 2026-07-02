"""Security tests for license management."""

import logging

from typer.testing import CliRunner

from bqcheck.cli import app
from bqcheck.license.security import mask_key

runner = CliRunner()


class TestMaskKey:
    """Test suite for master key masking."""

    def test_mask_key_shows_first_two_segments(self):
        """AC7: Test that only first 2 segments are visible."""
        key = "ABC-XYZ-123-DEF-456"
        masked = mask_key(key)

        assert masked == "ABC-XYZ-***"

    def test_mask_key_short_key(self):
        """Test masking short keys (< 3 segments)."""
        key = "SHORT"
        masked = mask_key(key)

        assert masked == "***"

    def test_mask_key_two_segments(self):
        """Test masking keys with only 2 segments."""
        key = "ABC-XYZ"
        masked = mask_key(key)

        assert masked == "***"

    def test_mask_key_long_key(self):
        """Test masking keys with many segments."""
        key = "A-B-C-D-E-F-G"
        masked = mask_key(key)

        assert masked == "A-B-***"

    def test_mask_key_never_shows_full_key(self):
        """AC7: Verify full key never appears in masked output."""
        keys = [
            "ABC-XYZ-123",
            "VALID-TEST-KEY-456",
            "SK-LIVE-SECRET-123-456",
        ]

        for key in keys:
            masked = mask_key(key)
            # Full key should never appear
            assert key != masked
            # Should contain ***
            assert "***" in masked


class TestTokenLogging:
    """Test suite for AC7: Ephemeral tokens never logged."""

    def test_ephemeral_tokens_never_in_stdout(self, tmp_path, monkeypatch):
        """
        AC7 CRITICAL: Verify ephemeral tokens never appear in CLI output.

        This test ensures that the mock ephemeral token "mock-ephemeral-token-xyz"
        never appears in stdout during license activation.
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Activate license and capture stdout
        result = runner.invoke(app, ["license", "activate", "VALID-TEST-KEY-123"])

        # AC7: Ephemeral token must NEVER appear in output
        assert "mock-ephemeral-token-xyz" not in result.stdout
        assert "mock-ephemeral-token" not in result.stdout
        assert "eyJ" not in result.stdout  # JWT pattern

    def test_ephemeral_tokens_never_in_logs(self, tmp_path, monkeypatch, caplog):
        """
        AC7 CRITICAL: Verify ephemeral tokens never appear in debug logs.

        Even with --verbose flag, ephemeral tokens must NOT be logged.
        """
        monkeypatch.setenv("HOME", str(tmp_path))

        # Activate with debug logging enabled
        with caplog.at_level(logging.DEBUG):
            runner.invoke(app, ["license", "activate", "VALID-DEBUG-KEY"])

        # AC7: Scan all log records for token patterns
        for record in caplog.records:
            assert "mock-ephemeral-token" not in record.message
            assert "eyJ" not in record.message  # JWT pattern
            # Master keys can appear but ONLY masked
            if "VALID" in record.message:
                assert "***" in record.message or "VALID-DEBUG-***" in record.message
