"""Unit tests for custom output path support (Story 5.4).

Tests cover:
- AC1: Custom absolute path
- AC2: Auto-create directories
- AC3: File overwrite prompt
- AC4: Force overwrite without prompt
- AC5: Permission denied handling
- AC6: Relative path resolution
"""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bqaudit.api.models import AuditResponse, AuditSummary
from bqaudit.cli import app
from bqaudit.report_generator import MarkdownReportGenerator

runner = CliRunner()


@pytest.fixture
def mock_credentials(tmp_path: Path) -> dict:
    """Create mock credentials for testing."""
    credentials = {
        "master_key": "VALID-TEST-KEY-123",
        "ephemeral_token": "test-token-xyz-789",
        "token_pool_balance": 10,
        "server_url": "https://api.bqaudit.com",
        "activated_at": "2024-01-01T00:00:00+00:00",
    }

    # Create credentials file
    creds_dir = tmp_path / ".bqaudit"
    creds_dir.mkdir(parents=True, exist_ok=True)
    creds_file = creds_dir / "credentials.json"
    creds_file.write_text(json.dumps(credentials))
    creds_file.chmod(0o600)

    return credentials


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
def mock_audit_response():
    """Create mock audit response for report generation."""
    return AuditResponse(
        recommendations=[],
        summary=AuditSummary(
            total_recommendations=0,
            total_potential_savings_eur=0.0,
            high_priority_count=0,
            medium_priority_count=0,
            low_priority_count=0,
            categories_breakdown={},
        ),
        audit_id="test-audit-123",
        new_ephemeral_token="new-token-456",
    )


class TestPathResolution:
    """Test path resolution logic (AC6)."""

    def test_resolve_default_path_none(self, tmp_path, monkeypatch):
        """Test default path when no custom path provided."""

        # Change to tmp_path to avoid conflicts with existing files
        monkeypatch.chdir(tmp_path)

        # When: No custom path (None)

        # We'll test this via the MarkdownReportGenerator
        response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test-123",
            new_ephemeral_token="token-456",
        )
        generator = MarkdownReportGenerator(response, project_name="test-project")

        # Default behavior (output_dir=None, output_path=None)
        result_path = generator.save_report()

        # Should be in cwd with default name format
        # Use generator's timestamp to match the filename
        date_str = generator.timestamp.strftime("%Y-%m-%d")
        expected_name = f"audit-report-{date_str}.md"

        assert result_path.name == expected_name
        assert result_path.parent == tmp_path

    def test_resolve_absolute_path(self, tmp_path):
        """Test absolute path is used as-is (AC1)."""
        # Given: Absolute path
        custom_path = tmp_path / "reports" / "audit.md"

        # When: Pass absolute path to save_report
        response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test-123",
            new_ephemeral_token="token-456",
        )
        generator = MarkdownReportGenerator(response, project_name="test-project")

        # Create parent dir
        custom_path.parent.mkdir(parents=True, exist_ok=True)

        # Save to custom absolute path
        result_path = generator.save_report(output_path=custom_path)

        # Then: Should use absolute path exactly
        assert result_path == custom_path
        assert result_path.is_absolute()
        assert result_path.exists()

    def test_resolve_relative_path(self, tmp_path, monkeypatch):
        """Test relative path is resolved against cwd (AC6)."""
        # Given: Change cwd to tmp_path for testing
        monkeypatch.chdir(tmp_path)

        # Given: Relative path
        custom_path = Path("reports") / "audit.md"

        # When: Pass relative path to save_report
        response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test-123",
            new_ephemeral_token="token-456",
        )
        generator = MarkdownReportGenerator(response, project_name="test-project")

        # Create parent dir
        full_path = tmp_path / "reports"
        full_path.mkdir(parents=True, exist_ok=True)

        # Save to custom relative path
        result_path = generator.save_report(output_path=custom_path)

        # Then: Should be resolved relative to cwd
        expected_path = tmp_path / "reports" / "audit.md"
        assert result_path == expected_path
        assert result_path.is_absolute()
        assert result_path.exists()


class TestDirectoryAutoCreation:
    """Test directory auto-creation (AC2)."""

    def test_auto_create_parent_directories(self, tmp_path):
        """Test parent directories are created automatically (AC2)."""
        # Given: Non-existent directory path
        output_path = tmp_path / "new_dir" / "subdir" / "report.md"

        # Verify parent doesn't exist yet
        assert not output_path.parent.exists()

        # When: Save report to that path
        response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test-123",
            new_ephemeral_token="token-456",
        )
        generator = MarkdownReportGenerator(response, project_name="test-project")
        result_path = generator.save_report(output_path=output_path)

        # Then: Parent directories should be created
        assert output_path.parent.exists()
        assert output_path.parent.is_dir()
        assert result_path.exists()

    def test_handles_permission_error_creating_directory(self, tmp_path, monkeypatch):
        """Test permission error handling when creating directory (AC5)."""
        # Given: Path that will trigger permission error
        output_path = tmp_path / "restricted" / "report.md"

        # Mock Path.mkdir to raise PermissionError
        original_mkdir = Path.mkdir

        def mock_mkdir(self, *args, **kwargs):
            if "restricted" in str(self):
                raise PermissionError("Permission denied")
            return original_mkdir(self, *args, **kwargs)

        monkeypatch.setattr(Path, "mkdir", mock_mkdir)

        # When/Then: Should raise PermissionError
        response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test-123",
            new_ephemeral_token="token-456",
        )
        generator = MarkdownReportGenerator(response, project_name="test-project")

        with pytest.raises(PermissionError):
            generator.save_report(output_path=output_path)


class TestFileOverwriteHandling:
    """Test file overwrite handling (AC3, AC4)."""

    def test_overwrite_with_force_flag(self, tmp_path):
        """Test --force flag overwrites without prompt (AC4)."""
        # Given: Existing report file
        output_path = tmp_path / "existing.md"
        output_path.write_text("old report content")

        # When: Save with force (no prompt)
        response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test-123",
            new_ephemeral_token="token-456",
        )
        generator = MarkdownReportGenerator(response, project_name="test-project")
        result_path = generator.save_report(output_path=output_path, force=True)

        # Then: File overwritten
        assert result_path.read_text() != "old report content"
        assert "BigQuery Audit Report" in result_path.read_text()

    def test_overwrite_prompt_user_accepts(self, tmp_path, monkeypatch):
        """Test overwrite prompt when user accepts (AC3)."""
        # Given: Existing file
        output_path = tmp_path / "existing.md"
        output_path.write_text("old content")

        # Mock user input to accept
        inputs = iter(["y"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))

        # When: Save without force (prompt)
        response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test-123",
            new_ephemeral_token="token-456",
        )
        generator = MarkdownReportGenerator(response, project_name="test-project")
        result_path = generator.save_report(output_path=output_path, force=False, interactive=True)

        # Then: File should be overwritten
        assert "BigQuery Audit Report" in result_path.read_text()

    def test_overwrite_prompt_user_declines(self, tmp_path, monkeypatch):
        """Test overwrite prompt when user declines (AC3)."""
        # Given: Existing file
        output_path = tmp_path / "existing.md"
        output_path.write_text("old content")

        # Mock user input to decline
        inputs = iter(["n"])
        monkeypatch.setattr("builtins.input", lambda _: next(inputs))

        # When: Save without force (prompt)
        response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test-123",
            new_ephemeral_token="token-456",
        )
        generator = MarkdownReportGenerator(response, project_name="test-project")

        # Then: Should return None when user declines
        # (Story 5.3: Changed from raising FileExistsError to returning None)
        # CLI will handle None by exiting with appropriate message
        result = generator.save_report(output_path=output_path, force=False, interactive=True)
        assert result is None, "Expected None when user declines overwrite"

        # Verify original file was not overwritten
        assert output_path.read_text() == "old content"


class TestPermissionErrors:
    """Test permission error handling (AC5)."""

    def test_handles_permission_error_writing_file(self, tmp_path, monkeypatch):
        """Test permission error when writing file (AC5)."""
        # Given: Path with write permission error
        output_path = tmp_path / "no_permission.md"

        # Mock Path.write_text to raise PermissionError
        def mock_write_text(*args, **kwargs):
            raise PermissionError("Permission denied")

        monkeypatch.setattr(Path, "write_text", mock_write_text)

        # When/Then: Should raise PermissionError
        response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test-123",
            new_ephemeral_token="token-456",
        )
        generator = MarkdownReportGenerator(response, project_name="test-project")

        with pytest.raises(PermissionError):
            generator.save_report(output_path=output_path)


class TestScanCommandWithCustomOutput:
    """Integration tests for scan command with --output and --force flags."""

    def test_scan_with_custom_output_absolute_path(
        self, tmp_path, mock_credentials, mock_creds_path, mock_audit_response, monkeypatch
    ):
        """Test scan with custom absolute output path (AC1)."""
        # Setup credentials
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Enable real scan mode to generate report
        monkeypatch.setenv("BQAUDIT_REAL_SCAN", "true")

        # Mock the BigQuery scanning to return a mocked audit response
        async def mock_execute_real_scan(self, project_id, token):
            return mock_audit_response

        monkeypatch.setattr(
            "bqaudit.scan.executor.ScanExecutor.execute_real_scan",
            mock_execute_real_scan,
        )

        # Custom output path
        output_path = tmp_path / "custom" / "report.md"

        # Run scan with custom output
        result = runner.invoke(
            app,
            ["scan", "--project", "test-project", "--output", str(output_path)],
        )

        # Should succeed
        assert result.exit_code == 0

        # Report should be saved to custom path
        assert output_path.exists()
        assert "BigQuery Audit Report" in output_path.read_text()

        # Note: Console output uses Rich library which is captured separately
        # Just verify the file was created correctly

    def test_scan_with_custom_output_relative_path(
        self, tmp_path, mock_credentials, mock_creds_path, mock_audit_response, monkeypatch
    ):
        """Test scan with relative output path (AC6)."""
        # Setup credentials
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Enable real scan mode to generate report
        monkeypatch.setenv("BQAUDIT_REAL_SCAN", "true")

        # Mock the BigQuery scanning to return a mocked audit response
        async def mock_execute_real_scan(self, project_id, token):
            return mock_audit_response

        monkeypatch.setattr(
            "bqaudit.scan.executor.ScanExecutor.execute_real_scan",
            mock_execute_real_scan,
        )

        # Change to tmp_path for relative path testing
        monkeypatch.chdir(tmp_path)

        # Relative output path
        output_path = Path("reports") / "audit.md"
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Run scan with relative output
        result = runner.invoke(
            app,
            ["scan", "--project", "test-project", "--output", str(output_path)],
        )

        # Should succeed
        assert result.exit_code == 0

        # Report should exist at resolved path
        full_path = tmp_path / "reports" / "audit.md"
        assert full_path.exists()

    def test_scan_with_force_overwrite(
        self, tmp_path, mock_credentials, mock_creds_path, mock_audit_response, monkeypatch
    ):
        """Test scan with --force flag overwrites without prompt (AC4)."""
        # Setup credentials
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Enable real scan mode to generate report
        monkeypatch.setenv("BQAUDIT_REAL_SCAN", "true")

        # Mock the BigQuery scanning to return a mocked audit response
        async def mock_execute_real_scan(self, project_id, token):
            return mock_audit_response

        monkeypatch.setattr(
            "bqaudit.scan.executor.ScanExecutor.execute_real_scan",
            mock_execute_real_scan,
        )

        # Create existing file
        output_path = tmp_path / "existing.md"
        output_path.write_text("old report")

        # Run scan with --force
        result = runner.invoke(
            app,
            [
                "scan",
                "--project",
                "test-project",
                "--output",
                str(output_path),
                "--force",
            ],
        )

        # Should succeed without prompt
        assert result.exit_code == 0
        assert "Overwrite?" not in result.stdout  # No prompt shown

        # File should be overwritten
        assert output_path.read_text() != "old report"
        assert "BigQuery Audit Report" in output_path.read_text()

    def test_scan_permission_denied_displays_error(
        self, tmp_path, mock_credentials, mock_creds_path, mock_audit_response, monkeypatch
    ):
        """Test scan displays error on permission denied (AC5)."""
        # Setup credentials
        mock_creds_path.parent.mkdir(parents=True, exist_ok=True)
        mock_creds_path.write_text(json.dumps(mock_credentials))
        mock_creds_path.chmod(0o600)

        # Enable real scan mode to generate report
        monkeypatch.setenv("BQAUDIT_REAL_SCAN", "true")

        # Mock the BigQuery scanning to return a mocked audit response
        async def mock_execute_real_scan(self, project_id, token):
            return mock_audit_response

        monkeypatch.setattr(
            "bqaudit.scan.executor.ScanExecutor.execute_real_scan",
            mock_execute_real_scan,
        )

        # Path that will cause permission error
        output_path = tmp_path / "restricted" / "report.md"

        # Mock Path.write_text to raise PermissionError
        original_write_text = Path.write_text

        def mock_write_text(self, *args, **kwargs):
            if "restricted" in str(self):
                raise PermissionError("Permission denied")
            return original_write_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", mock_write_text)

        # Run scan
        result = runner.invoke(
            app,
            ["scan", "--project", "test-project", "--output", str(output_path)],
        )

        # Should fail with exit code 2
        assert result.exit_code == 2

        # Should display error message (may be split across lines in output)
        assert "❌ Error: Permission denied" in result.stdout
        assert "restricted" in result.stdout  # Part of path is in output
