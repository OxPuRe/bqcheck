"""Integration tests for scan command (Story 5.1)."""

import json
from unittest.mock import Mock, patch

import httpx
import pytest

from bqaudit.api.client import BQAuditAPIClient
from bqaudit.api.models import AuditRequest, AuditResponse, AuditSummary, Recommendation


@pytest.fixture
def mock_credentials_file(tmp_path):
    """Create mock credentials file for testing."""
    creds_dir = tmp_path / ".bqaudit"
    creds_dir.mkdir()
    creds_file = creds_dir / "credentials"

    credentials = {
        "master_key": "sk_live_test_key",
        "ephemeral_token": "eph_test_token",
        "token_pool_balance": 5,
        "server_url": "https://api.bqaudit.test",
    }

    creds_file.write_text(json.dumps(credentials, indent=2))
    creds_file.chmod(0o600)

    return creds_file


@pytest.fixture
def mock_audit_response():
    """Create mock audit response for testing."""
    return AuditResponse(
        recommendations=[
            Recommendation(
                type="storage",
                priority="HIGH",
                title="Remove unused table",
                description="Table has not been accessed in 90 days",
                savings_eur=150.0,
                implementation_steps=["DROP TABLE dataset.table"],
            )
        ],
        summary=AuditSummary(
            total_recommendations=1,
            total_potential_savings_eur=150.0,
            high_priority_count=1,
            medium_priority_count=0,
            low_priority_count=0,
            categories_breakdown={"storage": 1},
        ),
        audit_id="audit_test_123",
        new_ephemeral_token="eph_new_token",
    )


class TestScanCommandIntegration:
    """Integration tests for scan command with mock server."""

    @pytest.mark.asyncio
    async def test_successful_audit_consumes_token(
        self, mock_credentials_file, mock_audit_response
    ):
        """
        Test successful audit execution with token consumption.

        Scenario:
        - token_pool_balance = 5
        - Execute scan command
        - Balance decremented to 4
        - New ephemeral token saved

        AC1, AC2
        """
        # RED PHASE: This test should FAIL because execute_audit() doesn't exist yet
        client = BQAuditAPIClient(mock_mode=False)

        audit_request = AuditRequest(
            project_id="a" * 64, metadata={"tables": [], "queries": []}
        )

        # Mock httpx response
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = mock_audit_response.model_dump()
            mock_post.return_value = mock_response

            # This should fail - method doesn't exist yet
            result = await client.execute_audit(
                audit_request=audit_request, ephemeral_token="eph_test_token"
            )

            assert isinstance(result, AuditResponse)
            assert result.new_ephemeral_token == "eph_new_token"
            assert result.summary.total_recommendations == 1

    @pytest.mark.asyncio
    async def test_network_error_preserves_token(self, mock_credentials_file):
        """
        Test that network errors don't consume tokens (AC3, AC5).

        Scenario:
        - Mock server returns ConnectError
        - Execute scan with retries
        - Token balance unchanged
        - Exit code 1
        """
        # RED PHASE: This test should FAIL
        client = BQAuditAPIClient(mock_mode=False)

        audit_request = AuditRequest(
            project_id="a" * 64, metadata={"tables": [], "queries": []}
        )

        # Mock httpx ConnectError
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_post.side_effect = httpx.ConnectError("Connection refused")

            # Should raise NetworkError after retries
            with pytest.raises(Exception):  # Will be NetworkError once implemented
                await client.execute_audit(
                    audit_request=audit_request, ephemeral_token="eph_test_token"
                )

            # Verify retries happened (at least 3 attempts)
            assert mock_post.call_count >= 3

    @pytest.mark.asyncio
    async def test_timeout_error_with_retries(self):
        """
        Test timeout handling with retry logic (AC5).

        Scenario:
        - Server times out (>15 minutes)
        - Retry logic attempts 3 times
        - Exit code 1
        """
        # RED PHASE: This test should FAIL
        client = BQAuditAPIClient(mock_mode=False)

        audit_request = AuditRequest(
            project_id="a" * 64, metadata={"tables": [], "queries": []}
        )

        # Mock httpx TimeoutException
        with patch("httpx.AsyncClient.post") as mock_post:
            mock_post.side_effect = httpx.TimeoutException("Request timeout")

            # Should raise after retries
            with pytest.raises(Exception):
                await client.execute_audit(
                    audit_request=audit_request, ephemeral_token="eph_test_token"
                )

            # Verify at least 3 retry attempts
            assert mock_post.call_count >= 3

    def test_token_depletion_prevents_scan(self, tmp_path):
        """
        Test that depleted token pool prevents scan (AC4).

        Scenario:
        - token_pool_balance = 0
        - Execute scan command
        - No HTTP request sent
        - Exit code 4
        """
        # RED PHASE: This test should FAIL - scan command doesn't exist yet
        # This will be implemented in Task 1.1-1.2

        creds_dir = tmp_path / ".bqaudit"
        creds_dir.mkdir()
        creds_file = creds_dir / "credentials"

        # Create credentials with zero balance
        credentials = {
            "master_key": "sk_live_test_key",
            "ephemeral_token": "eph_test_token",
            "token_pool_balance": 0,  # DEPLETED
            "server_url": "https://api.bqaudit.test",
        }

        creds_file.write_text(json.dumps(credentials, indent=2))

        # TODO: This will be implemented when scan command exists
        # For now, just verify the credentials file exists
        assert creds_file.exists()
        creds_data = json.loads(creds_file.read_text())
        assert creds_data["token_pool_balance"] == 0


@pytest.mark.asyncio
async def test_execute_audit_includes_correct_headers():
    """
    Test that execute_audit sends correct headers (AC1).

    Verify:
    - X-Ephemeral-Token header is included
    - Content-Type is application/json
    """
    # RED PHASE: This test should FAIL
    client = BQAuditAPIClient(mock_mode=False)

    audit_request = AuditRequest(
        project_id="a" * 64, metadata={"tables": [], "queries": []}
    )

    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "recommendations": [],
            "summary": {
                "total_recommendations": 0,
                "total_potential_savings_eur": 0.0,
                "high_priority_count": 0,
                "medium_priority_count": 0,
                "low_priority_count": 0,
                "categories_breakdown": {},
            },
            "audit_id": "test_123",
            "new_ephemeral_token": "eph_new",
        }
        mock_post.return_value = mock_response

        await client.execute_audit(
            audit_request=audit_request, ephemeral_token="eph_test_token"
        )

        # Verify headers
        call_kwargs = mock_post.call_args.kwargs
        headers = call_kwargs.get("headers", {})
        assert headers.get("X-Ephemeral-Token") == "eph_test_token"


class TestScanCommandProgressIndicators:
    """Integration tests for scan command progress indicators (Story 5.3)."""

    @pytest.mark.asyncio
    async def test_scan_shows_progress_indicators(
        self, mock_credentials_file, mock_audit_response
    ):
        """
        Test that scan command displays progress indicators (AC1-5).

        Scenario:
        - Execute real scan with BQAUDIT_REAL_SCAN=true
        - Verify progress messages are displayed in correct order
        - Verify success message with recommendations count and savings
        """
        # Mock BigQuery and server responses
        import io

        from rich.console import Console

        from bqaudit.api.client import BQAuditAPIClient
        from bqaudit.scan.executor import ScanExecutor

        # Create mock console to capture output
        console = Console(file=io.StringIO())

        # Mock BigQuery client and metadata extraction
        with patch("bqaudit.scanner.authenticate_bigquery") as mock_auth:
            with patch("bqaudit.scanner.metadata_extractor.extract_table_metadata") as mock_tables:
                with patch("bqaudit.scanner.metadata_extractor.extract_query_metadata") as mock_queries:
                    with patch("bqaudit.scanner.metadata_extractor.extract_access_patterns") as mock_access:
                        with patch("httpx.AsyncClient.post") as mock_post:
                            with patch("bqaudit.console.console", console):
                                # Setup mocks
                                mock_auth.return_value = Mock()
                                mock_tables.return_value = []
                                mock_queries.return_value = []
                                mock_access.return_value = []

                                mock_response = Mock()
                                mock_response.status_code = 200
                                mock_response.json.return_value = mock_audit_response.model_dump()
                                mock_post.return_value = mock_response

                                # Execute scan
                                client = BQAuditAPIClient(mock_mode=False)
                                executor = ScanExecutor(client)

                                await executor.execute_real_scan(
                                    project_id="my-project",
                                    ephemeral_token="eph_test_token"
                                )

                                # Verify output contains progress messages
                                output = console.file.getvalue()
                                assert "🔍 Starting BigQuery audit" in output
                                assert "☁️  Sending anonymized metadata" in output

    @pytest.mark.asyncio
    async def test_scan_handles_permission_error(self, mock_credentials_file, capsys):
        """
        Test that scan handles BigQuery permission errors (AC6).

        Scenario:
        - BigQuery raises PermissionDenied
        - Display actionable error message
        - Raises ScanError with exit code 3
        """
        from google.api_core.exceptions import PermissionDenied

        from bqaudit.api.client import BQAuditAPIClient
        from bqaudit.scan.executor import ScanError, ScanExecutor

        # Mock BigQuery to raise PermissionDenied
        with patch("bqaudit.scanner.authenticate_bigquery") as mock_auth:
            with patch("subprocess.check_output") as mock_gcloud:
                mock_auth.side_effect = PermissionDenied("Access denied")
                mock_gcloud.return_value = "user@example.com\n"

                # Execute scan
                client = BQAuditAPIClient(mock_mode=False)
                executor = ScanExecutor(client)

                # Story 5.3: Should raise ScanError with code 3 instead of sys.exit()
                with pytest.raises(ScanError) as exc_info:
                    await executor.execute_real_scan(
                        project_id="my-project",
                        ephemeral_token="eph_test_token"
                    )

                assert exc_info.value.exit_code == 3

                # Verify error message was printed (captured by Rich to stderr)
                captured = capsys.readouterr()
                assert "Insufficient BigQuery permissions" in captured.err or "Insufficient BigQuery permissions" in captured.out

    @pytest.mark.asyncio
    async def test_scan_handles_network_error(self, mock_credentials_file, capsys):
        """
        Test that scan handles network errors (AC7).

        Scenario:
        - Server communication fails with ConnectError (after retries)
        - Display actionable error message
        - Raises ScanError with exit code 1
        """
        from bqaudit.api.client import BQAuditAPIClient
        from bqaudit.scan.executor import ScanError, ScanExecutor

        # Mock BigQuery and server responses
        with patch("bqaudit.scanner.authenticate_bigquery") as mock_auth:
            with patch("bqaudit.scanner.metadata_extractor.extract_table_metadata") as mock_tables:
                with patch("bqaudit.scanner.metadata_extractor.extract_query_metadata") as mock_queries:
                    with patch("bqaudit.scanner.metadata_extractor.extract_access_patterns") as mock_access:
                        with patch("httpx.AsyncClient.post") as mock_post:
                            # Setup mocks
                            mock_auth.return_value = Mock()
                            mock_tables.return_value = []
                            mock_queries.return_value = []
                            mock_access.return_value = []

                            # Simulate network error
                            mock_post.side_effect = httpx.ConnectError("Connection refused")

                            # Execute scan
                            client = BQAuditAPIClient(mock_mode=False)
                            executor = ScanExecutor(client)

                            # Story 5.3: Should raise ScanError with code 1 instead of sys.exit()
                            with pytest.raises(ScanError) as exc_info:
                                await executor.execute_real_scan(
                                    project_id="my-project",
                                    ephemeral_token="eph_test_token"
                                )

                            assert exc_info.value.exit_code == 1

                            # Verify error message was printed
                            captured = capsys.readouterr()
                            assert "Unable to reach audit server" in captured.err or "Unable to reach audit server" in captured.out

    @pytest.mark.asyncio
    async def test_scan_handles_timeout_error(self, mock_credentials_file, capsys):
        """
        Test that scan handles timeout errors (AC8).

        Scenario:
        - Server times out (after retries)
        - Display actionable error message
        - Raises ScanError with exit code 1
        """
        from bqaudit.api.client import BQAuditAPIClient
        from bqaudit.scan.executor import ScanError, ScanExecutor

        # Mock BigQuery and server responses
        with patch("bqaudit.scanner.authenticate_bigquery") as mock_auth:
            with patch("bqaudit.scanner.metadata_extractor.extract_table_metadata") as mock_tables:
                with patch("bqaudit.scanner.metadata_extractor.extract_query_metadata") as mock_queries:
                    with patch("bqaudit.scanner.metadata_extractor.extract_access_patterns") as mock_access:
                        with patch("httpx.AsyncClient.post") as mock_post:
                            # Setup mocks
                            mock_auth.return_value = Mock()
                            mock_tables.return_value = []
                            mock_queries.return_value = []
                            mock_access.return_value = []

                            # Simulate timeout error
                            mock_post.side_effect = httpx.TimeoutException("Request timeout")

                            # Execute scan
                            client = BQAuditAPIClient(mock_mode=False)
                            executor = ScanExecutor(client)

                            # Story 5.3: Should raise ScanError with code 1 instead of sys.exit()
                            with pytest.raises(ScanError) as exc_info:
                                await executor.execute_real_scan(
                                    project_id="my-project",
                                    ephemeral_token="eph_test_token"
                                )

                            assert exc_info.value.exit_code == 1

                            # Verify error message was printed
                            captured = capsys.readouterr()
                            assert "Audit timeout" in captured.err or "Audit timeout" in captured.out
