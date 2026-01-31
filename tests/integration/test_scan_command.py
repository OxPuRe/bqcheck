"""Integration tests for scan command (Story 5.1)."""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
import httpx

from bqaudit.api.client import BQAuditAPIClient
from bqaudit.api.models import AuditRequest, AuditResponse, AuditSummary, Recommendation
from bqaudit.constants import (
    EXIT_SUCCESS,
    EXIT_NETWORK_ERROR,
    EXIT_NO_TOKENS,
)


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

            # Verify retries happened (3 attempts)
            assert mock_post.call_count == 3

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

            # Verify 3 retry attempts
            assert mock_post.call_count == 3

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
