"""Unit tests for API client with mock mode."""

import pytest

from bqaudit.api.client import BQAuditAPIClient
from bqaudit.api.exceptions import (
    HTTPSRequiredError,
    InvalidLicenseKeyError,
    NetworkError,
)


class TestBQAuditAPIClient:
    """Test suite for BQAuditAPIClient class."""

    def test_mock_mode_default_true(self):
        """Test that mock_mode defaults to True for Epic 3."""
        client = BQAuditAPIClient()
        assert client.mock_mode is True

    def test_https_enforcement_in_real_mode(self, monkeypatch):
        """
        AC8 (Partial): Test HTTPS-only enforcement in real mode.

        Coverage Status:
        ✅ HTTPS protocol enforcement (HTTP URLs rejected)
        ⚠️  Self-signed certificate rejection (deferred to future epic)

        Rationale for partial coverage:
        - HTTPS enforcement is testable without real server
        - Self-signed cert rejection is enforced by httpx default (verify=True)
        - Testing cert validation requires complex SSL mock setup
        - Real server endpoint implementation (future epic) will enable full AC8 testing

        This test verifies that HTTP URLs are rejected with HTTPSRequiredError.
        The httpx library's default behavior (verify=True) handles self-signed
        certificate rejection, but this is not explicitly tested here.
        """
        # Set HTTP server URL
        monkeypatch.setenv("BQAUDIT_API_URL", "http://insecure.com")

        # Should raise HTTPSRequiredError when mock_mode=False
        with pytest.raises(HTTPSRequiredError) as exc_info:
            BQAuditAPIClient(mock_mode=False)

        assert "https" in str(exc_info.value).lower()

    # TODO (Future Epic): Add test for self-signed certificate rejection
    # @pytest.mark.skip(reason="Requires real server with self-signed cert")
    # def test_self_signed_cert_rejection(self):
    #     """AC8 (Full): Verify self-signed certificates are rejected."""
    #     pass

    def test_https_not_enforced_in_mock_mode(self, monkeypatch):
        """Test that HTTPS check skipped in mock mode."""
        monkeypatch.setenv("BQAUDIT_API_URL", "http://localhost:8000")

        # Should NOT raise in mock mode
        client = BQAuditAPIClient(mock_mode=True)
        assert client.server_url == "http://localhost:8000"

    def test_activate_license_success_with_valid_key(self):
        """AC1: Test activation success with VALID- prefix."""
        client = BQAuditAPIClient(mock_mode=True)

        response = client.activate_license("VALID-TEST-KEY-123")

        assert response.token_pool_balance == 50
        assert response.ephemeral_token == "mock-ephemeral-token-xyz"
        assert "api.bqaudit.com" in response.server_url
        assert response.activated_at is not None

    def test_activate_license_invalid_key(self):
        """AC2: Test activation failure with invalid key."""
        client = BQAuditAPIClient(mock_mode=True)

        with pytest.raises(InvalidLicenseKeyError) as exc_info:
            client.activate_license("INVALID-KEY-123")

        assert "invalid license key" in str(exc_info.value).lower()

    def test_activate_license_network_error(self):
        """AC3: Test network error simulation."""
        client = BQAuditAPIClient(mock_mode=True)

        with pytest.raises(NetworkError) as exc_info:
            client.activate_license("NETWORK-ERROR-TEST")

        assert "network" in str(exc_info.value).lower()

    def test_renew_token_returns_new_token(self):
        """Test token renewal returns new ephemeral token."""
        client = BQAuditAPIClient(mock_mode=True)

        response = client.renew_token("VALID-TEST-KEY", current_balance=50)

        assert response.ephemeral_token.startswith("mock-renewed-token-")
        assert response.token_pool_balance == 49  # Decremented from 50

    def test_renew_token_different_each_time(self):
        """Test that renewed tokens are unique."""
        client = BQAuditAPIClient(mock_mode=True)

        token1 = client.renew_token(
            "VALID-TEST-KEY", current_balance=50
        ).ephemeral_token
        token2 = client.renew_token(
            "VALID-TEST-KEY", current_balance=50
        ).ephemeral_token

        # Should be different (random suffix)
        assert token1 != token2
