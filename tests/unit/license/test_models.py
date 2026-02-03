"""Unit tests for license models."""

from datetime import datetime, timezone

from bqaudit.license.models import Credentials
from bqaudit.scanner.encryption import IdentifierEncryptor


class TestCredentialsModel:
    """Test suite for Credentials model."""

    def test_parse_activated_at_from_datetime_object(self):
        """Test activated_at validator accepts datetime object directly."""
        dt = datetime(2026, 1, 30, 10, 0, 0, tzinfo=timezone.utc)

        credentials = Credentials(
            master_key="TEST-KEY",
            token_pool_balance=50,
            ephemeral_token="token123",
            server_url="https://api.bqaudit.com",
            activated_at=dt,  # Pass datetime object directly
            encryption_key=IdentifierEncryptor.key_to_base64(
                IdentifierEncryptor.generate_key()
            ),
        )

        assert credentials.activated_at == dt

    def test_to_safe_dict_masks_sensitive_fields(self):
        """Test to_safe_dict() masks master_key, ephemeral_token, and encryption_key."""
        credentials = Credentials(
            master_key="SECRET-MASTER-KEY",
            token_pool_balance=50,
            ephemeral_token="secret-token-123",
            server_url="https://api.bqaudit.com",
            activated_at="2026-01-30T10:00:00+00:00",
            encryption_key="secret-encryption-key-base64",
        )

        safe_dict = credentials.to_safe_dict()

        # Verify sensitive fields are masked
        assert safe_dict["master_key"] == "***REDACTED***"
        assert safe_dict["ephemeral_token"] == "***REDACTED***"
        assert safe_dict["encryption_key"] == "***REDACTED***"

        # Verify non-sensitive fields are intact
        assert safe_dict["token_pool_balance"] == 50
        assert safe_dict["server_url"] == "https://api.bqaudit.com"
        assert "activated_at" in safe_dict
