"""Shared test fixtures and utilities."""

import pytest

from bqaudit.scanner.encryption import IdentifierEncryptor


@pytest.fixture
def valid_test_credentials():
    """Create valid test credentials with all required fields including encryption_key."""
    return {
        "master_key": "TEST-KEY",
        "token_pool_balance": 50,
        "ephemeral_token": "token123",
        "server_url": "https://api.bqaudit.com",
        "activated_at": "2026-01-30T10:00:00+00:00",
        "encryption_key": IdentifierEncryptor.key_to_base64(
            IdentifierEncryptor.generate_key()
        ),
    }


def create_test_credentials(**overrides):
    """
    Helper function to create test credentials with optional field overrides.

    Args:
        **overrides: Fields to override in the default credentials

    Returns:
        Dict with valid test credentials

    Example:
        >>> creds = create_test_credentials(token_pool_balance=49)
        >>> creds["token_pool_balance"]
        49
    """
    credentials = {
        "master_key": "TEST-KEY",
        "token_pool_balance": 50,
        "ephemeral_token": "token123",
        "server_url": "https://api.bqaudit.com",
        "activated_at": "2026-01-30T10:00:00+00:00",
        "encryption_key": IdentifierEncryptor.key_to_base64(
            IdentifierEncryptor.generate_key()
        ),
    }
    credentials.update(overrides)
    return credentials
