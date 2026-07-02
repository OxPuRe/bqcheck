"""Unit tests for BigQuery client authentication."""

from unittest.mock import Mock, patch

import pytest
from google.api_core.exceptions import NotFound
from google.auth.exceptions import DefaultCredentialsError

from bqcheck.scanner.bigquery_client import (
    AuthenticationError,
    ProjectNotFoundError,
    authenticate_bigquery,
)


@patch("bqcheck.scanner.bigquery_client.default")
@patch("bqcheck.scanner.bigquery_client.bigquery.Client")
def test_successful_authentication(mock_client_class, mock_default):
    """Test successful BigQuery client initialization."""
    # Mock credentials
    mock_creds = Mock()
    mock_default.return_value = (mock_creds, None)

    # Mock client instance
    mock_bq_client = Mock()
    mock_client_class.return_value = mock_bq_client

    # Mock list_datasets to return empty iterator (project exists)
    mock_bq_client.list_datasets.return_value = iter([])

    # Call function
    client = authenticate_bigquery("test-project")

    # Verify client initialization
    mock_default.assert_called_once()
    mock_client_class.assert_called_once_with(
        credentials=mock_creds, project="test-project"
    )
    # Verify project verification was performed
    mock_bq_client.list_datasets.assert_called_once_with(max_results=1, timeout=30.0)
    assert client == mock_bq_client


@patch("bqcheck.scanner.bigquery_client.default")
def test_authentication_failure(mock_default):
    """Test authentication failure handling."""
    # Mock credentials error
    mock_default.side_effect = DefaultCredentialsError("No credentials")

    # Call function - should raise AuthenticationError
    with pytest.raises(AuthenticationError) as exc_info:
        authenticate_bigquery("test-project")

    # Verify error message
    assert exc_info.value.message == "GCP authentication failed - no credentials found"


@patch("bqcheck.scanner.bigquery_client.default")
@patch("bqcheck.scanner.bigquery_client.bigquery.Client")
def test_invalid_project_handling(mock_client_class, mock_default):
    """Test invalid project ID handling."""
    # Mock credentials
    mock_creds = Mock()
    mock_default.return_value = (mock_creds, None)

    # Mock client that raises NotFound on list_datasets
    mock_bq_client = Mock()
    mock_client_class.return_value = mock_bq_client
    mock_bq_client.list_datasets.side_effect = NotFound("Project not found")

    # Call function - should raise ProjectNotFoundError
    with pytest.raises(ProjectNotFoundError) as exc_info:
        authenticate_bigquery("invalid-project")

    # Verify error message
    assert (
        exc_info.value.message
        == "BigQuery project 'invalid-project' not found or inaccessible"
    )


@patch("bqcheck.scanner.bigquery_client.default")
@patch("bqcheck.scanner.bigquery_client.bigquery.Client")
def test_project_verification(mock_client_class, mock_default):
    """Test that project verification is actually performed."""
    # Mock credentials
    mock_creds = Mock()
    mock_default.return_value = (mock_creds, None)

    # Mock client with proper list_datasets return value
    mock_bq_client = Mock()
    mock_client_class.return_value = mock_bq_client
    mock_bq_client.list_datasets.return_value = iter([])

    # Call function
    client = authenticate_bigquery("verified-project")

    # Verify that list_datasets was called to verify project access
    mock_bq_client.list_datasets.assert_called_once_with(max_results=1, timeout=30.0)
    # Verify client was returned
    assert client == mock_bq_client
