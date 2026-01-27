"""Unit tests for BigQuery metadata extraction."""

from unittest.mock import Mock, patch

import pytest
from google.api_core.exceptions import GoogleAPIError

from bqaudit.scanner.metadata_extractor import (
    _validate_project_id,
    extract_table_metadata,
)
from bqaudit.scanner.models import TableMetadata


@patch("bqaudit.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_success(mock_client):
    """Test successful extraction of table metadata with various table types."""

    # Mock BigQuery query response with 3 tables
    mock_row_1 = Mock()
    mock_row_1.table_catalog = "my-project"
    mock_row_1.table_schema = "analytics"
    mock_row_1.table_name = "events"
    mock_row_1.table_type = "TABLE"
    mock_row_1.creation_time = "2024-01-15 10:30:00 UTC"
    mock_row_1.size_bytes = 1073741824  # 1 GB
    mock_row_1.row_count = 1000000
    mock_row_1.partition_expiration_days = 90
    mock_row_1.time_partitioning_type = "DAY"
    mock_row_1.time_partitioning_field = "event_date"
    mock_row_1.clustering_fields = ["user_id", "event_type"]

    mock_row_2 = Mock()
    mock_row_2.table_catalog = "my-project"
    mock_row_2.table_schema = "analytics"
    mock_row_2.table_name = "users"
    mock_row_2.table_type = "TABLE"
    mock_row_2.creation_time = "2024-01-10 08:00:00 UTC"
    mock_row_2.size_bytes = 536870912  # 512 MB
    mock_row_2.row_count = 50000
    mock_row_2.partition_expiration_days = None
    mock_row_2.time_partitioning_type = None
    mock_row_2.time_partitioning_field = None
    mock_row_2.clustering_fields = None

    mock_row_3 = Mock()
    mock_row_3.table_catalog = "my-project"
    mock_row_3.table_schema = "reporting"
    mock_row_3.table_name = "summary_view"
    mock_row_3.table_type = "VIEW"
    mock_row_3.creation_time = "2024-02-01 12:00:00 UTC"
    mock_row_3.size_bytes = None  # Views have no storage
    mock_row_3.row_count = None
    mock_row_3.partition_expiration_days = None
    mock_row_3.time_partitioning_type = None
    mock_row_3.time_partitioning_field = None
    mock_row_3.clustering_fields = None

    # Mock query result
    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_row_1, mock_row_2, mock_row_3]

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job

    # Call function
    tables = extract_table_metadata(mock_bq_client, "my-project")

    # Verify
    assert len(tables) == 3
    assert isinstance(tables[0], TableMetadata)

    # Verify partitioned + clustered table
    assert tables[0].table_name == "events"
    assert tables[0].table_catalog == "my-project"
    assert tables[0].table_schema == "analytics"
    assert tables[0].table_type == "TABLE"
    assert tables[0].creation_time == "2024-01-15 10:30:00 UTC"
    assert tables[0].size_bytes == 1073741824
    assert tables[0].row_count == 1000000
    assert tables[0].partition_expiration_days == 90
    assert tables[0].time_partitioning_type == "DAY"
    assert tables[0].time_partitioning_field == "event_date"
    assert tables[0].clustering_fields == ["user_id", "event_type"]

    # Verify non-partitioned table
    assert tables[1].table_name == "users"
    assert tables[1].size_bytes == 536870912
    assert tables[1].row_count == 50000
    assert tables[1].partition_expiration_days is None
    assert tables[1].time_partitioning_type is None
    assert tables[1].time_partitioning_field is None
    assert tables[1].clustering_fields is None

    # Verify view (no storage)
    assert tables[2].table_type == "VIEW"
    assert tables[2].table_name == "summary_view"
    assert tables[2].size_bytes is None
    assert tables[2].row_count is None


@patch("bqaudit.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_empty_project(mock_client):
    """Test extraction from project with 0 tables."""

    # Mock empty query result
    mock_query_job = Mock()
    mock_query_job.result.return_value = []

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job

    # Call function
    tables = extract_table_metadata(mock_bq_client, "empty-project")

    # Verify
    assert tables == []
    assert isinstance(tables, list)


@patch("bqaudit.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_api_error(mock_client):
    """Test BigQuery API error handling."""

    mock_bq_client = Mock()
    mock_bq_client.query.side_effect = GoogleAPIError("API quota exceeded")

    # Call function - should raise GoogleAPIError
    with pytest.raises(GoogleAPIError) as exc_info:
        extract_table_metadata(mock_bq_client, "my-project")

    assert "Failed to extract table metadata" in str(exc_info.value)
    assert "my-project" in str(exc_info.value)


@patch("bqaudit.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_pagination(mock_client):
    """Test extraction handles pagination for 100+ tables."""

    # Mock 150 tables (simulate pagination)
    mock_rows = []
    for i in range(150):
        mock_row = Mock()
        mock_row.table_catalog = "big-project"
        mock_row.table_schema = f"dataset_{i // 50}"
        mock_row.table_name = f"table_{i}"
        mock_row.table_type = "TABLE"
        mock_row.creation_time = "2024-01-01 00:00:00 UTC"
        mock_row.size_bytes = 1000000 * (i + 1)
        mock_row.row_count = 1000 * (i + 1)
        mock_row.partition_expiration_days = None
        mock_row.time_partitioning_type = None
        mock_row.time_partitioning_field = None
        mock_row.clustering_fields = None
        mock_rows.append(mock_row)

    # Mock query result with pagination
    mock_query_job = Mock()
    mock_query_job.result.return_value = mock_rows

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job

    # Call function
    tables = extract_table_metadata(mock_bq_client, "big-project")

    # Verify all 150 tables extracted
    assert len(tables) == 150
    assert all(isinstance(t, TableMetadata) for t in tables)
    # Verify first and last table
    assert tables[0].table_name == "table_0"
    assert tables[149].table_name == "table_149"


@patch("bqaudit.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_with_hour_partitioning(mock_client):
    """Test extraction of table with HOUR partitioning."""

    mock_row = Mock()
    mock_row.table_catalog = "my-project"
    mock_row.table_schema = "streaming"
    mock_row.table_name = "live_events"
    mock_row.table_type = "TABLE"
    mock_row.creation_time = "2024-01-20 14:30:00 UTC"
    mock_row.size_bytes = 2147483648  # 2 GB
    mock_row.row_count = 5000000
    mock_row.partition_expiration_days = 7
    mock_row.time_partitioning_type = "HOUR"
    mock_row.time_partitioning_field = "timestamp"
    mock_row.clustering_fields = ["event_id"]

    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_row]

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job

    # Call function
    tables = extract_table_metadata(mock_bq_client, "my-project")

    # Verify HOUR partitioning
    assert len(tables) == 1
    assert tables[0].time_partitioning_type == "HOUR"
    assert tables[0].time_partitioning_field == "timestamp"
    assert tables[0].partition_expiration_days == 7


@patch("bqaudit.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_clustered_only(mock_client):
    """Test extraction of table with clustering but no partitioning."""

    mock_row = Mock()
    mock_row.table_catalog = "my-project"
    mock_row.table_schema = "warehouse"
    mock_row.table_name = "products"
    mock_row.table_type = "TABLE"
    mock_row.creation_time = "2024-01-05 09:00:00 UTC"
    mock_row.size_bytes = 104857600  # 100 MB
    mock_row.row_count = 10000
    mock_row.partition_expiration_days = None
    mock_row.time_partitioning_type = None
    mock_row.time_partitioning_field = None
    mock_row.clustering_fields = ["category", "brand", "price"]

    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_row]

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job

    # Call function
    tables = extract_table_metadata(mock_bq_client, "my-project")

    # Verify clustering without partitioning
    assert len(tables) == 1
    assert tables[0].clustering_fields == ["category", "brand", "price"]
    assert tables[0].partition_expiration_days is None
    assert tables[0].time_partitioning_type is None


@patch("bqaudit.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_external_table(mock_client):
    """Test extraction of EXTERNAL table type."""

    mock_row = Mock()
    mock_row.table_catalog = "my-project"
    mock_row.table_schema = "external_data"
    mock_row.table_name = "gcs_data"
    mock_row.table_type = "EXTERNAL"
    mock_row.creation_time = "2024-02-10 11:00:00 UTC"
    mock_row.size_bytes = None  # External tables may not have size
    mock_row.row_count = None
    mock_row.partition_expiration_days = None
    mock_row.time_partitioning_type = None
    mock_row.time_partitioning_field = None
    mock_row.clustering_fields = None

    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_row]

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job

    # Call function
    tables = extract_table_metadata(mock_bq_client, "my-project")

    # Verify EXTERNAL table
    assert len(tables) == 1
    assert tables[0].table_type == "EXTERNAL"
    assert tables[0].size_bytes is None


def test_table_metadata_pydantic_validation():
    """Test that TableMetadata Pydantic validation works correctly."""

    # Valid table metadata
    valid_data = {
        "table_catalog": "test-project",
        "table_schema": "test_dataset",
        "table_name": "test_table",
        "table_type": "TABLE",
        "creation_time": "2024-01-01 00:00:00 UTC",
        "size_bytes": 1000,
        "row_count": 100,
        "partition_expiration_days": 30,
        "time_partitioning_type": "DAY",
        "time_partitioning_field": "date",
        "clustering_fields": ["field1", "field2"],
    }

    table = TableMetadata(**valid_data)
    assert table.table_name == "test_table"
    assert table.size_bytes == 1000
    assert table.clustering_fields == ["field1", "field2"]

    # Test with None optional fields
    minimal_data = {
        "table_catalog": "test-project",
        "table_schema": "test_dataset",
        "table_name": "test_view",
        "table_type": "VIEW",
        "creation_time": "2024-01-01 00:00:00 UTC",
    }

    view = TableMetadata(**minimal_data)
    assert view.table_type == "VIEW"
    assert view.size_bytes is None
    assert view.row_count is None
    assert view.clustering_fields is None

    # Test that required fields are enforced
    with pytest.raises(Exception):  # Pydantic validation error
        # Missing required fields
        TableMetadata(table_catalog="test", table_schema="test")


@patch("bqaudit.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_query_called(mock_client):
    """Test that BigQuery query is called with correct SQL."""

    mock_query_job = Mock()
    mock_query_job.result.return_value = []

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job

    # Call function
    extract_table_metadata(mock_bq_client, "test-project")

    # Verify query was called once
    mock_bq_client.query.assert_called_once()

    # Verify query contains INFORMATION_SCHEMA
    call_args = mock_bq_client.query.call_args
    query_sql = call_args[0][0]
    assert "INFORMATION_SCHEMA.TABLES" in query_sql
    assert "INFORMATION_SCHEMA.TABLE_STORAGE" in query_sql
    assert "test-project" in query_sql


def test_validate_project_id_valid():
    """Test that valid project IDs pass validation."""
    # Valid project IDs (6-30 characters)
    valid_ids = [
        "my-project",
        "test-123",
        "a-b-c-d",
        "project123",
        "my-gcp-project-2024",
        "abcdef",  # Minimum length (6 chars)
        "a" + "-" * 28 + "z",  # Maximum length (30 chars)
    ]

    for project_id in valid_ids:
        # Should not raise any exception
        _validate_project_id(project_id)


def test_validate_project_id_invalid():
    """Test that invalid project IDs raise ValueError."""
    invalid_ids = [
        "My-Project",  # Uppercase not allowed
        "project_name",  # Underscore not allowed
        "123-project",  # Cannot start with number
        "project-",  # Cannot end with hyphen
        "-project",  # Cannot start with hyphen
        "proj",  # Too short (< 6 chars)
        "a" * 31,  # Too long (> 30 chars)
        "project!123",  # Special characters not allowed
        "project name",  # Spaces not allowed
        "",  # Empty string
        "pro ject",  # Spaces in middle
        # SQL Injection attempts (security tests)
        "my-project'; DROP TABLE users--",  # SQL injection with semicolon
        "project` OR 1=1--",  # SQL injection with backtick
        "proj'; DELETE FROM *--",  # SQL injection DELETE
        'project"; SELECT * FROM secrets--',  # SQL injection with double quote
        "project/*comment*/",  # SQL comment injection
        "project\\'; DROP--",  # SQL injection with backslash escape
    ]

    for project_id in invalid_ids:
        with pytest.raises(ValueError) as exc_info:
            _validate_project_id(project_id)
        assert "Invalid project_id format" in str(exc_info.value)


@patch("bqaudit.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_invalid_project_id(mock_client):
    """Test that extract_table_metadata validates project_id."""
    mock_bq_client = Mock()

    # Call function with invalid project_id
    with pytest.raises(ValueError) as exc_info:
        extract_table_metadata(mock_bq_client, "INVALID-PROJECT")

    assert "Invalid project_id format" in str(exc_info.value)
    # Query should never be called due to validation failure
    mock_bq_client.query.assert_not_called()
