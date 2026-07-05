"""Unit tests for BigQuery metadata extraction."""

from unittest.mock import Mock, patch

import pytest
from google.api_core.exceptions import GoogleAPIError

from bqcheck.scanner.metadata_extractor import (
    _extract_materialized_view_query_from_ddl,
    _parse_partitioning_from_ddl,
    _validate_project_id,
    extract_access_patterns,
    extract_materialized_view_definitions,
    extract_query_metadata,
    extract_table_metadata,
)
from bqcheck.scanner.models import AccessPattern, QueryMetadata, TableMetadata


def _setup_dataset_mocks(mock_client, datasets=None):
    """Helper to setup list_datasets and get_dataset mocks.

    Args:
        mock_client: Mock BigQuery client
        datasets: List of (dataset_id, location) tuples. Default: [("analytics", "EU")]
    """
    if datasets is None:
        datasets = [("analytics", "EU")]

    # Mock datasets
    mock_datasets = []
    for dataset_id, _ in datasets:
        mock_dataset = Mock()
        mock_dataset.dataset_id = dataset_id
        mock_datasets.append(mock_dataset)

    mock_client.list_datasets.return_value = mock_datasets

    # Mock get_dataset to return location
    def get_dataset_side_effect(dataset_ref):
        dataset_id = dataset_ref.split(".")[-1] if "." in dataset_ref else dataset_ref
        for ds_id, location in datasets:
            if ds_id == dataset_id:
                mock_dataset_ref = Mock()
                mock_dataset_ref.location = location
                return mock_dataset_ref
        raise ValueError(f"Dataset {dataset_id} not found")

    mock_client.get_dataset.side_effect = get_dataset_side_effect


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_success(mock_client):
    """Test successful extraction of table metadata with various table types."""

    # Mock BigQuery query response with 3 tables
    mock_row_1 = Mock()
    mock_row_1.ddl = ""
    mock_row_1.table_catalog = "my-project"
    mock_row_1.table_schema = "analytics"
    mock_row_1.table_name = "events"
    mock_row_1.table_type = "TABLE"
    mock_row_1.creation_time = "2024-01-15 10:30:00 UTC"
    mock_row_1.last_modified_time = "2024-06-15 10:30:00 UTC"
    mock_row_1.size_bytes = 1073741824  # 1 GB
    mock_row_1.row_count = 1000000
    mock_row_1.partition_expiration_days = 90
    mock_row_1.time_partitioning_type = "DAY"
    mock_row_1.time_partitioning_field = "event_date"
    mock_row_1.clustering_fields = ["user_id", "event_type"]

    mock_row_2 = Mock()
    mock_row_2.ddl = ""
    mock_row_2.table_catalog = "my-project"
    mock_row_2.table_schema = "analytics"
    mock_row_2.table_name = "users"
    mock_row_2.table_type = "TABLE"
    mock_row_2.creation_time = "2024-01-10 08:00:00 UTC"
    mock_row_2.last_modified_time = "2024-06-10 08:00:00 UTC"
    mock_row_2.size_bytes = 536870912  # 512 MB
    mock_row_2.row_count = 50000
    mock_row_2.partition_expiration_days = None
    mock_row_2.time_partitioning_type = None
    mock_row_2.time_partitioning_field = None
    mock_row_2.clustering_fields = None

    mock_row_3 = Mock()
    mock_row_3.ddl = ""
    mock_row_3.table_catalog = "my-project"
    mock_row_3.table_schema = "reporting"
    mock_row_3.table_name = "summary_view"
    mock_row_3.table_type = "VIEW"
    mock_row_3.creation_time = "2024-02-01 12:00:00 UTC"
    mock_row_3.last_modified_time = None
    mock_row_3.size_bytes = None  # Views have no storage
    mock_row_3.row_count = None
    mock_row_3.partition_expiration_days = None
    mock_row_3.time_partitioning_type = None
    mock_row_3.time_partitioning_field = None
    mock_row_3.clustering_fields = None

    # Mock last-modified metatable result, then main INFORMATION_SCHEMA result.
    modified_row_1 = Mock()
    modified_row_1.table_id = "events"
    modified_row_1.last_modified_time = "2024-06-15 10:30:00 UTC"
    modified_row_2 = Mock()
    modified_row_2.table_id = "users"
    modified_row_2.last_modified_time = "2024-06-10 08:00:00 UTC"

    mock_modified_query_job = Mock()
    mock_modified_query_job.result.return_value = [modified_row_1, modified_row_2]

    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_row_1, mock_row_2, mock_row_3]

    mock_bq_client = Mock()
    mock_bq_client.query.side_effect = [mock_modified_query_job, mock_query_job]
    _setup_dataset_mocks(mock_bq_client)

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
    assert tables[0].last_modified_time == "2024-06-15 10:30:00 UTC"
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


def test_parse_partitioning_from_ddl_supports_date_trunc_month():
    """DATE_TRUNC partition expressions should expose the underlying field."""
    ddl = """
    CREATE TABLE foo.bar
    PARTITION BY DATE_TRUNC(event_month, MONTH)
    AS SELECT 1
    """

    parsed = _parse_partitioning_from_ddl(ddl)

    assert parsed["type"] == "MONTH"
    assert parsed["field"] == "event_month"


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_empty_project(mock_client):
    """Test extraction from project with 0 tables."""

    # Mock empty query result
    mock_query_job = Mock()
    mock_query_job.result.return_value = []

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client, datasets=[])

    # Call function
    tables = extract_table_metadata(mock_bq_client, "empty-project")

    # Verify
    assert tables == []
    assert isinstance(tables, list)


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_api_error(mock_client):
    """Test BigQuery API error handling."""

    mock_bq_client = Mock()
    mock_bq_client.list_datasets.side_effect = GoogleAPIError("API quota exceeded")

    # Call function - should raise GoogleAPIError
    with pytest.raises(GoogleAPIError) as exc_info:
        extract_table_metadata(mock_bq_client, "my-project")

    assert "Failed to extract table metadata" in str(exc_info.value)
    # Code Review Round 8, Issue #4: project_id removed from error to prevent info disclosure


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_pagination(mock_client):
    """Test extraction handles pagination for 100+ tables."""

    # Mock 150 tables (simulate pagination)
    mock_rows = []
    for i in range(150):
        mock_row = Mock()
        mock_row.ddl = ""
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
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    tables = extract_table_metadata(mock_bq_client, "big-project")

    # Verify all 150 tables extracted
    assert len(tables) == 150
    assert all(isinstance(t, TableMetadata) for t in tables)
    # Verify tables are sorted by size (largest first)
    assert tables[0].table_name == "table_149"  # Largest (150MB)
    assert tables[149].table_name == "table_0"  # Smallest (1MB)


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_with_hour_partitioning(mock_client):
    """Test extraction of table with HOUR partitioning."""

    mock_row = Mock()
    mock_row.ddl = ""
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
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    tables = extract_table_metadata(mock_bq_client, "my-project")

    # Verify HOUR partitioning
    assert len(tables) == 1
    assert tables[0].time_partitioning_type == "HOUR"
    assert tables[0].time_partitioning_field == "timestamp"
    assert tables[0].partition_expiration_days == 7


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_clustered_only(mock_client):
    """Test extraction of table with clustering but no partitioning."""

    mock_row = Mock()
    mock_row.ddl = ""
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
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    tables = extract_table_metadata(mock_bq_client, "my-project")

    # Verify clustering without partitioning
    assert len(tables) == 1
    assert tables[0].clustering_fields == ["category", "brand", "price"]
    assert tables[0].partition_expiration_days is None
    assert tables[0].time_partitioning_type is None


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_external_table(mock_client):
    """Test extraction of EXTERNAL table type."""

    mock_row = Mock()
    mock_row.ddl = ""
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
    _setup_dataset_mocks(mock_bq_client)

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


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_query_called(mock_client):
    """Test that BigQuery query is called with correct SQL."""

    mock_query_job = Mock()
    mock_query_job.result.return_value = []

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    extract_table_metadata(mock_bq_client, "test-project")

    # Verify the table metadata query was called after the dataset metatable lookup.
    assert mock_bq_client.query.call_count == 2

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


def test_extract_materialized_view_query_from_ddl():
    """Extract the SELECT body from materialized view DDL."""
    ddl = """
    CREATE MATERIALIZED VIEW `my-project.reporting.mv_daily_events`
    AS
    SELECT event_date, COUNT(*) AS total_events
    FROM `my-project.analytics.events`
    GROUP BY event_date;
    """

    result = _extract_materialized_view_query_from_ddl(ddl)

    assert result is not None
    assert result.startswith("SELECT event_date")
    assert "CREATE MATERIALIZED VIEW" not in result


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_materialized_view_definitions(mock_client):
    """Materialized view definitions are extracted from INFORMATION_SCHEMA."""
    mock_row = Mock()
    mock_row.ddl = """
    CREATE MATERIALIZED VIEW `my-project.reporting.mv_daily_events`
    AS
    SELECT event_date, COUNT(*) AS total_events
    FROM `my-project.analytics.events`
    GROUP BY event_date
    """

    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_row]

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    result = extract_materialized_view_definitions(mock_bq_client, "my-project")

    assert result == [
        "SELECT event_date, COUNT(*) AS total_events\n"
        "    FROM `my-project.analytics.events`\n"
        "    GROUP BY event_date"
    ]


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_table_metadata_invalid_project_id(mock_client):
    """Test that extract_table_metadata validates project_id."""
    mock_bq_client = Mock()

    # Call function with invalid project_id
    with pytest.raises(ValueError) as exc_info:
        extract_table_metadata(mock_bq_client, "INVALID-PROJECT")

    assert "Invalid project_id format" in str(exc_info.value)
    # Query should never be called due to validation failure
    mock_bq_client.query.assert_not_called()


def test_query_metadata_pydantic_validation():
    """Test that QueryMetadata Pydantic validation works correctly."""

    # Valid query metadata
    valid_data = {
        "job_id": "project:location.job_abc123",
        "query": "SELECT * FROM dataset.table WHERE date = '2024-01-01'",
        "total_bytes_processed": 1073741824,  # 1 GB
        "creation_time": "2024-01-20 10:30:00 UTC",
        "user_email": "user@example.com",
        "job_type": "QUERY",
        "state": "DONE",
    }

    query = QueryMetadata(**valid_data)
    assert query.job_id == "project:location.job_abc123"
    assert query.total_bytes_processed == 1073741824
    assert query.job_type == "QUERY"
    assert query.state == "DONE"

    # Test with None optional fields
    minimal_data = {
        "job_id": "project:location.job_xyz789",
        "query": "SELECT COUNT(*) FROM dataset.table",
        "total_bytes_processed": 0,  # Cached query
        "creation_time": "2024-01-21 12:00:00 UTC",
        "user_email": None,  # Service account or anonymous
        "job_type": "QUERY",
        "state": "DONE",
    }

    query_min = QueryMetadata(**minimal_data)
    assert query_min.user_email is None
    assert query_min.total_bytes_processed == 0

    # Test that required fields are enforced
    with pytest.raises(Exception):  # Pydantic validation error
        # Missing required fields
        QueryMetadata(job_id="test", query="SELECT 1")


def test_access_pattern_pydantic_validation():
    """Test that AccessPattern Pydantic validation works correctly."""

    # Valid access pattern
    valid_data = {
        "table_catalog": "test-project",
        "table_schema": "analytics",
        "table_name": "events",
        "last_access_time": "2024-01-15 08:30:00 UTC",
    }

    pattern = AccessPattern(**valid_data)
    assert pattern.table_catalog == "test-project"
    assert pattern.table_schema == "analytics"
    assert pattern.table_name == "events"
    assert pattern.last_access_time == "2024-01-15 08:30:00 UTC"

    # Test that required fields are enforced
    with pytest.raises(Exception):  # Pydantic validation error
        # Missing required fields
        AccessPattern(table_catalog="test", table_schema="test")


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_success(mock_client):
    """Test successful extraction of query metadata with filtering."""

    # Mock BigQuery query response with 5 sample queries
    mock_row_1 = Mock()
    mock_row_1.ddl = ""
    mock_row_1.job_id = "my-project:us.job_abc123"
    mock_row_1.query = "SELECT * FROM analytics.events WHERE date = '2024-01-20'"
    mock_row_1.total_bytes_processed = 1073741824  # 1 GB
    mock_row_1.creation_time = "2024-01-20 10:30:00 UTC"
    mock_row_1.user_email = "user@example.com"
    mock_row_1.job_type = "QUERY"
    mock_row_1.state = "DONE"
    mock_row_1.referenced_tables = [{"dataset_id": "analytics", "table_id": "events"}]

    mock_row_2 = Mock()
    mock_row_2.ddl = ""
    mock_row_2.job_id = "my-project:us.job_def456"
    mock_row_2.query = "SELECT COUNT(*) FROM analytics.users"
    mock_row_2.total_bytes_processed = 536870912  # 512 MB
    mock_row_2.creation_time = "2024-01-19 14:00:00 UTC"
    mock_row_2.user_email = None  # Service account
    mock_row_2.job_type = "QUERY"
    mock_row_2.state = "DONE"
    mock_row_2.referenced_tables = [{"dataset_id": "analytics", "table_id": "users"}]

    mock_row_3 = Mock()
    mock_row_3.ddl = ""
    mock_row_3.job_id = "my-project:us.job_ghi789"
    mock_row_3.query = "SELECT AVG(amount) FROM sales.transactions"
    mock_row_3.total_bytes_processed = 268435456  # 256 MB
    mock_row_3.creation_time = "2024-01-18 09:00:00 UTC"
    mock_row_3.user_email = "analyst@example.com"
    mock_row_3.job_type = "QUERY"
    mock_row_3.state = "DONE"
    mock_row_3.referenced_tables = [{"dataset_id": "sales", "table_id": "transactions"}]

    # Mock query result
    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_row_1, mock_row_2, mock_row_3]

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    queries = extract_query_metadata(mock_bq_client, "my-project", days=30)

    # Verify
    assert len(queries) == 3
    assert isinstance(queries[0], QueryMetadata)

    # Verify first query (most expensive)
    assert queries[0].job_id == "my-project:us.job_abc123"
    assert queries[0].total_bytes_processed == 1073741824
    assert queries[0].job_type == "QUERY"
    assert queries[0].state == "DONE"
    assert queries[0].user_email == "user@example.com"

    # Verify second query (no user_email)
    assert queries[1].user_email is None

    # Verify query was called
    mock_bq_client.query.assert_called_once()


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_aggregates_multiple_locations(mock_client):
    """Queries from multiple regions should be combined deterministically."""
    eu_row = Mock()
    eu_row.job_id = "job_eu"
    eu_row.query = "SELECT * FROM eu.table"
    eu_row.total_bytes_processed = 200
    eu_row.creation_time = "2024-01-20 10:30:00 UTC"
    eu_row.user_email = "user@example.com"
    eu_row.job_type = "QUERY"
    eu_row.state = "DONE"
    eu_row.referenced_tables = [{"dataset_id": "eu", "table_id": "table"}]

    us_row = Mock()
    us_row.job_id = "job_us"
    us_row.query = "SELECT * FROM us.table"
    us_row.total_bytes_processed = 100
    us_row.creation_time = "2024-01-19 10:30:00 UTC"
    us_row.user_email = "user@example.com"
    us_row.job_type = "QUERY"
    us_row.state = "DONE"
    us_row.referenced_tables = [{"dataset_id": "us", "table_id": "table"}]

    eu_job = Mock()
    eu_job.result.return_value = [eu_row]
    us_job = Mock()
    us_job.result.return_value = [us_row]

    mock_bq_client = Mock()
    mock_bq_client.query.side_effect = [eu_job, us_job]
    _setup_dataset_mocks(
        mock_bq_client,
        datasets=[("analytics_eu", "EU"), ("analytics_us", "US")],
    )

    queries = extract_query_metadata(mock_bq_client, "my-project", days=30)

    assert len(queries) == 2
    assert queries[0].job_id == "my-project:EU.job_eu"
    assert queries[1].job_id == "my-project:US.job_us"
    assert mock_bq_client.query.call_count == 2


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_job_id_format_handling(mock_client):
    """Test that job_id is correctly formatted regardless of input format."""

    # Test with short format job_id (should be prefixed)
    mock_row_short = Mock()
    mock_row_short.ddl = ""
    mock_row_short.job_id = "bquxjob_abc123"  # Short format
    mock_row_short.query = "SELECT 1"
    mock_row_short.total_bytes_processed = 1073741824
    mock_row_short.creation_time = "2024-01-20 10:30:00 UTC"
    mock_row_short.user_email = "user@example.com"
    mock_row_short.job_type = "QUERY"
    mock_row_short.state = "DONE"
    mock_row_short.referenced_tables = []

    # Test with full format job_id (should be kept as-is)
    mock_row_full = Mock()
    mock_row_full.ddl = ""
    mock_row_full.job_id = "my-project:EU.script_job_def456"  # Full format
    mock_row_full.query = "SELECT 2"
    mock_row_full.total_bytes_processed = 1073741824
    mock_row_full.creation_time = "2024-01-20 10:30:00 UTC"
    mock_row_full.user_email = "user@example.com"
    mock_row_full.job_type = "QUERY"
    mock_row_full.state = "DONE"
    mock_row_full.referenced_tables = []

    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_row_short, mock_row_full]

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    queries = extract_query_metadata(mock_bq_client, "my-project", days=30)

    assert len(queries) == 2

    # Short format should be prefixed with project:location.
    assert queries[0].job_id == "my-project:EU.bquxjob_abc123"

    # Full format should be kept as-is
    assert queries[1].job_id == "my-project:EU.script_job_def456"


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_job_type_filter(mock_client):
    """Test that extract_query_metadata filters to job_type='QUERY' only."""

    # Mock response with mixed job types (should only return QUERY jobs)
    mock_query_row = Mock()
    mock_query_row.job_id = "my-project:us.job_query1"
    mock_query_row.query = "SELECT * FROM dataset.table"
    mock_query_row.total_bytes_processed = 1000000
    mock_query_row.creation_time = "2024-01-20 10:00:00 UTC"
    mock_query_row.user_email = "user@example.com"
    mock_query_row.job_type = "QUERY"
    mock_query_row.state = "DONE"
    mock_query_row.referenced_tables = [{"dataset_id": "dataset", "table_id": "table"}]

    # These should be filtered out by SQL WHERE clause
    # (we verify the SQL query excludes them, not that we filter in Python)

    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_query_row]

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    queries = extract_query_metadata(mock_bq_client, "my-project")

    # Verify SQL query contains job_type filter
    call_args = mock_bq_client.query.call_args
    query_sql = call_args[0][0]
    assert "job_type = 'QUERY'" in query_sql or "job_type='QUERY'" in query_sql
    assert "state = 'DONE'" in query_sql or "state='DONE'" in query_sql

    # Verify only QUERY jobs returned
    assert len(queries) == 1
    assert queries[0].job_type == "QUERY"


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_days_parameter(mock_client):
    """Test that days parameter affects SQL WHERE clause."""

    mock_query_job = Mock()
    mock_query_job.result.return_value = []

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    # Call with days=7
    extract_query_metadata(mock_bq_client, "my-project", days=7)

    call_args = mock_bq_client.query.call_args
    query_sql = call_args[0][0]
    assert "INTERVAL 7 DAY" in query_sql

    # Call with days=90
    mock_bq_client.reset_mock()
    extract_query_metadata(mock_bq_client, "my-project", days=90)

    call_args = mock_bq_client.query.call_args
    query_sql = call_args[0][0]
    assert "INTERVAL 90 DAY" in query_sql


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_limit_clause(mock_client):
    """Test that max_queries parameter adds LIMIT clause."""

    mock_query_job = Mock()
    mock_query_job.result.return_value = []

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    # Call with default max_queries (10000)
    extract_query_metadata(mock_bq_client, "my-project", max_queries=10000)

    call_args = mock_bq_client.query.call_args
    query_sql = call_args[0][0]
    assert "LIMIT 10000" in query_sql or "LIMIT\n    10000" in query_sql


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_null_query_handling(mock_client):
    """Test that NULL query field is filtered out."""

    # Mock empty query result (queries with NULL query field should be filtered)
    mock_query_job = Mock()
    mock_query_job.result.return_value = []

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    queries = extract_query_metadata(mock_bq_client, "my-project")

    # Verify SQL includes NULL filter
    call_args = mock_bq_client.query.call_args
    query_sql = call_args[0][0]
    assert "query IS NOT NULL" in query_sql

    # Verify empty result (NULL queries filtered out)
    assert queries == []


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_empty_project(mock_client):
    """Test extraction from project with 0 queries."""

    # Mock empty query result
    mock_query_job = Mock()
    mock_query_job.result.return_value = []

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    queries = extract_query_metadata(mock_bq_client, "empty-project")

    # Verify
    assert queries == []
    assert isinstance(queries, list)


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_invalid_project_id(mock_client):
    """Test that extract_query_metadata validates project_id."""
    mock_bq_client = Mock()

    # Call function with invalid project_id
    with pytest.raises(ValueError) as exc_info:
        extract_query_metadata(mock_bq_client, "INVALID-PROJECT")

    assert "Invalid project_id format" in str(exc_info.value)
    # Query should never be called due to validation failure
    mock_bq_client.query.assert_not_called()


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_query_metadata_api_error(mock_client):
    """Test BigQuery API error handling for query extraction returns empty list."""

    mock_bq_client = Mock()
    # Set up error for both list_datasets and query
    api_error = GoogleAPIError("API quota exceeded")
    mock_bq_client.list_datasets.side_effect = api_error
    mock_bq_client.query.side_effect = api_error

    # Call function - should return empty list and log warning
    result = extract_query_metadata(mock_bq_client, "my-project")

    assert result == []


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_access_patterns_success(mock_client):
    """Test successful extraction of access patterns."""

    # Mock BigQuery query response with 3 sample tables
    mock_row_1 = Mock()
    mock_row_1.ddl = ""
    mock_row_1.table_catalog = "my-project"
    mock_row_1.table_schema = "analytics"
    mock_row_1.table_name = "old_events"
    mock_row_1.last_access_time = "2023-06-15 08:30:00 UTC"  # Very old

    mock_row_2 = Mock()
    mock_row_2.ddl = ""
    mock_row_2.table_catalog = "my-project"
    mock_row_2.table_schema = "analytics"
    mock_row_2.table_name = "recent_users"
    mock_row_2.last_access_time = "2024-01-20 14:00:00 UTC"  # Recent

    mock_row_3 = Mock()
    mock_row_3.ddl = ""
    mock_row_3.table_catalog = "my-project"
    mock_row_3.table_schema = "warehouse"
    mock_row_3.table_name = "products"
    mock_row_3.last_access_time = "2024-01-10 10:00:00 UTC"  # Older

    # Mock query result
    mock_query_job = Mock()
    mock_query_job.result.return_value = [mock_row_1, mock_row_2, mock_row_3]

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    patterns = extract_access_patterns(mock_bq_client, "my-project")

    # Verify
    assert len(patterns) == 3
    assert isinstance(patterns[0], AccessPattern)

    # Verify first table (oldest - unused)
    assert patterns[0].table_name == "old_events"
    assert patterns[0].last_access_time == "2023-06-15 08:30:00 UTC"

    # Verify query was called
    mock_bq_client.query.assert_called_once()

    # Verify ORDER BY clause for oldest-first sorting
    call_args = mock_bq_client.query.call_args
    query_sql = call_args[0][0]
    assert "ORDER BY" in query_sql
    assert "project_id as table_catalog" in query_sql
    assert "last_access_time" in query_sql
    # Verify ASC ordering (oldest first to identify unused tables)
    assert "ASC" in query_sql or "last_access_time\n" in query_sql
    assert "LIMIT 10000" in query_sql


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_access_patterns_aggregates_multiple_locations(mock_client):
    """Access patterns from multiple regions should be merged and sorted."""
    eu_row = Mock()
    eu_row.table_catalog = "my-project"
    eu_row.table_schema = "eu"
    eu_row.table_name = "older_table"
    eu_row.last_access_time = "2024-01-01 00:00:00 UTC"

    us_row = Mock()
    us_row.table_catalog = "my-project"
    us_row.table_schema = "us"
    us_row.table_name = "newer_table"
    us_row.last_access_time = "2024-01-02 00:00:00 UTC"

    eu_job = Mock()
    eu_job.result.return_value = [eu_row]
    us_job = Mock()
    us_job.result.return_value = [us_row]

    mock_bq_client = Mock()
    mock_bq_client.query.side_effect = [eu_job, us_job]
    _setup_dataset_mocks(
        mock_bq_client,
        datasets=[("analytics_eu", "EU"), ("analytics_us", "US")],
    )

    patterns = extract_access_patterns(mock_bq_client, "my-project")

    assert len(patterns) == 2
    assert patterns[0].table_name == "older_table"
    assert patterns[1].table_name == "newer_table"
    assert mock_bq_client.query.call_count == 2


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_access_patterns_empty_project(mock_client):
    """Test extraction from project with no access data."""

    # Mock empty query result
    mock_query_job = Mock()
    mock_query_job.result.return_value = []

    mock_bq_client = Mock()
    mock_bq_client.query.return_value = mock_query_job
    _setup_dataset_mocks(mock_bq_client)

    # Call function
    patterns = extract_access_patterns(mock_bq_client, "empty-project")

    # Verify
    assert patterns == []
    assert isinstance(patterns, list)


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_access_patterns_invalid_project_id(mock_client):
    """Test that extract_access_patterns validates project_id."""
    mock_bq_client = Mock()

    # Call function with invalid project_id
    with pytest.raises(ValueError) as exc_info:
        extract_access_patterns(mock_bq_client, "INVALID-PROJECT")

    assert "Invalid project_id format" in str(exc_info.value)
    # Query should never be called due to validation failure
    mock_bq_client.query.assert_not_called()


@patch("bqcheck.scanner.metadata_extractor.bigquery.Client")
def test_extract_access_patterns_api_error(mock_client):
    """Test BigQuery API error handling for access pattern extraction returns empty list."""

    mock_bq_client = Mock()
    # Set up error for both list_datasets and query
    api_error = GoogleAPIError("API quota exceeded")
    mock_bq_client.list_datasets.side_effect = api_error
    mock_bq_client.query.side_effect = api_error

    # Call function - should return empty list and log warning
    result = extract_access_patterns(mock_bq_client, "my-project")

    assert result == []
