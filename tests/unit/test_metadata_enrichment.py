"""Tests for metadata enrichment functions."""

from unittest.mock import Mock

from bqcheck.scanner.anonymizer import merge_table_metadata
from bqcheck.scanner.metadata_extractor import extract_table_schemas
from bqcheck.scanner.models import AccessPattern, QueryMetadata, TableMetadata


def test_merge_table_metadata_basic():
    """Test basic metadata merging."""
    tables = [
        TableMetadata(
            table_catalog="project",
            table_schema="dataset",
            table_name="table1",
            table_type="TABLE",
            creation_time="2024-01-01T00:00:00Z",
            last_modified_time="2024-05-01T00:00:00Z",
            size_bytes=1000,
            row_count=100,
        )
    ]

    access_patterns = [
        AccessPattern(
            table_catalog="project",
            table_schema="dataset",
            table_name="table1",
            last_access_time="2024-06-01T00:00:00Z",
        )
    ]

    queries = [
        QueryMetadata(
            job_id="job1",
            query="SELECT * FROM `dataset.table1`",
            total_bytes_processed=5000,
            creation_time="2024-01-01T00:00:00Z",
            job_type="QUERY",
            state="DONE",
        )
    ]

    schemas = {"dataset.table1": [{"name": "col1", "type": "STRING"}]}

    result = merge_table_metadata(tables, access_patterns, queries, schemas)

    assert len(result) == 1
    assert result[0]["table_id"] == "dataset.table1"
    assert result[0]["last_access_time"] == "2024-06-01T00:00:00Z"
    assert result[0]["last_access_time_source"] == "TABLE_STORAGE_TIMELINE"
    assert result[0]["last_modified_time"] == "2024-05-01T00:00:00Z"
    assert result[0]["last_modified_time_source"] == "__TABLES__"
    assert result[0]["schema"] == [{"name": "col1", "type": "STRING"}]
    assert result[0]["query_stats"]["total_bytes_processed"] == 5000
    assert result[0]["query_stats"]["query_count"] == 1
    assert result[0]["query_stats"]["query_days_in_period"] == 1.0
    assert result[0]["query_stats"]["query_distinct_days"] == 1


def test_merge_table_metadata_tracks_query_activity_window():
    """Query stats include the observed activity window for better savings estimates."""
    tables = [
        TableMetadata(
            table_catalog="project",
            table_schema="dataset",
            table_name="table1",
            table_type="TABLE",
            creation_time="2024-01-01T00:00:00Z",
            size_bytes=1000,
            row_count=100,
        )
    ]

    queries = [
        QueryMetadata(
            job_id="job1",
            query="SELECT * FROM `dataset.table1`",
            total_bytes_processed=5000,
            creation_time="2024-01-01 00:00:00 UTC",
            job_type="QUERY",
            state="DONE",
        ),
        QueryMetadata(
            job_id="job2",
            query="SELECT * FROM `dataset.table1`",
            total_bytes_processed=5000,
            creation_time="2024-01-31 00:00:00 UTC",
            job_type="QUERY",
            state="DONE",
        ),
    ]

    result = merge_table_metadata(tables, [], queries, {})

    assert result[0]["query_stats"]["query_count"] == 2
    assert result[0]["query_stats"]["query_days_in_period"] == 30.0
    assert result[0]["query_stats"]["query_distinct_days"] == 2
    assert result[0]["query_stats"]["recent_query_count"] == 0
    assert result[0]["query_stats"]["last_query_time"] == "2024-01-31T00:00:00"


def test_merge_table_metadata_uses_referenced_tables_for_fully_qualified_queries():
    """Fully-qualified refs should still enrich the matching dataset.table entry."""
    tables = [
        TableMetadata(
            table_catalog="project",
            table_schema="mobility",
            table_name="locations",
            table_type="TABLE",
            creation_time="2024-01-01T00:00:00Z",
            size_bytes=1000,
            row_count=100,
        )
    ]

    queries = [
        QueryMetadata(
            job_id="job1",
            query="SELECT * FROM `roam-prod-dt-cur-0.mobility.locations`",
            total_bytes_processed=5000,
            creation_time="2024-01-01 00:00:00 UTC",
            job_type="QUERY",
            state="DONE",
            referenced_tables=["mobility.locations"],
        )
    ]

    result = merge_table_metadata(tables, [], queries, {})

    assert result[0]["query_stats"]["query_count"] == 1
    assert result[0]["query_stats"]["total_bytes_processed"] == 5000


def test_merge_table_metadata_marks_limited_query_observation():
    """Tables should carry the truncated-query-window signal to the server."""
    tables = [
        TableMetadata(
            table_catalog="project",
            table_schema="dataset",
            table_name="table1",
            table_type="TABLE",
            creation_time="2024-01-01T00:00:00Z",
            size_bytes=1000,
            row_count=100,
        )
    ]

    result = merge_table_metadata(
        tables,
        [],
        [],
        {},
        query_observation_limited=True,
    )

    assert result[0]["query_stats"]["observation_limited"] is True


def test_merge_table_metadata_no_access_pattern():
    """Test merging when access pattern is missing."""
    tables = [
        TableMetadata(
            table_catalog="project",
            table_schema="dataset",
            table_name="table1",
            table_type="TABLE",
            creation_time="2024-01-01T00:00:00Z",
            size_bytes=1000,
            row_count=100,
        )
    ]

    result = merge_table_metadata(tables, [], [], {})

    assert len(result) == 1
    assert "last_modified_time" not in result[0]
    assert "last_access_time" not in result[0]
    assert result[0]["schema"] == []
    assert result[0]["query_stats"] == {
        "total_bytes_processed": 0,
        "query_count": 0,
        "observation_limited": False,
    }


def test_merge_table_metadata_detects_date_sharded_table_groups():
    """Daily shard families are summarized for server-side recommendations."""
    tables = [
        TableMetadata(
            table_catalog="project",
            table_schema="dataset",
            table_name=f"events_2024010{i}",
            table_type="TABLE",
            creation_time="2024-01-01T00:00:00Z",
            size_bytes=2 * 1024**3,
            row_count=100,
        )
        for i in range(1, 8)
    ]

    queries = [
        QueryMetadata(
            job_id="job1",
            query="SELECT * FROM `dataset.events_20240101`",
            total_bytes_processed=5 * 1024**3,
            creation_time="2024-01-01 00:00:00 UTC",
            job_type="QUERY",
            state="DONE",
        ),
        QueryMetadata(
            job_id="job2",
            query=(
                "SELECT * FROM `dataset.events_20240101` "
                "UNION ALL SELECT * FROM `dataset.events_20240102`"
            ),
            total_bytes_processed=5 * 1024**3,
            creation_time="2024-01-02 00:00:00 UTC",
            job_type="QUERY",
            state="DONE",
        ),
    ]

    result = merge_table_metadata(tables, [], queries, {})

    assert all(table["is_date_sharded"] for table in result)
    assert all(table["shard_group_table_count"] == 7 for table in result)
    assert all(
        table["shard_group_total_size_bytes"] == 14 * 1024**3 for table in result
    )
    assert result[0]["shard_group_query_stats"]["query_count"] == 2
    assert result[0]["shard_group_query_stats"]["query_days_in_period"] == 1.0


def test_extract_table_schemas_mock():
    """Test schema extraction with mocked client."""
    mock_client = Mock()
    mock_client.list_datasets.return_value = []
    mock_query_job = Mock()
    mock_query_job.result.return_value = []
    mock_client.query.return_value = mock_query_job

    result = extract_table_schemas(mock_client, "test-project")

    assert isinstance(result, dict)
    assert len(result) == 0
