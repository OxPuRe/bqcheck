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
            size_bytes=1000,
            row_count=100,
        )
    ]

    access_patterns = [
        AccessPattern(
            table_catalog="project",
            table_schema="dataset",
            table_name="table1",
            last_modified_time="2024-06-01T00:00:00Z",
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
    assert result[0]["last_modified_time"] == "2024-06-01T00:00:00Z"
    assert result[0]["schema"] == [{"name": "col1", "type": "STRING"}]
    assert result[0]["query_stats"]["total_bytes_processed"] == 5000
    assert result[0]["query_stats"]["query_count"] == 1


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
    assert result[0]["last_modified_time"] == "2024-01-01T00:00:00Z"
    assert result[0]["schema"] == []
    assert result[0]["query_stats"] == {"total_bytes_processed": 0, "query_count": 0}


def test_extract_table_schemas_mock():
    """Test schema extraction with mocked client."""
    mock_client = Mock()
    mock_client.list_datasets.return_value = []

    result = extract_table_schemas(mock_client, "test-project")

    assert isinstance(result, dict)
    assert len(result) == 0
