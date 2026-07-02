"""Tests for query aggregation module.

This module tests the query aggregation logic that transforms raw query metadata
into aggregated statistics required by server detection algorithms.
"""

import pytest

from bqcheck.scanner.aggregator import (
    _calculate_days_in_period,
    _parse_iso_timestamp,
    aggregate_query_metadata,
)
from bqcheck.scanner.encryption import IdentifierEncryptor
from bqcheck.scanner.models import QueryMetadata


class TestTimestampParsing:
    """Test suite for timestamp parsing functions."""

    def test_parse_iso_timestamp_standard_format(self):
        """Test parsing standard BigQuery timestamp format."""
        timestamp = "2024-01-20 10:30:00 UTC"
        dt = _parse_iso_timestamp(timestamp)
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 20
        assert dt.hour == 10
        assert dt.minute == 30
        assert dt.second == 0

    def test_parse_iso_timestamp_with_microseconds(self):
        """Test parsing timestamp with microseconds."""
        timestamp = "2024-01-20 10:30:00.123456 UTC"
        dt = _parse_iso_timestamp(timestamp)
        assert dt.year == 2024
        assert dt.microsecond == 123456

    def test_parse_iso_timestamp_bigquery_format_with_offset(self):
        """Test parsing BigQuery format with timezone offset (+00)."""
        timestamp = "2025-12-15 15:06:24.456+00"
        dt = _parse_iso_timestamp(timestamp)
        assert dt.year == 2025
        assert dt.month == 12
        assert dt.day == 15
        assert dt.hour == 15
        assert dt.minute == 6
        assert dt.second == 24
        assert dt.microsecond == 456000

    def test_parse_iso_timestamp_bigquery_format_without_microseconds(self):
        """Test parsing BigQuery format without microseconds."""
        timestamp = "2025-12-15 15:06:24+00"
        dt = _parse_iso_timestamp(timestamp)
        assert dt.year == 2025
        assert dt.month == 12
        assert dt.day == 15

    def test_parse_iso_timestamp_invalid_format(self):
        """Test that invalid timestamp format raises ValueError."""
        with pytest.raises(ValueError, match="Unable to parse timestamp"):
            _parse_iso_timestamp("invalid-timestamp")


class TestDaysInPeriodCalculation:
    """Test suite for calculating days in scan period."""

    def test_calculate_days_same_day(self):
        """Test calculation for queries on the same day returns minimum 1.0."""
        timestamps = [
            "2024-01-20 10:00:00 UTC",
            "2024-01-20 11:00:00 UTC",
            "2024-01-20 12:00:00 UTC",
        ]
        days = _calculate_days_in_period(timestamps)
        # Same day = 2 hours / 24 = 0.083 days, but minimum is 1.0 to avoid division by zero
        assert days == 1.0

    def test_calculate_days_multiple_days(self):
        """Test calculation for queries across multiple days."""
        timestamps = [
            "2024-01-01 10:00:00 UTC",
            "2024-01-02 10:00:00 UTC",
            "2024-01-03 10:00:00 UTC",
        ]
        days = _calculate_days_in_period(timestamps)
        assert days == pytest.approx(2.0, rel=0.01)  # 2 days between first and last

    def test_calculate_days_empty_list(self):
        """Test that empty timestamp list returns 1.0 (minimum)."""
        days = _calculate_days_in_period([])
        assert days == 1.0

    def test_calculate_days_invalid_timestamp(self):
        """Test handling of invalid timestamp (returns 1.0 fallback)."""
        timestamps = ["invalid"]
        days = _calculate_days_in_period(timestamps)
        assert days == 1.0


class TestQueryAggregation:
    """Test suite for query metadata aggregation."""

    def test_aggregate_empty_list(self):
        """Test aggregation with empty query list."""
        salt = IdentifierEncryptor.generate_key()
        result = aggregate_query_metadata([], salt)
        assert result == []

    def test_aggregate_single_query(self):
        """Test aggregation with a single query."""
        salt = IdentifierEncryptor.generate_key()
        queries = [
            QueryMetadata(
                job_id="project:us.job1",
                query="SELECT * FROM dataset.table",
                total_bytes_processed=1099511627776,  # 1 TB
                creation_time="2024-01-01 10:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            )
        ]

        result = aggregate_query_metadata(queries, salt)

        assert len(result) == 1
        assert "query_hash" in result[0]
        assert len(result[0]["query_hash"]) == 64  # SHA-256 hash
        assert result[0]["total_bytes_processed"] == 1099511627776
        assert result[0]["bytes_per_execution"] == 1099511627776
        assert result[0]["executions_per_day"] == 1.0  # 1 execution / 1 day minimum
        assert result[0]["has_materialized_view"] is False

    def test_aggregate_duplicate_queries(self):
        """Test aggregation groups duplicate queries by pattern."""
        salt = IdentifierEncryptor.generate_key()
        queries = [
            QueryMetadata(
                job_id="project:us.job1",
                query="SELECT * FROM dataset.table",
                total_bytes_processed=1099511627776,  # 1 TB
                creation_time="2024-01-01 10:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            ),
            QueryMetadata(
                job_id="project:us.job2",
                query="SELECT * FROM dataset.table",  # Same query
                total_bytes_processed=1099511627776,  # 1 TB
                creation_time="2024-01-02 10:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            ),
        ]

        result = aggregate_query_metadata(queries, salt)

        # Should group into single pattern
        assert len(result) == 1
        assert result[0]["total_bytes_processed"] == 2199023255552  # 2 TB total
        assert result[0]["bytes_per_execution"] == 1099511627776  # 1 TB average
        assert result[0]["executions_per_day"] == 2.0  # 2 executions / 1 day

    def test_aggregate_different_queries(self):
        """Test aggregation creates separate groups for different queries."""
        salt = IdentifierEncryptor.generate_key()
        queries = [
            QueryMetadata(
                job_id="project:us.job1",
                query="SELECT * FROM dataset.table1",
                total_bytes_processed=1099511627776,
                creation_time="2024-01-01 10:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            ),
            QueryMetadata(
                job_id="project:us.job2",
                query="SELECT * FROM dataset.table2",  # Different table
                total_bytes_processed=2199023255552,
                creation_time="2024-01-01 11:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            ),
        ]

        result = aggregate_query_metadata(queries, salt)

        # Should create two separate patterns
        assert len(result) == 2

        # Each pattern should have its own statistics
        for pattern in result:
            assert pattern["total_bytes_processed"] in [1099511627776, 2199023255552]
            assert pattern["bytes_per_execution"] == pattern["total_bytes_processed"]
            assert pattern["has_materialized_view"] is False

    def test_aggregate_skips_empty_queries(self):
        """Test that queries without query text are skipped."""
        salt = IdentifierEncryptor.generate_key()
        queries = [
            QueryMetadata(
                job_id="project:us.job1",
                query="",  # Empty query
                total_bytes_processed=1099511627776,
                creation_time="2024-01-01 10:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            ),
            QueryMetadata(
                job_id="project:us.job2",
                query="SELECT * FROM dataset.table",  # Valid query
                total_bytes_processed=2199023255552,
                creation_time="2024-01-01 11:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            ),
        ]

        result = aggregate_query_metadata(queries, salt)

        # Should only have one pattern (empty query skipped)
        assert len(result) == 1
        assert result[0]["total_bytes_processed"] == 2199023255552

    def test_aggregate_query_text_anonymized(self):
        """Test that query text has table references anonymized."""
        salt = IdentifierEncryptor.generate_key()
        queries = [
            QueryMetadata(
                job_id="project:us.job1",
                query="SELECT * FROM dataset.table",
                total_bytes_processed=1099511627776,
                creation_time="2024-01-01 10:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            )
        ]

        result = aggregate_query_metadata(queries, salt)

        # Original table reference should not appear in anonymized query
        assert "dataset.table" not in result[0]["query_text"]
        # SQL structure should be preserved
        assert "SELECT * FROM" in result[0]["query_text"]

    def test_aggregate_executions_per_day_calculation(self):
        """Test accurate executions per day calculation across time range."""
        salt = IdentifierEncryptor.generate_key()
        queries = [
            QueryMetadata(
                job_id=f"project:us.job{i}",
                query="SELECT * FROM dataset.table",
                total_bytes_processed=1099511627776,
                creation_time=f"2024-01-{i:02d} 10:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            )
            for i in range(1, 11)  # 10 queries over 10 days
        ]

        result = aggregate_query_metadata(queries, salt, scan_days=90)

        assert len(result) == 1
        # 10 executions / 9 days (day 1 to day 10) ≈ 1.11 per day
        assert result[0]["executions_per_day"] == pytest.approx(1.11, rel=0.01)

    def test_aggregate_returns_all_required_fields(self):
        """Test that aggregated results contain all required fields."""
        salt = IdentifierEncryptor.generate_key()
        queries = [
            QueryMetadata(
                job_id="project:us.job1",
                query="SELECT * FROM dataset.table",
                total_bytes_processed=1099511627776,
                creation_time="2024-01-01 10:00:00 UTC",
                job_type="QUERY",
                state="DONE",
            )
        ]

        result = aggregate_query_metadata(queries, salt)

        assert len(result) == 1
        # Verify all required fields are present (may have additional fields)
        required_fields = {
            "query_hash",
            "query_text",
            "query_type",
            "executions_per_day",
            "bytes_per_execution",
            "total_bytes_processed",
            "has_materialized_view",
        }
        assert set(result[0].keys()) >= required_fields
        # Verify query_type is extracted correctly
        assert result[0]["query_type"] == "SELECT"

    def test_aggregate_extracts_query_type_correctly(self):
        """Test that query_type is correctly extracted for different SQL statements."""
        salt = IdentifierEncryptor.generate_key()

        # Test SELECT
        select_query = QueryMetadata(
            job_id="project:us.job1",
            query="SELECT * FROM dataset.table",
            total_bytes_processed=1099511627776,
            creation_time="2024-01-01 10:00:00 UTC",
            job_type="QUERY",
            state="DONE",
        )
        result = aggregate_query_metadata([select_query], salt)
        assert result[0]["query_type"] == "SELECT"

        # Test MERGE
        merge_query = QueryMetadata(
            job_id="project:us.job2",
            query="MERGE INTO dataset.table AS t USING source AS s ON t.id = s.id",
            total_bytes_processed=1099511627776,
            creation_time="2024-01-01 10:00:00 UTC",
            job_type="QUERY",
            state="DONE",
        )
        result = aggregate_query_metadata([merge_query], salt)
        assert result[0]["query_type"] == "MERGE"

        # Test INSERT
        insert_query = QueryMetadata(
            job_id="project:us.job3",
            query="INSERT INTO dataset.table VALUES (1, 2, 3)",
            total_bytes_processed=1099511627776,
            creation_time="2024-01-01 10:00:00 UTC",
            job_type="QUERY",
            state="DONE",
        )
        result = aggregate_query_metadata([insert_query], salt)
        assert result[0]["query_type"] == "INSERT"

        # Test CREATE
        create_query = QueryMetadata(
            job_id="project:us.job4",
            query="CREATE TABLE dataset.new_table AS SELECT * FROM dataset.source",
            total_bytes_processed=1099511627776,
            creation_time="2024-01-01 10:00:00 UTC",
            job_type="QUERY",
            state="DONE",
        )
        result = aggregate_query_metadata([create_query], salt)
        assert result[0]["query_type"] == "CREATE"

    def test_aggregate_handles_invalid_timestamp_gracefully(self):
        """Test that aggregator handles invalid timestamps with fallback."""
        salt = IdentifierEncryptor.generate_key()

        # Create query with malformed timestamp that will fail parsing
        query_with_bad_timestamp = QueryMetadata(
            job_id="project:us.job1",
            query="SELECT * FROM dataset.table",
            total_bytes_processed=1099511627776,
            creation_time="INVALID-TIMESTAMP",  # This will trigger ValueError in parsing
            job_type="QUERY",
            state="DONE",
        )

        # Should not raise error, should use fallback
        result = aggregate_query_metadata([query_with_bad_timestamp], salt)

        # Verify result is still generated (fallback worked)
        assert len(result) == 1
        assert result[0]["query_type"] == "SELECT"
        assert "last_execution_time" in result[0]
