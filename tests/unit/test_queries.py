"""
Unit tests for bqaudit.queries module.

Tests SQL query generation with injection protection and validation.
"""

import pytest

from bqaudit.queries import (
    get_sample_queries_query,
    get_simple_test_query,
    get_table_count_query,
    get_tables_query,
)


class TestSimpleTestQuery:
    """Test get_simple_test_query function."""

    def test_returns_simple_select(self):
        """Test returns basic SELECT 1 query."""
        query = get_simple_test_query()
        assert query == "SELECT 1"

    def test_query_is_cached(self):
        """Test query result is cached (same object returned)."""
        query1 = get_simple_test_query()
        query2 = get_simple_test_query()
        assert query1 is query2  # Same object due to lru_cache


class TestTablesQuery:
    """Test get_tables_query function."""

    def test_valid_project_id_default_limit(self):
        """Test query generation with valid project_id and default limit."""
        query = get_tables_query("test-project-123")
        assert "test-project-123.INFORMATION_SCHEMA.TABLES" in query
        assert "LIMIT 1" in query

    def test_valid_project_id_custom_limit(self):
        """Test query generation with custom limit."""
        query = get_tables_query("my-project-456", limit=10)
        assert "my-project-456.INFORMATION_SCHEMA.TABLES" in query
        assert "LIMIT 10" in query

    def test_query_includes_required_columns(self):
        """Test query selects table_catalog, table_schema, table_name."""
        query = get_tables_query("test-project")
        assert "table_catalog" in query
        assert "table_schema" in query
        assert "table_name" in query

    def test_rejects_sql_injection_attempt(self):
        """Test SQL injection in project_id is blocked."""
        with pytest.raises(ValueError, match="Invalid project_id format"):
            get_tables_query("test-project; DROP TABLE users--")

    def test_rejects_invalid_project_id_format(self):
        """Test invalid project_id format raises ValueError."""
        with pytest.raises(ValueError, match="Invalid project_id format"):
            get_tables_query("INVALID_PROJECT_123")  # uppercase not allowed

    def test_rejects_negative_limit(self):
        """Test negative limit raises ValueError."""
        with pytest.raises(ValueError, match="Invalid limit value"):
            get_tables_query("test-project", limit=-1)

    def test_rejects_zero_limit(self):
        """Test zero limit raises ValueError."""
        with pytest.raises(ValueError, match="Invalid limit value"):
            get_tables_query("test-project", limit=0)

    def test_rejects_non_integer_limit(self):
        """Test non-integer limit raises ValueError."""
        with pytest.raises(ValueError, match="Invalid limit value"):
            get_tables_query("test-project", limit="10")  # type: ignore

    def test_query_is_not_cached(self):
        """Test query result is NOT cached (Round 6: removed @lru_cache)."""
        query1 = get_tables_query("test-project", limit=5)
        query2 = get_tables_query("test-project", limit=5)
        assert query1 is not query2  # Different objects, no cache
        assert query1 == query2  # But same content


class TestTableCountQuery:
    """Test get_table_count_query function."""

    def test_valid_project_id(self):
        """Test query generation with valid project_id."""
        query = get_table_count_query("test-project-789")
        assert "test-project-789.INFORMATION_SCHEMA.TABLES" in query
        assert "COUNT(*)" in query
        assert "table_count" in query

    def test_rejects_sql_injection_attempt(self):
        """Test SQL injection in project_id is blocked."""
        with pytest.raises(ValueError, match="Invalid project_id format"):
            get_table_count_query("test`; SELECT password FROM users--")

    def test_rejects_invalid_project_id(self):
        """Test invalid project_id raises ValueError."""
        with pytest.raises(ValueError, match="Invalid project_id format"):
            get_table_count_query("project_with_underscores")

    def test_query_is_not_cached(self):
        """Test query result is NOT cached (Round 6: removed @lru_cache)."""
        query1 = get_table_count_query("test-project")
        query2 = get_table_count_query("test-project")
        assert query1 is not query2  # Different objects, no cache
        assert query1 == query2  # But same content


class TestSampleQueriesQuery:
    """Test get_sample_queries_query function."""

    def test_valid_project_id_default_limit(self):
        """Test query generation with default limit."""
        query = get_sample_queries_query("test-project-abc")
        assert "test-project-abc.INFORMATION_SCHEMA.JOBS_BY_PROJECT" in query
        assert "LIMIT 3" in query

    def test_valid_project_id_custom_limit(self):
        """Test query generation with custom limit."""
        query = get_sample_queries_query("my-project-xyz", limit=5)
        assert "my-project-xyz.INFORMATION_SCHEMA.JOBS_BY_PROJECT" in query
        assert "LIMIT 5" in query

    def test_query_filters_select_statements(self):
        """Test query filters for SELECT statement_type."""
        query = get_sample_queries_query("test-project")
        assert "statement_type = 'SELECT'" in query
        assert "query IS NOT NULL" in query
        assert "ORDER BY creation_time DESC" in query

    def test_rejects_sql_injection_attempt(self):
        """Test SQL injection in project_id is blocked."""
        with pytest.raises(ValueError, match="Invalid project_id format"):
            get_sample_queries_query("test-project' OR '1'='1")

    def test_rejects_invalid_project_id(self):
        """Test invalid project_id raises ValueError."""
        with pytest.raises(ValueError, match="Invalid project_id format"):
            get_sample_queries_query("123-starts-with-number")

    def test_rejects_negative_limit(self):
        """Test negative limit raises ValueError."""
        with pytest.raises(ValueError, match="Invalid limit value"):
            get_sample_queries_query("test-project", limit=-5)

    def test_rejects_zero_limit(self):
        """Test zero limit raises ValueError."""
        with pytest.raises(ValueError, match="Invalid limit value"):
            get_sample_queries_query("test-project", limit=0)

    def test_rejects_non_integer_limit(self):
        """Test non-integer limit raises ValueError."""
        with pytest.raises(ValueError, match="Invalid limit value"):
            get_sample_queries_query("test-project", limit=3.5)  # type: ignore

    def test_query_is_not_cached(self):
        """Test query result is NOT cached (Round 6: removed @lru_cache)."""
        query1 = get_sample_queries_query("test-project", limit=3)
        query2 = get_sample_queries_query("test-project", limit=3)
        assert query1 is not query2  # Different objects, no cache
        assert query1 == query2  # But same content


class TestModuleExports:
    """Test module __all__ exports."""

    def test_all_exports_defined(self):
        """Test __all__ is defined with expected functions."""
        from bqaudit import queries

        assert hasattr(queries, "__all__")
        assert "get_simple_test_query" in queries.__all__
        assert "get_tables_query" in queries.__all__
        assert "get_table_count_query" in queries.__all__
        assert "get_sample_queries_query" in queries.__all__
