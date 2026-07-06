"""Unit tests for BigQuery SQL query builders."""

from collections.abc import Callable

import pytest

from bqcheck import queries
from bqcheck.queries import (
    get_sample_queries_query,
    get_simple_test_query,
    get_table_count_query,
    get_tables_query,
)


def test_simple_test_query_is_cached():
    assert get_simple_test_query() == "SELECT 1"
    assert get_simple_test_query() is get_simple_test_query()


@pytest.mark.parametrize(
    ("builder", "project_id", "limit", "expected_fragments"),
    [
        (
            get_tables_query,
            "test-project-123",
            None,
            [
                "test-project-123.INFORMATION_SCHEMA.TABLES",
                "table_catalog",
                "table_schema",
                "table_name",
                "LIMIT 1",
            ],
        ),
        (
            get_tables_query,
            "my-project-456",
            10,
            ["my-project-456.INFORMATION_SCHEMA.TABLES", "LIMIT 10"],
        ),
        (
            get_table_count_query,
            "test-project-789",
            None,
            [
                "test-project-789.INFORMATION_SCHEMA.TABLES",
                "COUNT(*)",
                "table_count",
            ],
        ),
        (
            get_sample_queries_query,
            "test-project-abc",
            None,
            [
                "test-project-abc.INFORMATION_SCHEMA.JOBS_BY_PROJECT",
                "statement_type = 'SELECT'",
                "query IS NOT NULL",
                "ORDER BY creation_time DESC",
                "LIMIT 3",
            ],
        ),
        (
            get_sample_queries_query,
            "my-project-xyz",
            5,
            ["my-project-xyz.INFORMATION_SCHEMA.JOBS_BY_PROJECT", "LIMIT 5"],
        ),
    ],
)
def test_query_builders_emit_expected_sql(
    builder: Callable[..., str],
    project_id: str,
    limit: int | None,
    expected_fragments: list[str],
):
    query = builder(project_id) if limit is None else builder(project_id, limit=limit)

    for fragment in expected_fragments:
        assert fragment in query


@pytest.mark.parametrize(
    ("builder", "project_id"),
    [
        (get_tables_query, "test-project; DROP TABLE users--"),
        (get_tables_query, "INVALID_PROJECT_123"),
        (get_table_count_query, "test`; SELECT password FROM users--"),
        (get_table_count_query, "project_with_underscores"),
        (get_sample_queries_query, "test-project' OR '1'='1"),
        (get_sample_queries_query, "123-starts-with-number"),
    ],
)
def test_query_builders_reject_invalid_project_ids(
    builder: Callable[..., str],
    project_id: str,
):
    with pytest.raises(ValueError, match="Invalid project_id format"):
        builder(project_id)


@pytest.mark.parametrize(
    ("builder", "invalid_limit"),
    [
        (get_tables_query, -1),
        (get_tables_query, 0),
        (get_tables_query, "10"),
        (get_sample_queries_query, -5),
        (get_sample_queries_query, 0),
        (get_sample_queries_query, 3.5),
    ],
)
def test_limited_query_builders_reject_invalid_limits(
    builder: Callable[..., str],
    invalid_limit: object,
):
    with pytest.raises(ValueError, match="Invalid limit value"):
        builder("test-project", limit=invalid_limit)


@pytest.mark.parametrize(
    "builder",
    [get_tables_query, get_table_count_query, get_sample_queries_query],
)
def test_dynamic_query_builders_are_not_cached(builder: Callable[..., str]):
    query1 = builder("test-project")
    query2 = builder("test-project")

    assert query1 == query2
    assert query1 is not query2


def test_module_exports_all_query_builders():
    assert queries.__all__ == [
        "get_simple_test_query",
        "get_tables_query",
        "get_table_count_query",
        "get_sample_queries_query",
    ]
