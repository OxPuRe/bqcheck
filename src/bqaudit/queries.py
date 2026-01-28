"""
BigQuery SQL query templates for INFORMATION_SCHEMA.

Centralized query management for validate command and metadata extraction.
All queries use consistent formatting with SQL injection protection.
"""

import logging
from functools import lru_cache

from bqaudit.scanner.metadata_extractor import _validate_project_id

logger = logging.getLogger(__name__)

__all__ = [
    "get_simple_test_query",
    "get_tables_query",
    "get_table_count_query",
    "get_sample_queries_query",
]


@lru_cache(maxsize=32)
def get_simple_test_query() -> str:
    """
    Get simple test query for API enablement check.

    Returns:
        Simple SELECT 1 query to verify BigQuery API is enabled
    """
    logger.debug("Generating simple test query")
    return "SELECT 1"


@lru_cache(maxsize=32)
def get_tables_query(project_id: str, limit: int = 1) -> str:
    """
    Get query to retrieve table metadata from INFORMATION_SCHEMA.

    Args:
        project_id: GCP project ID (validated against injection)
        limit: Maximum number of tables to return (must be positive)

    Returns:
        SQL query string for INFORMATION_SCHEMA.TABLES

    Raises:
        ValueError: If project_id format is invalid or limit is not positive
    """
    _validate_project_id(project_id)

    if not isinstance(limit, int) or limit < 1:
        raise ValueError(
            f"Invalid limit value: {limit}. Must be positive integer."
        )

    logger.debug(
        f"Generating tables query for project={project_id}, limit={limit}"
    )
    return f"""
        SELECT table_catalog, table_schema, table_name
        FROM `{project_id}.INFORMATION_SCHEMA.TABLES`
        LIMIT {limit}
    """


@lru_cache(maxsize=32)
def get_table_count_query(project_id: str) -> str:
    """
    Get query to count total tables in project.

    Args:
        project_id: GCP project ID (validated against injection)

    Returns:
        SQL query string to count tables

    Raises:
        ValueError: If project_id format is invalid
    """
    _validate_project_id(project_id)
    logger.debug(f"Generating table count query for project={project_id}")
    return f"""
        SELECT COUNT(*) as table_count
        FROM `{project_id}.INFORMATION_SCHEMA.TABLES`
    """


@lru_cache(maxsize=32)
def get_sample_queries_query(project_id: str, limit: int = 3) -> str:
    """
    Get query to retrieve sample SELECT queries from JOBS_BY_PROJECT.

    Args:
        project_id: GCP project ID (validated against injection)
        limit: Maximum number of queries to return (must be positive)

    Returns:
        SQL query string for recent SELECT queries

    Raises:
        ValueError: If project_id format is invalid or limit is not positive
    """
    _validate_project_id(project_id)

    if not isinstance(limit, int) or limit < 1:
        raise ValueError(
            f"Invalid limit value: {limit}. Must be positive integer."
        )

    logger.debug(
        f"Generating sample queries query for "
        f"project={project_id}, limit={limit}"
    )
    return f"""
        SELECT query
        FROM `{project_id}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`
        WHERE statement_type = 'SELECT'
          AND query IS NOT NULL
        ORDER BY creation_time DESC
        LIMIT {limit}
    """
