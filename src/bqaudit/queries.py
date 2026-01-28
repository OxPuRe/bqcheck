"""
BigQuery SQL query templates for INFORMATION_SCHEMA.

Centralized query management for validate command and metadata extraction.
All queries use consistent formatting and project ID validation.
"""


def get_simple_test_query() -> str:
    """
    Get simple test query for API enablement check.

    Returns:
        Simple SELECT 1 query to verify BigQuery API is enabled
    """
    return "SELECT 1"


def get_tables_query(project_id: str, limit: int = 1) -> str:
    """
    Get query to retrieve table metadata from INFORMATION_SCHEMA.

    Args:
        project_id: GCP project ID
        limit: Maximum number of tables to return

    Returns:
        SQL query string for INFORMATION_SCHEMA.TABLES
    """
    return f"""
        SELECT table_catalog, table_schema, table_name
        FROM `{project_id}.INFORMATION_SCHEMA.TABLES`
        LIMIT {limit}
    """


def get_table_count_query(project_id: str) -> str:
    """
    Get query to count total tables in project.

    Args:
        project_id: GCP project ID

    Returns:
        SQL query string to count tables
    """
    return f"""
        SELECT COUNT(*) as table_count
        FROM `{project_id}.INFORMATION_SCHEMA.TABLES`
    """


def get_sample_queries_query(project_id: str, limit: int = 3) -> str:
    """
    Get query to retrieve sample SELECT queries from JOBS_BY_PROJECT.

    Args:
        project_id: GCP project ID
        limit: Maximum number of queries to return

    Returns:
        SQL query string for recent SELECT queries
    """
    return f"""
        SELECT query
        FROM `{project_id}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`
        WHERE statement_type = 'SELECT'
          AND query IS NOT NULL
        ORDER BY creation_time DESC
        LIMIT {limit}
    """
