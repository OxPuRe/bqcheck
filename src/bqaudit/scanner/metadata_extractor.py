"""Extract complete BigQuery metadata from INFORMATION_SCHEMA."""

import logging
import re
from typing import List

from google.api_core.exceptions import GoogleAPIError
from google.cloud import bigquery

from bqaudit.scanner.models import AccessPattern, QueryMetadata, TableMetadata

logger = logging.getLogger(__name__)


def _validate_project_id(project_id: str) -> None:
    """
    Validate project_id format to prevent SQL injection.

    Args:
        project_id: GCP project ID to validate

    Raises:
        ValueError: If project_id format is invalid

    GCP project ID requirements:
    - Must be 6-30 characters
    - Must start with lowercase letter
    - Can contain lowercase letters, numbers, and hyphens
    - Cannot end with hyphen
    """
    # GCP project ID pattern: ^[a-z][-a-z0-9]{4,28}[a-z0-9]$
    # Explanation:
    # - ^[a-z] - starts with lowercase letter
    # - [-a-z0-9]{4,28} - middle chars (letters, numbers, hyphens), 4-28 chars
    # - [a-z0-9]$ - ends with letter or number (total 6-30 chars)
    pattern = r"^[a-z][-a-z0-9]{4,28}[a-z0-9]$"

    if not re.match(pattern, project_id):
        raise ValueError(
            f"Invalid project_id format: '{project_id}'. "
            "Must be 6-30 characters, start with lowercase letter, "
            "contain only lowercase letters, numbers, and hyphens, "
            "and cannot end with hyphen."
        )


def extract_table_metadata(
    client: bigquery.Client, project_id: str
) -> List[TableMetadata]:
    """
    Extract complete table metadata from INFORMATION_SCHEMA.

    Queries INFORMATION_SCHEMA.TABLES JOIN TABLE_STORAGE to get:
    - Table identification (catalog, schema, name, type)
    - Storage statistics (size_bytes, row_count)
    - Partitioning configuration
    - Clustering configuration

    Args:
        client: Authenticated BigQuery client (from authenticate_bigquery)
        project_id: GCP project ID to scan

    Returns:
        List of TableMetadata objects with complete metadata

    Raises:
        ValueError: If project_id format is invalid
        GoogleAPIError: BigQuery API failures

    Privacy Note:
        This function accesses ONLY metadata via INFORMATION_SCHEMA.
        It NEVER queries actual table data.
    """
    # Validate project_id to prevent SQL injection
    _validate_project_id(project_id)

    query = f"""
    SELECT
        t.table_catalog,
        t.table_schema,
        t.table_name,
        t.table_type,
        CAST(t.creation_time AS STRING) as creation_time,

        -- Storage metadata (may be NULL for views)
        s.total_logical_bytes as size_bytes,
        s.total_rows as row_count,

        -- Partitioning metadata (may be NULL)
        t.partition_expiration_days,
        t.time_partitioning_type,
        t.time_partitioning_field,

        -- Clustering metadata (may be NULL)
        t.clustering_fields

    FROM `{project_id}.INFORMATION_SCHEMA.TABLES` AS t
    LEFT JOIN `{project_id}.INFORMATION_SCHEMA.TABLE_STORAGE` AS s
        ON t.table_catalog = s.project_id
        AND t.table_schema = s.table_schema
        AND t.table_name = s.table_name

    WHERE t.table_schema NOT IN ('INFORMATION_SCHEMA', 'information_schema')

    ORDER BY s.total_logical_bytes DESC NULLS LAST
    """

    try:
        # Configure query job
        job_config = bigquery.QueryJobConfig()

        query_job = client.query(query, job_config=job_config)

        # Collect results (automatic pagination handled by SDK)
        tables = []
        for row in query_job.result():
            # Convert BigQuery row to dict
            table_dict = {
                "table_catalog": row.table_catalog,
                "table_schema": row.table_schema,
                "table_name": row.table_name,
                "table_type": row.table_type,
                "creation_time": row.creation_time,
                "size_bytes": row.size_bytes,
                "row_count": row.row_count,
                "partition_expiration_days": row.partition_expiration_days,
                "time_partitioning_type": row.time_partitioning_type,
                "time_partitioning_field": row.time_partitioning_field,
                "clustering_fields": row.clustering_fields,
            }

            # Validate and create Pydantic model
            table_metadata = TableMetadata(**table_dict)
            tables.append(table_metadata)

        return tables

    except GoogleAPIError as e:
        # Don't preserve exception chain to avoid
        # stack trace leakage of internal paths and Google API details to CLI users
        raise GoogleAPIError(
            f"Failed to extract table metadata: {str(e)}"
        )


def extract_query_metadata(
    client: bigquery.Client,
    project_id: str,
    days: int = 30,
    max_queries: int = 10000,
) -> List[QueryMetadata]:
    """
    Extract query execution metadata from INFORMATION_SCHEMA.JOBS_BY_PROJECT.

    Queries INFORMATION_SCHEMA.JOBS_BY_PROJECT to get:
    - Query text and execution metrics
    - Total bytes processed
    - Job execution timestamps
    - User identification

    Args:
        client: Authenticated BigQuery client (from authenticate_bigquery)
        project_id: GCP project ID to scan
        days: Number of days of history to fetch (default: 30)
        max_queries: Maximum number of queries to return (default: 10000)

    Returns:
        List of QueryMetadata objects with query execution metadata

    Raises:
        ValueError: If project_id format is invalid
        GoogleAPIError: BigQuery API failures

    Privacy Note:
        This function accesses ONLY query metadata via INFORMATION_SCHEMA.
        Query text will be anonymized in Story 2.4.
    """
    # Validate project_id to prevent SQL injection
    _validate_project_id(project_id)

    query = f"""
    SELECT
        job_id,
        query,
        total_bytes_processed,
        CAST(creation_time AS STRING) as creation_time,
        user_email,
        job_type,
        state

    FROM `{project_id}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`

    WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
        AND job_type = 'QUERY'
        AND state = 'DONE'
        AND query IS NOT NULL

    ORDER BY total_bytes_processed DESC

    LIMIT {max_queries}
    """

    try:
        # Configure query job
        job_config = bigquery.QueryJobConfig()

        query_job = client.query(query, job_config=job_config)

        # Collect results (automatic pagination handled by SDK)
        queries = []
        for row in query_job.result():
            # Convert BigQuery row to dict
            query_dict = {
                "job_id": row.job_id,
                "query": row.query,
                "total_bytes_processed": row.total_bytes_processed,
                "creation_time": row.creation_time,
                "user_email": row.user_email,
                "job_type": row.job_type,
                "state": row.state,
            }

            # Validate and create Pydantic model
            query_metadata = QueryMetadata(**query_dict)
            queries.append(query_metadata)

        # Warn if results were limited
        if len(queries) == max_queries:
            logger.warning(
                f"Query results limited to {max_queries} most expensive queries. "
                f"Project {project_id} may have more queries in the last {days} days."
            )

        return queries

    except GoogleAPIError as e:
        # Re-raise with context for CLI error handling
        raise GoogleAPIError(
            f"Failed to extract query metadata from {project_id}: {str(e)}"
        ) from e


def extract_access_patterns(
    client: bigquery.Client,
    project_id: str,
) -> List[AccessPattern]:
    """
    Extract table access patterns from INFORMATION_SCHEMA.TABLE_STORAGE_TIMELINE.

    Queries INFORMATION_SCHEMA.TABLE_STORAGE_TIMELINE_BY_PROJECT to get:
    - Last modification timestamp per table (approximates last access)
    - Identifies potentially unused tables

    Args:
        client: Authenticated BigQuery client (from authenticate_bigquery)
        project_id: GCP project ID to scan

    Returns:
        List of AccessPattern objects with last modification timestamps

    Raises:
        ValueError: If project_id format is invalid
        GoogleAPIError: BigQuery API failures

    Privacy Note:
        This function accesses ONLY metadata via INFORMATION_SCHEMA.
        Table names will be anonymized in Story 2.4.
    """
    # Validate project_id to prevent SQL injection
    _validate_project_id(project_id)

    query = f"""
    SELECT
        table_catalog,
        table_schema,
        table_name,
        CAST(MAX(timestamp) AS STRING) as last_modified_time

    FROM `{project_id}.INFORMATION_SCHEMA.TABLE_STORAGE_TIMELINE_BY_PROJECT`

    GROUP BY table_catalog, table_schema, table_name
    HAVING MAX(timestamp) IS NOT NULL

    ORDER BY last_modified_time ASC
    """

    try:
        # Configure query job
        job_config = bigquery.QueryJobConfig()

        query_job = client.query(query, job_config=job_config)

        # Collect results (automatic pagination handled by SDK)
        patterns = []
        for row in query_job.result():
            # Convert BigQuery row to dict
            pattern_dict = {
                "table_catalog": row.table_catalog,
                "table_schema": row.table_schema,
                "table_name": row.table_name,
                "last_modified_time": row.last_modified_time,
            }

            # Validate and create Pydantic model
            access_pattern = AccessPattern(**pattern_dict)
            patterns.append(access_pattern)

        return patterns

    except GoogleAPIError as e:
        # Re-raise with context for CLI error handling
        raise GoogleAPIError(
            f"Failed to extract access patterns from {project_id}: {str(e)}"
        ) from e
