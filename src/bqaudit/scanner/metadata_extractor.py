"""Extract complete BigQuery metadata from INFORMATION_SCHEMA."""

import re
from typing import List

from google.api_core.exceptions import GoogleAPIError
from google.cloud import bigquery

from bqaudit.scanner.models import TableMetadata


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
    client: bigquery.Client,
    project_id: str
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
        # Re-raise with context for CLI error handling
        raise GoogleAPIError(
            f"Failed to extract table metadata from {project_id}: {str(e)}"
        ) from e
