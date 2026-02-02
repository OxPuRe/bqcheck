"""Extract complete BigQuery metadata from INFORMATION_SCHEMA."""

import logging
import re
from typing import List

from google.api_core.exceptions import GoogleAPIError
from google.cloud import bigquery

from bqaudit.scanner.models import AccessPattern, QueryMetadata, TableMetadata

logger = logging.getLogger(__name__)


def _parse_partitioning_from_ddl(ddl: str) -> dict:
    """
    Parse partitioning information from DDL statement.

    Args:
        ddl: CREATE TABLE DDL statement

    Returns:
        Dict with keys: type, field, expiration_days (all optional)
    """
    if not ddl:
        return {}

    partition_info = {}

    # Look for PARTITION BY clause
    # Examples:
    # - PARTITION BY DATE(timestamp_column)
    # - PARTITION BY DATETIME_TRUNC(datetime_column, DAY)
    # - PARTITION BY timestamp_column (direct field reference)
    # - PARTITION BY _PARTITIONDATE

    # First try function-based partitioning
    partition_match = re.search(
        r"PARTITION\s+BY\s+(DATE|DATETIME_TRUNC|TIMESTAMP_TRUNC|RANGE)\s*\(([^)]+)\)",
        ddl,
        re.IGNORECASE,
    )
    if partition_match:
        partition_type = partition_match.group(1).upper()
        partition_expr = partition_match.group(2)

        # Simplify type names
        if partition_type in ("DATE", "DATETIME_TRUNC", "TIMESTAMP_TRUNC"):
            partition_info["type"] = "DAY"
        elif partition_type == "RANGE":
            partition_info["type"] = "RANGE"
        else:
            partition_info["type"] = partition_type

        # Extract field name (first argument to function)
        field_match = re.search(r"([a-zA-Z_][a-zA-Z0-9_]*)", partition_expr)
        if field_match:
            partition_info["field"] = field_match.group(1)
    else:
        # Try direct field partitioning (PARTITION BY field_name)
        direct_match = re.search(
            r"PARTITION\s+BY\s+([a-zA-Z_][a-zA-Z0-9_]*)",
            ddl,
            re.IGNORECASE,
        )
        if direct_match:
            partition_info["type"] = "DAY"  # Assume DAY partitioning for direct field
            partition_info["field"] = direct_match.group(1)

    # Look for OPTIONS clause with partition_expiration_days
    expiration_match = re.search(
        r"partition_expiration_days\s*=\s*(\d+)", ddl, re.IGNORECASE
    )
    if expiration_match:
        partition_info["expiration_days"] = int(expiration_match.group(1))

    return partition_info


def _parse_clustering_from_ddl(ddl: str) -> list:
    """
    Parse clustering fields from DDL statement.

    Args:
        ddl: CREATE TABLE DDL statement

    Returns:
        List of clustering field names (empty if not clustered)
    """
    if not ddl:
        return []

    # Look for CLUSTER BY clause
    # Example: CLUSTER BY customer_id, order_date
    # Stop at OPTIONS, semicolon, or end of DDL
    cluster_match = re.search(r"CLUSTER\s+BY\s+([^;]+?)(?:OPTIONS|;|$)", ddl, re.IGNORECASE)
    if cluster_match:
        fields_str = cluster_match.group(1).strip()
        # Split by comma and clean up whitespace
        fields = [f.strip() for f in fields_str.split(",")]
        return [f for f in fields if f]  # Filter empty strings

    return []


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

    try:
        # List all datasets to detect regions
        datasets = list(client.list_datasets(project=project_id))

        if not datasets:
            logger.warning(f"No datasets found in project {project_id}")
            return []

        # Group datasets by location (region)
        locations = set()
        for dataset in datasets:
            dataset_ref = client.get_dataset(f"{project_id}.{dataset.dataset_id}")
            locations.add(dataset_ref.location)

        logger.info(f"Found {len(datasets)} datasets across {len(locations)} region(s): {locations}")

        # Collect tables from all regions using project-wide INFORMATION_SCHEMA
        all_tables = []

        for location in locations:
            logger.info(f"Querying INFORMATION_SCHEMA for region: {location}")

            # Query project-wide INFORMATION_SCHEMA with TABLE_STORAGE for complete metrics
            # region-{location}.INFORMATION_SCHEMA provides all metadata at project level
            query = f"""
            SELECT
                t.table_catalog,
                t.table_schema,
                t.table_name,
                t.table_type,
                CAST(t.creation_time AS STRING) as creation_time,

                -- Storage metadata from TABLE_STORAGE (real values!)
                COALESCE(s.total_logical_bytes, 0) as size_bytes,
                COALESCE(s.total_rows, 0) as row_count,

                -- Partitioning metadata from TABLES
                t.ddl as ddl

            FROM `{project_id}.region-{location}.INFORMATION_SCHEMA.TABLES` t
            LEFT JOIN `{project_id}.region-{location}.INFORMATION_SCHEMA.TABLE_STORAGE` s
              ON t.table_catalog = s.table_catalog
              AND t.table_schema = s.table_schema
              AND t.table_name = s.table_name
            WHERE t.table_type IN ('BASE TABLE', 'VIEW', 'EXTERNAL')
            ORDER BY s.total_logical_bytes DESC NULLS LAST
            """

            try:
                query_job = client.query(query, location=location)

                # Collect results for this region
                for row in query_job.result():
                    # Parse DDL to extract partitioning and clustering info
                    partition_info = _parse_partitioning_from_ddl(row.ddl)
                    clustering_fields = _parse_clustering_from_ddl(row.ddl)

                    table_dict = {
                        "table_catalog": row.table_catalog,
                        "table_schema": row.table_schema,
                        "table_name": row.table_name,
                        "table_type": row.table_type,
                        "creation_time": row.creation_time,
                        "size_bytes": row.size_bytes,
                        "row_count": row.row_count,
                        "partition_expiration_days": partition_info.get("expiration_days"),
                        "time_partitioning_type": partition_info.get("type"),
                        "time_partitioning_field": partition_info.get("field"),
                        "clustering_fields": clustering_fields,
                    }

                    # Validate and create Pydantic model
                    table_metadata = TableMetadata(**table_dict)
                    all_tables.append(table_metadata)

            except GoogleAPIError as e:
                logger.warning(
                    f"Failed to query INFORMATION_SCHEMA for region {location}: {e}. "
                    f"This may be normal if no tables exist in this region."
                )
                continue

        # Sort all tables by size (largest first)
        all_tables.sort(key=lambda t: t.size_bytes or 0, reverse=True)

        logger.info(
            f"Extracted metadata for {len(all_tables)} tables across {len(locations)} region(s)"
        )
        return all_tables

    except GoogleAPIError as e:
        # Don't preserve exception chain to avoid
        # stack trace leakage of internal paths and Google API details to CLI users
        raise GoogleAPIError(f"Failed to extract table metadata: {str(e)}")


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

    # Detect locations by listing datasets
    try:
        datasets = list(client.list_datasets(project=project_id))
        locations = set()
        for dataset in datasets:
            dataset_ref = client.get_dataset(f"{project_id}.{dataset.dataset_id}")
            locations.add(dataset_ref.location)
    except GoogleAPIError:
        # Fallback to common regions if dataset listing fails
        locations = {"US", "EU"}

    # Try each detected location
    for location in locations:
        query = f"""
        SELECT
            job_id,
            query,
            COALESCE(total_bytes_processed, 0) as total_bytes_processed,
            CAST(creation_time AS STRING) as creation_time,
            user_email,
            job_type,
            state

        FROM `{project_id}.region-{location.lower()}.INFORMATION_SCHEMA.JOBS_BY_PROJECT`

        WHERE creation_time >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL {days} DAY)
            AND job_type = 'QUERY'
            AND state = 'DONE'
            AND query IS NOT NULL

        ORDER BY total_bytes_processed DESC

        LIMIT {max_queries}
        """

        try:
            # Configure query job with location
            job_config = bigquery.QueryJobConfig()
            query_job = client.query(query, job_config=job_config, location=location)

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

            # Success - log and return
            logger.info(f"Extracted {len(queries)} queries from location {location}")

            # Warn if results were limited
            if len(queries) == max_queries:
                logger.warning(
                    f"Query results limited to {max_queries} most expensive queries. "
                    f"Project {project_id} may have more queries in the last {days} days."
                )

            return queries

        except GoogleAPIError as e:
            # Try next location
            logger.debug(f"Location {location} failed: {str(e)}")
            continue

    # No location worked - return empty list with warning
    logger.warning(
        f"Could not extract query metadata from {project_id}. "
        f"Tried locations: {locations}. This may be normal if the project "
        "has no query history or uses a different location."
    )
    return []


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

    # Detect locations by listing datasets
    try:
        datasets = list(client.list_datasets(project=project_id))
        locations = set()
        for dataset in datasets:
            dataset_ref = client.get_dataset(f"{project_id}.{dataset.dataset_id}")
            locations.add(dataset_ref.location)
    except GoogleAPIError:
        # Fallback to common regions if dataset listing fails
        locations = {"US", "EU"}

    # Try each detected location
    for location in locations:
        query = f"""
        SELECT
            table_catalog,
            table_schema,
            table_name,
            CAST(MAX(timestamp) AS STRING) as last_modified_time

        FROM `{project_id}.region-{location.lower()}.INFORMATION_SCHEMA.TABLE_STORAGE_TIMELINE_BY_PROJECT`

        GROUP BY table_catalog, table_schema, table_name
        HAVING MAX(timestamp) IS NOT NULL

        ORDER BY last_modified_time ASC
        """

        try:
            # Configure query job with location
            job_config = bigquery.QueryJobConfig()
            query_job = client.query(query, job_config=job_config, location=location)

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

            # Success - log and return
            logger.info(f"Extracted {len(patterns)} access patterns from location {location}")
            return patterns

        except GoogleAPIError as e:
            # Try next location
            logger.debug(f"Location {location} failed: {str(e)}")
            continue

    # No location worked - return empty list with warning
    logger.warning(
        f"Could not extract access patterns from {project_id}. "
        f"Tried locations: {locations}. This may be normal if the project "
        "has no storage timeline data or uses a different location."
    )
    return []
