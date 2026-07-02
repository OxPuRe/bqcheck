"""BigQuery scanner module for metadata extraction."""

from bqcheck.scanner.anonymizer import (
    anonymize_access_patterns,
    anonymize_dataset_name,
    anonymize_metadata,
    anonymize_project_id,
    anonymize_query_list,
    anonymize_query_pattern,
    anonymize_table_list,
    anonymize_table_name,
    generate_salt,
    merge_table_metadata,
)
from bqcheck.scanner.bigquery_client import (
    AuthenticationError,
    ProjectNotFoundError,
    authenticate_bigquery,
)
from bqcheck.scanner.metadata_extractor import (
    extract_access_patterns,
    extract_query_metadata,
    extract_table_metadata,
    extract_table_schemas,
)
from bqcheck.scanner.models import AccessPattern, QueryMetadata, TableMetadata

__all__ = [
    "authenticate_bigquery",
    "AuthenticationError",
    "ProjectNotFoundError",
    "TableMetadata",
    "QueryMetadata",
    "AccessPattern",
    "extract_table_metadata",
    "extract_query_metadata",
    "extract_access_patterns",
    "extract_table_schemas",
    "generate_salt",
    "anonymize_table_name",
    "anonymize_dataset_name",
    "anonymize_project_id",
    "anonymize_query_pattern",
    "anonymize_metadata",
    "anonymize_table_list",
    "anonymize_query_list",
    "anonymize_access_patterns",
    "merge_table_metadata",
]
