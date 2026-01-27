"""BigQuery scanner module for metadata extraction."""

from bqaudit.scanner.bigquery_client import (
    AuthenticationError,
    ProjectNotFoundError,
    authenticate_bigquery,
)
from bqaudit.scanner.metadata_extractor import extract_table_metadata
from bqaudit.scanner.models import TableMetadata

__all__ = [
    "authenticate_bigquery",
    "AuthenticationError",
    "ProjectNotFoundError",
    "TableMetadata",
    "extract_table_metadata",
]
