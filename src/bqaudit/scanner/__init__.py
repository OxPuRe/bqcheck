"""BigQuery scanner module for metadata extraction."""

from bqaudit.scanner.bigquery_client import (
    authenticate_bigquery,
    AuthenticationError,
    ProjectNotFoundError,
)

__all__ = ["authenticate_bigquery", "AuthenticationError", "ProjectNotFoundError"]
