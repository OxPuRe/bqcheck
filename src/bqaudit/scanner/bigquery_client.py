"""BigQuery client authentication and initialization."""

from google.api_core.exceptions import Forbidden, NotFound
from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
from google.cloud import bigquery


class AuthenticationError(Exception):
    """Raised when GCP authentication fails."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class ProjectNotFoundError(Exception):
    """Raised when BigQuery project is not found or inaccessible."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class PermissionError(Exception):
    """Raised when required BigQuery permissions are missing."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def authenticate_bigquery(project_id: str) -> bigquery.Client:
    """
    Authenticate with GCP and initialize BigQuery client.

    Args:
        project_id: GCP project ID to connect to

    Returns:
        Authenticated BigQuery client configured for project

    Raises:
        AuthenticationError: When GCP authentication fails (exit code 3)
        ProjectNotFoundError: When BigQuery project not found (exit code 4)
    """
    try:
        # Use Application Default Credentials
        credentials, _ = default()
        client = bigquery.Client(credentials=credentials, project=project_id)

        # Verify project access with minimal query
        # Note: This will raise NotFound if project doesn't exist or is inaccessible
        # Add timeout to prevent hanging on slow API calls
        list(client.list_datasets(max_results=1, timeout=30.0))

        return client

    except DefaultCredentialsError:
        raise AuthenticationError(
            message="GCP authentication failed - no credentials found"
        )

    except NotFound:
        raise ProjectNotFoundError(
            message=f"BigQuery project '{project_id}' not found or inaccessible"
        )


def validate_multi_project_permissions(
    storage_project: str, query_project: str | None = None
) -> None:
    """
    Validate BigQuery permissions for multi-project scan.

    Validates that the user has required permissions on both projects:
    - Storage project: bigquery.datasets.get (list_datasets API)
    - Query project: bigquery.jobs.list (list_jobs API)

    Args:
        storage_project: Project containing tables (--project)
        query_project: Optional project running queries (--query-project)

    Raises:
        AuthenticationError: When GCP authentication fails
        ProjectNotFoundError: When project is not found or inaccessible
        PermissionError: When required permissions are missing

    Example:
        >>> validate_multi_project_permissions("my-storage", "my-processing")
        # Validates both projects, raises exception if permissions missing
    """
    # Validate storage project (datasets/tables)
    try:
        storage_client = authenticate_bigquery(storage_project)

        # Test bigquery.datasets.get permission (already done in authenticate_bigquery)
        # Test bigquery.tables.list permission
        datasets = list(storage_client.list_datasets(max_results=1))
        if datasets:
            # Try to list tables in first dataset to verify table-level permissions
            dataset_ref = datasets[0].reference
            list(storage_client.list_tables(dataset_ref, max_results=1))

    except Forbidden:
        raise PermissionError(
            f"Missing required permissions on storage project '{storage_project}'. "
            f"Required: bigquery.metadataViewer or bigquery.tables.get"
        )

    # Validate query project (jobs) if specified
    if query_project and query_project != storage_project:
        try:
            query_client = authenticate_bigquery(query_project)

            # Test bigquery.jobs.list permission
            list(query_client.list_jobs(project=query_project, max_results=1))

        except Forbidden:
            raise PermissionError(
                f"Missing required permissions on query project '{query_project}'. "
                f"Required: bigquery.metadataViewer or bigquery.jobs.list"
            )
