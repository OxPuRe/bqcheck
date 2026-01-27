"""BigQuery client authentication and initialization."""

from google.auth import default
from google.auth.exceptions import DefaultCredentialsError
from google.api_core.exceptions import NotFound
from google.cloud import bigquery


class AuthenticationError(Exception):
    """Raised when GCP authentication fails."""

    def __init__(self, message: str, action: str):
        self.message = message
        self.action = action
        super().__init__(message)


class ProjectNotFoundError(Exception):
    """Raised when BigQuery project is not found or inaccessible."""

    def __init__(self, message: str, action: str):
        self.message = message
        self.action = action
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
        list(client.list_datasets(max_results=1))

        return client

    except DefaultCredentialsError:
        raise AuthenticationError(
            message="GCP authentication failed - no credentials found",
            action="Run: gcloud auth application-default login",
        )

    except NotFound:
        raise ProjectNotFoundError(
            message=f"BigQuery project '{project_id}' not found or inaccessible",
            action="Verify project ID and ensure BigQuery API is enabled",
        )
