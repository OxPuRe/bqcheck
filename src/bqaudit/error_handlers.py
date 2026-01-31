"""Actionable error message formatters for CLI (Story 5.3).

Provides user-friendly error messages with actionable guidance for:
- BigQuery permission errors (AC6)
- Network errors (AC7)
- Timeout errors (AC8)
"""

import sys

from rich.console import Console

# Exit codes (from Story 5.1)
EXIT_SUCCESS = 0
EXIT_NETWORK_ERROR = 1
EXIT_FILE_ERROR = 2
EXIT_AUTH_ERROR = 3
EXIT_NO_TOKENS = 4
EXIT_RATE_LIMIT = 5


def handle_bigquery_permission_error(
    console: Console, project_id: str, email: str
) -> None:
    """
    Handle BigQuery permission denied errors (AC6).

    Args:
        console: Rich console for output
        project_id: GCP project ID
        email: User email for IAM binding

    Exits with code 3 (AUTH_ERROR)
    """
    console.print("[red]❌ Error: Insufficient BigQuery permissions[/red]")
    console.print("\nRun this command to grant permissions:")
    console.print(
        f"[yellow]gcloud projects add-iam-policy-binding {project_id} \\[/yellow]"
    )
    console.print(f"[yellow]  --member=user:{email} \\[/yellow]")
    console.print(
        "[yellow]  --role=roles/bigquery.metadataViewer[/yellow]"
    )
    sys.exit(EXIT_AUTH_ERROR)


def handle_network_error(console: Console) -> None:
    """
    Handle network communication errors (AC7).

    Args:
        console: Rich console for output

    Exits with code 1 (NETWORK_ERROR)
    """
    console.print("[red]❌ Error: Unable to reach audit server. Check your internet connection.[/red]")
    console.print("\nRetry the scan when connection is restored.")
    console.print("[dim]Your token was not consumed.[/dim]")
    sys.exit(EXIT_NETWORK_ERROR)


def handle_timeout_error(console: Console) -> None:
    """
    Handle server timeout errors (AC8).

    Args:
        console: Rich console for output

    Exits with code 1 (NETWORK_ERROR)
    """
    console.print("[red]❌ Error: Audit timeout (>15 minutes). This may indicate a very large project.[/red]")
    console.print("\nContact support if the issue persists.")
    console.print("[dim]Your token was not consumed.[/dim]")
    sys.exit(EXIT_NETWORK_ERROR)


def handle_bigquery_not_found_error(console: Console, project_id: str) -> None:
    """
    Handle BigQuery project not found errors.

    Args:
        console: Rich console for output
        project_id: GCP project ID that was not found

    Exits with code 2 (FILE_ERROR)
    """
    console.print(f"[red]❌ Error: Project '{project_id}' not found[/red]")
    console.print("\nVerify the project ID is correct.")
    sys.exit(EXIT_FILE_ERROR)


def handle_bigquery_forbidden_error(console: Console, project_id: str) -> None:
    """
    Handle BigQuery access forbidden errors.

    Args:
        console: Rich console for output
        project_id: GCP project ID

    Exits with code 3 (AUTH_ERROR)
    """
    console.print(f"[red]❌ Error: Access denied to project '{project_id}'[/red]")
    console.print("\nEnsure you have access to this project.")
    sys.exit(EXIT_AUTH_ERROR)
