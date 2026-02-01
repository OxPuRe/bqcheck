"""Actionable error message formatters for CLI (Story 5.3).

Provides user-friendly error messages with actionable guidance for:
- BigQuery permission errors (AC6)
- Network errors (AC7)
- Timeout errors (AC8)

Design: Error handlers format/display messages and RETURN exit codes.
This allows callers to decide when to exit (e.g., sys.exit(code)),
making the handlers testable and reusable in library contexts.
"""

from typing import NoReturn

from rich.console import Console

from bqaudit.constants import (
    EXIT_SUCCESS,
    EXIT_NETWORK_ERROR,
    EXIT_FILE_ERROR,
    EXIT_AUTH_ERROR,
    EXIT_NO_TOKENS,
    EXIT_RATE_LIMIT,
)


def handle_bigquery_permission_error(
    console: Console, project_id: str, email: str
) -> int:
    """
    Handle BigQuery permission denied errors (AC6).

    Args:
        console: Rich console for output
        project_id: GCP project ID
        email: User email for IAM binding

    Returns:
        EXIT_AUTH_ERROR code (3)
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
    return EXIT_AUTH_ERROR


def handle_network_error(console: Console) -> int:
    """
    Handle network communication errors (AC7).

    Args:
        console: Rich console for output

    Returns:
        EXIT_NETWORK_ERROR code (1)
    """
    console.print("[red]❌ Error: Unable to reach audit server. Check your internet connection.[/red]")
    console.print("\nRetry the scan when connection is restored.")
    console.print("[dim]Your token was not consumed.[/dim]")
    return EXIT_NETWORK_ERROR


def handle_timeout_error(console: Console) -> int:
    """
    Handle server timeout errors (AC8).

    Args:
        console: Rich console for output

    Returns:
        EXIT_NETWORK_ERROR code (1)
    """
    console.print("[red]❌ Error: Audit timeout (>15 minutes). This may indicate a very large project.[/red]")
    console.print("\nContact support if the issue persists.")
    console.print("[dim]Your token was not consumed.[/dim]")
    return EXIT_NETWORK_ERROR


def handle_bigquery_not_found_error(console: Console, project_id: str) -> int:
    """
    Handle BigQuery project not found errors.

    Args:
        console: Rich console for output
        project_id: GCP project ID that was not found

    Returns:
        EXIT_FILE_ERROR code (2)
    """
    console.print(f"[red]❌ Error: Project '{project_id}' not found[/red]")
    console.print("\nVerify the project ID is correct.")
    return EXIT_FILE_ERROR


def handle_bigquery_forbidden_error(console: Console, project_id: str) -> int:
    """
    Handle BigQuery access forbidden errors.

    Args:
        console: Rich console for output
        project_id: GCP project ID

    Returns:
        EXIT_AUTH_ERROR code (3)
    """
    console.print(f"[red]❌ Error: Access denied to project '{project_id}'[/red]")
    console.print("\nEnsure you have access to this project.")
    return EXIT_AUTH_ERROR
