"""
CLI entrypoint for bqaudit.

Provides commands: validate, scan, license (activate, status, revoke).
"""

import sys

import typer
from rich.console import Console
from typing_extensions import Annotated

from bqaudit.scanner import (
    AuthenticationError,
    ProjectNotFoundError,
    authenticate_bigquery,
)

app = typer.Typer(
    name="bqaudit", help="BigQuery cost optimization audit tool", no_args_is_help=True
)

console = Console()


@app.command()
def validate(
    project: Annotated[
        str, typer.Option("--project", help="GCP project ID to audit")
    ],
) -> None:
    """Validate BigQuery access without consuming tokens."""
    console.print(f"[blue]Validating access to project:[/blue] {project}")

    try:
        # Authenticate and verify project access
        _client = authenticate_bigquery(project)

        console.print("[green]✓ Authentication successful[/green]")
        console.print(f"[green]✓ BigQuery project '{project}' is accessible[/green]")

    except AuthenticationError as e:
        console.print(f"[red]✗ Authentication failed:[/red] {e.message}")
        console.print(f"[yellow]→ Action:[/yellow] {e.action}")
        sys.exit(3)

    except ProjectNotFoundError as e:
        console.print(f"[red]✗ Project error:[/red] {e.message}")
        console.print(f"[yellow]→ Action:[/yellow] {e.action}")
        sys.exit(4)


@app.command()
def scan(
    project_id: Annotated[str, typer.Argument(help="GCP project ID to scan")],
) -> None:
    """Run full audit scan (consumes 1 token)."""
    typer.echo("Scan command - placeholder")


# License management subcommand group
license_app = typer.Typer(help="License activation and token management")
app.add_typer(license_app, name="license")


@license_app.command("activate")
def license_activate(
    master_key: Annotated[str, typer.Argument(help="Master license key")],
) -> None:
    """Activate license with master license key."""
    typer.echo("License activate command - placeholder")


@license_app.command("status")
def license_status() -> None:
    """Check token balance and license status."""
    typer.echo("License status command - placeholder")


@license_app.command("revoke")
def license_revoke() -> None:
    """Revoke credentials and clear local license."""
    typer.echo("License revoke command - placeholder")


if __name__ == "__main__":
    app()
