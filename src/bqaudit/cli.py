"""
CLI entrypoint for bqaudit.

Provides commands: validate, scan, license (activate, status, revoke).
"""

import time

import httpx
import typer
from google.api_core.exceptions import BadRequest, Forbidden, GoogleAPIError, NotFound
from google.auth.exceptions import DefaultCredentialsError
from packaging import version
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typing_extensions import Annotated

from bqaudit import __version__
from bqaudit.api.client import check_server_health
from bqaudit.scanner import (
    AuthenticationError,
    authenticate_bigquery,
)

app = typer.Typer(
    name="bqaudit", help="BigQuery cost optimization audit tool", no_args_is_help=True
)

console = Console()


@app.command()
def validate(
    project: Annotated[
        str, typer.Option("--project", "-p", help="GCP project ID to validate")
    ],
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Show detailed validation steps"),
    ] = False,
) -> None:
    """
    Validate BigQuery access and permissions (0 tokens consumed).

    This command performs pre-flight checks without consuming any tokens:
    - GCP authentication verification
    - BigQuery API enablement check
    - IAM permissions validation
    - Test query execution (LIMIT 1)
    - Server connectivity check

    No data is transmitted to the server during validation.
    No tokens are consumed from your pool.

    Args:
        project: GCP project ID to validate
        verbose: Show detailed validation steps

    Exit Codes:
        0: Validation successful
        1: General error (network, server)
        2: Invalid arguments (handled by Typer)
        3: Authentication failure
        4: BigQuery error (API disabled, permissions)
    """
    # CRITICAL: This command must NEVER consume tokens
    start_time = time.time()

    console.print("\n[bold cyan]🔍 Starting BigQuery Validation...[/bold cyan]\n")

    # Track validation results
    validation_results = []

    # Step 1: GCP Authentication
    try:
        if verbose:
            console.print("[blue]ℹ Checking GCP authentication...[/blue]")

        client = authenticate_bigquery(project)
        console.print("[green]✓ Authentication successful[/green]")
        validation_results.append(("GCP Authentication", "✓", "Authenticated"))

    except (AuthenticationError, DefaultCredentialsError):
        console.print("[red]❌ GCP authentication failed[/red]")
        error_message = _format_error_guidance("auth_fail", project)
        error_panel = Panel(
            error_message,
            title="[red]Validation Failed[/red]",
            border_style="red",
        )
        console.print(error_panel)
        raise typer.Exit(3)

    # Step 2: BigQuery API Enablement Check
    try:
        if verbose:
            console.print("[blue]ℹ Checking BigQuery API enablement...[/blue]")

        # Test query to verify API is enabled
        test_query = "SELECT 1"
        if verbose:
            console.print(f"[dim]  Query: {test_query}[/dim]")

        query_job = client.query(test_query)
        list(query_job.result())  # Execute query

        console.print("[green]✓ BigQuery API enabled[/green]")
        validation_results.append(("BigQuery API", "✓", "Enabled"))

    except Forbidden as e:
        if "BigQuery API has not been used" in str(e) or "disabled" in str(e).lower():
            console.print("[red]❌ BigQuery API not enabled for project[/red]")
            error_message = _format_error_guidance("api_disabled", project)
            error_panel = Panel(
                error_message,
                title="[red]Validation Failed[/red]",
                border_style="red",
            )
            console.print(error_panel)
            raise typer.Exit(4)
        else:
            # Re-raise for permissions check below
            raise

    # Step 3: IAM Permissions Verification
    try:
        if verbose:
            console.print("[blue]ℹ Checking IAM permissions...[/blue]")

        # Test bigquery.tables.get permission
        tables_query = f"""
        SELECT table_catalog, table_schema, table_name
        FROM `{project}.INFORMATION_SCHEMA.TABLES`
        LIMIT 1
        """
        if verbose:
            console.print(f"[dim]  Query: {tables_query.strip()}[/dim]")

        query_job = client.query(tables_query)
        list(query_job.result())  # Execute query

        # Test bigquery.jobs.list permission
        if verbose:
            console.print("[dim]  Testing bigquery.jobs.list permission...[/dim]")

        _ = list(client.list_jobs(project=project, max_results=1))

        console.print("[green]✓ Permissions verified (bigquery.metadataViewer)[/green]")
        validation_results.append(
            ("IAM Permissions", "✓", "bigquery.metadataViewer")
        )

    except Forbidden:
        console.print("[red]❌ Missing required permissions[/red]")
        error_message = _format_error_guidance("permissions_missing", project)
        error_panel = Panel(
            error_message,
            title="[red]Validation Failed[/red]",
            border_style="red",
        )
        console.print(error_panel)
        raise typer.Exit(4)

    # Step 4: Test Query Execution
    try:
        if verbose:
            console.print("[blue]ℹ Running test query...[/blue]")

        test_query = f"""
        SELECT table_catalog, table_schema, table_name
        FROM `{project}.INFORMATION_SCHEMA.TABLES`
        LIMIT 1
        """
        if verbose:
            console.print(f"[dim]  Query: {test_query.strip()}[/dim]")

        query_job = client.query(test_query)
        results = list(query_job.result())

        console.print("[green]✓ Test query successful[/green]")
        validation_results.append(("Test Query", "✓", "Successful"))

    except NotFound:
        console.print("[red]❌ Project not found or no datasets exist[/red]")
        error_message = _format_error_guidance("project_not_found", project)
        error_panel = Panel(
            error_message,
            title="[red]Validation Failed[/red]",
            border_style="red",
        )
        console.print(error_panel)
        raise typer.Exit(4)

    # Step 5: Project Data Sufficiency Check
    try:
        if verbose:
            console.print("[blue]ℹ Checking project data sufficiency...[/blue]")

        count_query = f"""
        SELECT COUNT(*) as table_count
        FROM `{project}.INFORMATION_SCHEMA.TABLES`
        """
        if verbose:
            console.print(f"[dim]  Query: {count_query.strip()}[/dim]")

        query_job = client.query(count_query)
        results = list(query_job.result())

        if not results:
            console.print("[yellow]⚠ Could not retrieve table count[/yellow]")
            validation_results.append(("Project Data", "⚠", "Count unavailable"))
        elif results[0].table_count == 0:
            console.print(
                "[yellow]⚠ Project has no tables - "
                "audit will have limited value[/yellow]"
            )
            validation_results.append(
                ("Project Data", "⚠", "0 tables (limited value)")
            )
        else:
            table_count = results[0].table_count
            console.print(f"[green]✓ Project has {table_count} tables[/green]")
            validation_results.append(("Project Data", "✓", f"{table_count} tables"))

    except (Forbidden, NotFound, BadRequest, GoogleAPIError) as e:
        console.print(f"[yellow]⚠ Could not count tables: {e}[/yellow]")
        validation_results.append(("Project Data", "⚠", "Count failed"))

    # Step 6: Server Connectivity Check
    try:
        if verbose:
            console.print("[blue]ℹ Checking server connectivity...[/blue]")
            console.print("[dim]  GET /v1/health[/dim]")

        health = check_server_health()

        if verbose:
            console.print(f"[dim]  Response: {health}[/dim]")

        console.print("[green]✓ Server connectivity OK[/green]")
        validation_results.append(("Server Health", "✓", "api.bqaudit.com reachable"))

        # Version compatibility check
        min_version = health.get("min_client_version")
        if min_version:
            try:
                current_version = version.parse(__version__)
                required_version = version.parse(min_version)

                if current_version < required_version:
                    console.print(
                        f"[yellow]⚠ CLI update recommended: "
                        f"v{__version__} < v{min_version}[/yellow]"
                    )
                    validation_results.append(
                        ("Version Check", "⚠", f"Update to v{min_version}+")
                    )
                elif verbose:
                    console.print(
                        f"[dim]  Version check: "
                        f"v{__version__} >= v{min_version} ✓[/dim]"
                    )
            except Exception as e:
                if verbose:
                    console.print(f"[dim]  Version check failed: {e}[/dim]")

    except httpx.ConnectError:
        console.print("[red]❌ Cannot reach bqaudit server[/red]")
        error_message = _format_error_guidance("server_unreachable", project)
        error_panel = Panel(
            error_message,
            title="[red]Validation Failed[/red]",
            border_style="red",
        )
        console.print(error_panel)
        raise typer.Exit(1)

    except httpx.TimeoutException:
        console.print("[red]❌ Server timeout (5s)[/red]")
        error_message = _format_error_guidance("server_timeout", project)
        error_panel = Panel(
            error_message,
            title="[red]Validation Failed[/red]",
            border_style="red",
        )
        console.print(error_panel)
        raise typer.Exit(1)

    except httpx.HTTPStatusError as e:
        console.print(f"[red]❌ Server error: HTTP {e.response.status_code}[/red]")
        error_message = _format_error_guidance("server_error", project)
        error_panel = Panel(
            error_message,
            title="[red]Validation Failed[/red]",
            border_style="red",
        )
        console.print(error_panel)
        raise typer.Exit(1)

    except Exception as e:
        console.print(f"[yellow]⚠ Server health check failed: {e}[/yellow]")
        validation_results.append(("Server Health", "⚠", f"Check failed: {e}"))

    # Display validation summary table
    console.print("\n")
    table = Table(
        title="Validation Results", show_header=True, header_style="bold cyan"
    )
    table.add_column("Check", style="cyan", width=25)
    table.add_column("Status", style="green", width=10)
    table.add_column("Details", style="white")

    for check, status, details in validation_results:
        # Color status based on result
        if status == "✓":
            status_style = "green"
        elif status == "⚠":
            status_style = "yellow"
        else:
            status_style = "red"

        table.add_row(check, f"[{status_style}]{status}[/{status_style}]", details)

    console.print(table)

    # Display execution time
    elapsed = time.time() - start_time
    console.print(
        f"\n[green bold]✓ Validation completed in {elapsed:.2f}s[/green bold]\n"
    )


def _format_error_guidance(error_type: str, project_id: str) -> str:
    """
    Format actionable error guidance with exact fix commands.

    Args:
        error_type: Type of error (auth_fail, api_disabled, etc.)
        project_id: GCP project ID for context

    Returns:
        Multi-line string with error guidance and fix commands
    """
    if error_type == "auth_fail":
        return """❌ GCP authentication failed

To fix, run:
    gcloud auth application-default login

For service accounts:
    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json"""

    elif error_type == "api_disabled":
        return f"""❌ BigQuery API not enabled for project: {project_id}

To fix, run:
    gcloud services enable bigquery.googleapis.com --project={project_id}"""

    elif error_type == "permissions_missing":
        return f"""❌ Missing required permissions: \
bigquery.tables.get, bigquery.jobs.list

To fix, run:
    gcloud projects add-iam-policy-binding {project_id} \\
      --member=user:YOUR_EMAIL \\
      --role=roles/bigquery.metadataViewer

Replace YOUR_EMAIL with your GCP account email."""

    elif error_type == "project_not_found":
        return f"""❌ Project not found or no datasets exist

Verify project ID: {project_id}

To list available projects:
    gcloud projects list"""

    elif error_type == "server_unreachable":
        return """❌ Cannot reach bqaudit server (api.bqaudit.com)

Possible causes:
- Check internet connectivity
- Verify firewall/proxy settings allow HTTPS to api.bqaudit.com
- Server may be temporarily down (try again in a few minutes)"""

    elif error_type == "server_timeout":
        return """❌ Server timeout (5 seconds)

Possible causes:
- Slow internet connection
- Server is experiencing high load
- Network latency issues

Try again in a few minutes."""

    elif error_type == "server_error":
        return """❌ Server returned an error response

Possible causes:
- Server is experiencing issues (check https://status.bqaudit.com)
- API endpoint may be temporarily unavailable
- Your request may have triggered a server-side error

Try again in a few minutes. If the problem persists, contact support."""

    else:
        return f"❌ Unknown error type: {error_type}"


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
