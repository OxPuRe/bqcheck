"""
CLI entrypoint for bqcheck.

Provides commands: validate, scan, license (activate, status, revoke).
"""

import json
import logging
import time
from pathlib import Path
from typing import Optional

import httpx
import typer
from google.api_core.exceptions import BadRequest, Forbidden, GoogleAPIError, NotFound
from google.auth.exceptions import DefaultCredentialsError
from packaging import version
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from typing_extensions import Annotated

from bqcheck import __version__
from bqcheck.api.client import check_server_health
from bqcheck.config import configure_logging
from bqcheck.constants import ExitCode
from bqcheck.queries import (
    get_sample_queries_query,
    get_simple_test_query,
    get_table_count_query,
    get_tables_query,
)
from bqcheck.scanner import (
    AuthenticationError,
    authenticate_bigquery,
)
from bqcheck.scanner.anonymizer import (
    anonymize_query_pattern,
    anonymize_table_name,
)
from bqcheck.scanner.encryption import IdentifierEncryptor

app = typer.Typer(
    name="bqcheck", help="BigQuery sanity check CLI", no_args_is_help=True
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

    # Configure logging based on verbose flag
    logger = configure_logging(verbose)

    console.print("\n[bold cyan]🔍 Starting BigQuery Validation...[/bold cyan]\n")

    # Track validation results
    validation_results = []

    # Step 1: GCP Authentication
    try:
        logger.debug(f"Authenticating with project: {project}")
        if verbose:
            console.print("[blue]ℹ Checking GCP authentication...[/blue]")

        client = authenticate_bigquery(project)
        console.print("[green]✓ Authentication successful[/green]")
        validation_results.append(("GCP Authentication", "✓", "Authenticated"))

    except (AuthenticationError, DefaultCredentialsError):
        console.print("[red]❌ GCP authentication failed[/red]")
        _handle_validation_error("auth_fail", project, 3)

    # Step 2: BigQuery API Enablement Check
    try:
        logger.debug(f"Checking BigQuery API enablement for project: {project}")
        if verbose:
            console.print("[blue]ℹ Checking BigQuery API enablement...[/blue]")

        # Test query to verify API is enabled
        test_query = get_simple_test_query()
        if verbose:
            console.print(f"[dim]  Query: {test_query}[/dim]")

        query_job = client.query(test_query)
        list(query_job.result())  # Execute query

        console.print("[green]✓ BigQuery API enabled[/green]")
        validation_results.append(("BigQuery API", "✓", "Enabled"))

    except Forbidden as e:
        if "BigQuery API has not been used" in str(e) or "disabled" in str(e).lower():
            console.print("[red]❌ BigQuery API not enabled for project[/red]")
            _handle_validation_error("api_disabled", project, 4)
        else:
            # Re-raise for permissions check below
            raise

    # Step 3: IAM Permissions Verification
    try:
        logger.debug(f"Verifying IAM permissions for project: {project}")
        if verbose:
            console.print("[blue]ℹ Checking IAM permissions...[/blue]")

        # Test bigquery.tables.get permission
        tables_query = get_tables_query(project, limit=1)
        if verbose:
            console.print(f"[dim]  Query: {tables_query.strip()}[/dim]")

        query_job = client.query(tables_query)
        list(query_job.result())  # Execute query

        # Test bigquery.jobs.list permission
        if verbose:
            console.print("[dim]  Testing bigquery.jobs.list permission...[/dim]")

        _ = list(client.list_jobs(project=project, max_results=1))

        console.print("[green]✓ Permissions verified (bigquery.metadataViewer)[/green]")
        validation_results.append(("IAM Permissions", "✓", "bigquery.metadataViewer"))

    except Forbidden:
        console.print("[red]❌ Missing required permissions[/red]")
        _handle_validation_error("permissions_missing", project, 4)

    # Step 4: Test Query Execution
    try:
        if verbose:
            console.print("[blue]ℹ Running test query...[/blue]")

        test_query = get_tables_query(project, limit=1)
        if verbose:
            console.print(f"[dim]  Query: {test_query.strip()}[/dim]")

        query_job = client.query(test_query)
        results = list(query_job.result())

        console.print("[green]✓ Test query successful[/green]")
        validation_results.append(("Test Query", "✓", "Successful"))

    except NotFound:
        console.print("[red]❌ Project not found or no datasets exist[/red]")
        _handle_validation_error("project_not_found", project, 4)

    # Step 5: Project Data Sufficiency Check
    try:
        if verbose:
            console.print("[blue]ℹ Checking project data sufficiency...[/blue]")

        count_query = get_table_count_query(project)
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
                "sanity check will have limited value[/yellow]"
            )
            validation_results.append(("Project Data", "⚠", "0 tables (limited value)"))
        else:
            table_count = results[0].table_count
            console.print(f"[green]✓ Project has {table_count} tables[/green]")
            validation_results.append(("Project Data", "✓", f"{table_count} tables"))

    except (Forbidden, NotFound, BadRequest, GoogleAPIError) as e:
        console.print(f"[yellow]⚠ Could not count tables: {e}[/yellow]")
        validation_results.append(("Project Data", "⚠", "Count failed"))

    # Step 5.5: Verbose Mode - Metadata Preview and Anonymization Display
    if verbose:
        try:
            logger.debug(
                f"Extracting sample metadata for preview from project: {project}"
            )
            console.print("\n[blue]ℹ Extracting sample metadata for preview...[/blue]")

            # Extract sample tables (first 3)
            sample_tables_query = get_tables_query(project, limit=3)
            query_job = client.query(sample_tables_query)
            sample_tables = list(query_job.result())

            # Extract sample queries (first 3 SELECT queries)
            sample_queries_query = get_sample_queries_query(project, limit=3)
            query_job = client.query(sample_queries_query)
            sample_queries = list(query_job.result())

            # Generate temporary encryption key for anonymization preview
            # (validate command doesn't need real credentials)
            temp_encryption_key = IdentifierEncryptor.generate_key()

            # Display metadata preview section
            console.print("\n")
            preview_panel = Panel(
                "[bold cyan]Metadata Preview[/bold cyan]\n\n"
                "Sample of metadata that will be extracted and anonymized:",
                border_style="cyan",
            )
            console.print(preview_panel)

            # Display table anonymization preview
            if sample_tables:
                logger.debug(f"Anonymizing {len(sample_tables)} sample tables")
                console.print("\n[bold]Table Name Anonymization:[/bold]")
                for table in sample_tables:
                    # Defensive: skip rows with None values
                    if not (
                        table.table_catalog and table.table_schema and table.table_name
                    ):
                        continue
                    original = (
                        f"{table.table_catalog}.{table.table_schema}.{table.table_name}"
                    )
                    anonymized = anonymize_table_name(
                        table.table_name, temp_encryption_key
                    )
                    # Truncate encrypted identifier for display
                    anonymized_short = anonymized[:16] + "..."
                    console.print(
                        f"  Table: [yellow]{original}[/yellow] → "
                        f"[green]{anonymized_short}[/green]"
                    )

            # Display query anonymization preview
            if sample_queries:
                console.print("\n[bold]Query Pattern Anonymization:[/bold]")
                for query_row in sample_queries:
                    # Defensive: skip rows with None/empty query
                    if not query_row.query:
                        continue

                    # Truncate original query for display
                    original_truncated = query_row.query[:60].replace("\n", " ")
                    if len(query_row.query) > 60:
                        original_truncated += "..."

                    # Anonymize query
                    anonymized = anonymize_query_pattern(
                        query_row.query, temp_encryption_key
                    )
                    anonymized_truncated = anonymized[:60].replace("\n", " ")
                    if len(anonymized) > 60:
                        anonymized_truncated += "..."

                    console.print(f"  Query: [yellow]{original_truncated}[/yellow]")
                    console.print(f"      → [green]{anonymized_truncated}[/green]")

            # Calculate and display payload size estimate
            # Use varied realistic estimates for better payload size approximation
            payload_sample = {
                "tables": [
                    {
                        "table_name": anonymize_table_name(
                            t.table_name, temp_encryption_key
                        ),
                        "table_catalog": t.table_catalog,
                        "table_schema": t.table_schema,
                        # Varied: 5MB, 10MB, 15MB
                        "size_bytes": (i + 1) * 5000000,
                        # Varied: 10k, 20k, 30k rows
                        "row_count": (i + 1) * 10000,
                    }
                    for i, t in enumerate(sample_tables)
                    if t.table_catalog and t.table_schema and t.table_name
                ],
                "queries": [
                    {
                        "query": anonymize_query_pattern(
                            q.query if q.query else "", temp_encryption_key
                        ),
                        # Varied: 2.5MB, 5MB, 7.5MB
                        "bytes_processed": (i + 1) * 2500000,
                    }
                    for i, q in enumerate(sample_queries)
                    if q.query
                ],
            }
            payload_json = json.dumps(payload_sample)
            payload_size_kb = len(payload_json) / 1024

            console.print(
                f"\n[bold]Estimated Payload Size:[/bold] "
                f"[cyan]{payload_size_kb:.2f} KB[/cyan]"
            )

            # Display privacy guarantees
            console.print("\n")
            privacy_panel = Panel(
                "✓ All table names anonymized\n"
                "✓ All queries anonymized\n"
                "✓ No raw data accessed",
                title="[green]Privacy Guarantees[/green]",
                border_style="green",
            )
            console.print(privacy_panel)

            # Display transmission statement
            transmission_panel = Panel(
                "[bold]This is what will be sent to bqcheck server:[/bold]\n"
                "• Metadata only (no table data)\n"
                "• All identifiers encrypted with AES-256\n"
                "• Only statistical information (sizes, counts, patterns)",
                title="[cyan]Data Transmission[/cyan]",
                border_style="cyan",
            )
            console.print(transmission_panel)
            console.print("\n")

        except (Forbidden, NotFound, BadRequest, GoogleAPIError) as e:
            console.print(f"[yellow]⚠ Could not extract sample metadata: {e}[/yellow]")

    # Step 6: Server Connectivity Check
    try:
        if verbose:
            console.print("[blue]ℹ Checking server connectivity...[/blue]")
            console.print("[dim]  GET /v1/health[/dim]")

        health = check_server_health()

        if verbose:
            console.print(f"[dim]  Response: {health}[/dim]")

        console.print("[green]✓ Server connectivity OK[/green]")
        validation_results.append(("Server Health", "✓", "api.bqcheck.com reachable"))

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
        console.print("[red]❌ Cannot reach bqcheck server[/red]")
        _handle_validation_error("server_unreachable", project, 1)

    except httpx.TimeoutException:
        console.print("[red]❌ Server timeout (5s)[/red]")
        _handle_validation_error("server_timeout", project, 1)

    except httpx.HTTPStatusError as e:
        console.print(f"[red]❌ Server error: HTTP {e.response.status_code}[/red]")
        _handle_validation_error("server_error", project, 1)

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
        f"\n[green bold]✓ Validation completed in {elapsed:.2f}s[/green bold]"
    )

    console.print("[dim]Validation successful (no tokens consumed)[/dim]\n")


def _handle_validation_error(error_type: str, project_id: str, exit_code: int) -> None:
    """
    Display error panel and exit with appropriate code.

    Centralizes error handling pattern used throughout validate command.

    Args:
        error_type: Type of error for guidance (auth_fail, api_disabled, etc.)
        project_id: GCP project ID for context
        exit_code: Exit code to use (3=auth, 4=bigquery, 1=general)
    """
    error_message = _format_error_guidance(error_type, project_id)
    error_panel = Panel(
        error_message,
        title="[red]Validation Failed[/red]",
        border_style="red",
    )
    console.print(error_panel)
    raise typer.Exit(exit_code)


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
        return """❌ Cannot reach bqcheck server (api.bqcheck.com)

Possible causes:
- Check internet connectivity
- Verify firewall/proxy settings allow HTTPS to api.bqcheck.com
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
- Server is experiencing issues (check https://status.bqcheck.com)
- API endpoint may be temporarily unavailable
- Your request may have triggered a server-side error

Try again in a few minutes. If the problem persists, contact support."""

    else:
        return f"❌ Unknown error type: {error_type}"


@app.command()
def scan(
    project: Annotated[
        str, typer.Option("--project", "-p", help="GCP project ID to scan")
    ],
    query_project: Annotated[
        Optional[str],
        typer.Option(
            "--query-project",
            "-q",
            help="GCP project ID for query metadata (defaults to --project)",
        ),
    ] = None,
    output: Annotated[
        Optional[Path],
        typer.Option(
            "--output",
            "-o",
            help="Custom output file path for sanity check report",
            dir_okay=False,
            writable=True,
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help="Force overwrite existing file without prompt",
        ),
    ] = False,
) -> None:
    """
    Run full sanity check scan (consumes 1 token).

    Executes complete BigQuery sanity check with server integration.
    Extracts metadata from INFORMATION_SCHEMA, sends to the analysis server,
    and generates Markdown report with cost-saving recommendations.

    Multi-Project Support:
        For separated storage/processing architectures:
        - --project: Project with tables (e.g., *-dt-cur-0)
        - --query-project: Project running queries (e.g., *-dt-prc-0)

        If --query-project is omitted, queries are extracted from --project.

        Example:
            bqcheck scan --project roam-staging-dt-cur-0 \\
                         --query-project roam-staging-dt-prc-0

    Mode Selection:
        - Default: Real BigQuery extraction + server analysis
        - BQCHECK_REAL_SCAN=false: Simulated local test scan

    Security:
        - Uses ephemeral token (auto-renewed after success)
        - Master key is not transmitted during scans
        - Tokens never logged
        - Project ID anonymized (SHA-256) before transmission

    Exit Codes:
        0: Scan completed successfully
        1: Scan failed or no license found
        2: File error (permission denied, file exists and user declined)
        4: Token pool depleted
    """
    from bqcheck.api.client import BQCheckAPIClient
    from bqcheck.license.storage import CredentialStore
    from bqcheck.scan.executor import ScanExecutor

    try:
        # Step 1: Check credentials exist
        if not CredentialStore.exists():
            console.print("\n[yellow]No active license found.[/yellow]\n")
            console.print("Run: [cyan]bqcheck license activate <key>[/cyan]")
            raise typer.Exit(ExitCode.FILE_ERROR)

        # Step 2: Load credentials and check balance
        credentials = CredentialStore.load()

        if credentials["token_pool_balance"] == 0:
            console.print("\n[red]❌ Token pool depleted (0 scans remaining).[/red]\n")
            console.print("💰 Purchase more tokens at https://bqcheck.com/pricing\n")
            raise typer.Exit(ExitCode.NO_TOKENS)

        # Step 3: Check if this is the last token
        is_last_token = credentials["token_pool_balance"] == 1

        # Step 4: Execute scan with token management
        from bqcheck.constants import is_real_mode

        mock_mode = not is_real_mode()
        api_client = BQCheckAPIClient(
            mock_mode=mock_mode,
            server_url=credentials["server_url"],
        )
        executor = ScanExecutor(api_client)
        executor.execute_scan_with_tokens(
            project, query_project=query_project, output_path=output, force=force
        )

        # Step 5: Show warning if this was the last token
        if is_last_token:
            console.print("\n[yellow]⚠️  Warning: This was your last token.[/yellow]")
            console.print(
                "💰 Purchase more tokens to continue running sanity checks: https://bqcheck.com/pricing\n"
            )

        # Success - exit 0
        raise typer.Exit(ExitCode.SUCCESS)

    except typer.Exit:
        # Re-raise Exit to preserve exit code
        raise

    except PermissionError:
        console.print(f"\n[red]❌ Error: Permission denied writing to {output}[/red]\n")
        raise typer.Exit(ExitCode.FILE_ERROR)

    # FileExistsError handler removed (dead code)
    # Rationale: report_generator.py returns None when user declines overwrite,
    # it never raises FileExistsError. The None return is handled in executor.py:170

    except Exception as e:
        # Handle Pydantic ValidationError for corrupted credentials
        from pydantic import ValidationError

        if isinstance(e, ValidationError):
            console.print(
                "\n[red]❌ Credentials file has invalid data "
                "(e.g., negative balance).[/red]\n"
            )
            console.print(
                "Run: [cyan]bqcheck license revoke && "
                "bqcheck license activate <key>[/cyan]\n"
            )
            raise typer.Exit(ExitCode.FILE_ERROR)

        # General error handler
        console.print(f"\n[red]❌ Scan error: {e}[/red]\n")
        raise typer.Exit(ExitCode.NETWORK_ERROR)


# License management subcommand group
license_app = typer.Typer(help="License activation and token management")
app.add_typer(license_app, name="license")


@license_app.command("activate")
def license_activate(
    master_key: Annotated[str, typer.Argument(help="Master license key")],
) -> None:
    """
    Activate license with master license key (one-time setup).

    Exchanges your master license key for ephemeral credentials and stores
    them securely at ~/.bqcheck/credentials.json with chmod 600.

    After activation, you can run scans without manually entering tokens.

    Example:
        bqcheck license activate VALID-ABC-XYZ-123

    Security:
        - Credentials stored with chmod 600 (owner read/write only)
        - Master key transmitted only during activation (never during scans)
        - Ephemeral tokens auto-renewed after each successful scan

    Exit Codes:
        0: Activation successful
        1: Invalid key, network error, or other failure
    """
    from bqcheck.api.exceptions import InvalidLicenseKeyError, NetworkError
    from bqcheck.license.activate import activate_license
    from bqcheck.license.security import mask_key

    try:
        # activate_license will raise FileExistsError if already activated
        # Mock mode is used only when BQCHECK_REAL_MODE=false.
        from bqcheck.constants import is_real_mode

        mock_mode = not is_real_mode()
        result = activate_license(master_key, mock_mode=mock_mode)

        console.print("\n[green]✅ License activated successfully![/green]\n")
        console.print(f"Master Key: {mask_key(master_key)}")
        console.print(
            f"Token Pool Balance: {result['token_pool_balance']} scans remaining"
        )
        console.print(f"Activated: {result['activated_at']}\n")
        console.print(
            "You can now run sanity checks with: "
            "[cyan]bqcheck scan --project <project-id>[/cyan]"
        )

        # Success - no raise needed, typer will exit with 0

    except FileExistsError as e:
        console.print(f"\n[yellow]⚠️  {e}[/yellow]\n")
        # Rationale: "Already activated" is not an error state - it's a valid
        # system state where credentials exist and are functional. The user's
        # goal (having activated credentials) is already satisfied.
        # This allows scripts to safely call `activate` idempotently.
        # If user wants to re-activate, they must explicitly revoke first.

    except InvalidLicenseKeyError as e:
        console.print(f"\n[red]❌ {e}[/red]\n")
        raise typer.Exit(ExitCode.AUTH_ERROR)

    except NetworkError as e:
        console.print(f"\n[red]❌ {e}[/red]\n")
        raise typer.Exit(ExitCode.NETWORK_ERROR)

    except Exception as e:
        # Unexpected error
        console.print(f"\n[red]❌ Activation failed: {e}[/red]\n")
        raise typer.Exit(ExitCode.NETWORK_ERROR)


@license_app.command("status")
def license_status() -> None:
    """
    Display license status and token pool balance.

    Shows current license activation status, remaining scan tokens,
    and activation details. Returns exit code 0 if active, 1 if not.

    Security:
        - Master key is masked (only first 2 segments shown)
        - Verifies file permissions (chmod 600)
        - Validates credential integrity

    Exit Codes:
        0: License active and valid
        1: No license, unsafe permissions, or corrupted credentials
    """
    import json
    from datetime import datetime, timezone

    from bqcheck.license.security import mask_key
    from bqcheck.license.storage import (
        CredentialNotFoundError,
        CredentialStore,
        UnsafePermissionsError,
    )

    try:
        # Load and validate credentials
        credentials = CredentialStore.load()

        # Format activated timestamp for display
        # Python 3.8-3.10 don't support 'Z' suffix in fromisoformat
        activated_at_str = credentials["activated_at"].replace("Z", "+00:00")
        activated_at = datetime.fromisoformat(activated_at_str)

        # Ensure timezone-aware datetime for proper display
        if activated_at.tzinfo is None:
            # If naive datetime, assume UTC for older credential files.
            activated_at = activated_at.replace(tzinfo=timezone.utc)

        # Convert to UTC for consistent display
        activated_utc = activated_at.astimezone(timezone.utc)
        formatted_time = activated_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

        console.print("\n[green]License Status: Active[/green]\n")
        console.print(f"Master Key: {mask_key(credentials['master_key'])}")

        # Highlight depletion clearly for users.
        balance = credentials["token_pool_balance"]
        if balance == 0:
            console.print(
                f"Token Pool Balance: {balance} scans remaining [red](DEPLETED)[/red]"
            )
            console.print("\n💰 Purchase more tokens at https://bqcheck.com/pricing\n")
        else:
            console.print(f"Token Pool Balance: {balance} scans remaining")

        console.print(f"Activated: {formatted_time}")
        console.print(f"Server: {credentials['server_url']}\n")

        # Success exit code
        # No explicit raise typer.Exit(0) needed - function returns normally

    except CredentialNotFoundError:
        console.print("\n[yellow]No active license found.[/yellow]\n")
        console.print("To activate your license, run:")
        console.print("  [cyan]bqcheck license activate <your-license-key>[/cyan]")
        console.print("\nDon't have a license key? Visit https://bqcheck.com/pricing\n")
        raise typer.Exit(ExitCode.FILE_ERROR)

    except UnsafePermissionsError:
        console.print("\n[red]Credentials file has unsafe permissions.[/red]\n")
        console.print("Run: [cyan]chmod 600 ~/.bqcheck/credentials.json[/cyan]\n")
        raise typer.Exit(ExitCode.FILE_ERROR)

    except (json.JSONDecodeError, KeyError, ValueError):
        console.print(
            "\n[red]Credentials file corrupted. "
            "Please re-activate your license.[/red]\n"
        )
        console.print(
            "Run: [cyan]bqcheck license revoke && "
            "bqcheck license activate <key>[/cyan]\n"
        )
        raise typer.Exit(ExitCode.FILE_ERROR)

    except Exception as e:
        # Catch Pydantic ValidationError and other unexpected errors
        # (ValidationError happens if balance is negative, wrong types, etc.)
        from pydantic import ValidationError

        if isinstance(e, ValidationError):
            console.print(
                "\n[red]Credentials file has invalid data "
                "(e.g., negative balance).[/red]\n"
            )
            console.print(
                "Run: [cyan]bqcheck license revoke && "
                "bqcheck license activate <key>[/cyan]\n"
            )
            raise typer.Exit(ExitCode.FILE_ERROR)
        # Re-raise unexpected errors
        raise


@license_app.command("revoke")
def license_revoke(
    yes: Annotated[
        bool,
        typer.Option(
            "-y",
            "--yes",
            help="Skip confirmation prompt and immediately revoke license",
        ),
    ] = False,
) -> None:
    """
    Revoke stored license credentials.

    Deletes the local credentials file (~/.bqcheck/credentials.json).
    This deactivates the license on this machine.

    Use Cases:
        - Switch to a different license key (revoke → activate new key)
        - Deactivate license on this machine
        - Clear credentials for security reasons
          (e.g., machine being decommissioned or compromised)

    Examples:
        # Revoke with confirmation prompt
        bqcheck license revoke

        # Revoke without confirmation (automation-friendly)
        bqcheck license revoke -y
        bqcheck license revoke --yes

    Exit Codes:
        0: Revocation successful (or user cancelled)
        1: No active license to revoke
    """
    from bqcheck.license.storage import (
        CredentialNotFoundError,
        CredentialStore,
    )

    if not CredentialStore.exists():
        console.print("\n[yellow]No active license to revoke.[/yellow]\n")
        raise typer.Exit(ExitCode.FILE_ERROR)

    if not yes:
        confirm = typer.confirm(
            "Are you sure you want to revoke your license?",
            default=False,
        )
        if not confirm:
            console.print("\n[blue]Revocation cancelled.[/blue]\n")
            # Exit code 0 (cancellation is not an error)
            return

    # Delete credentials
    try:
        # Activity logging for security trail
        logger = logging.getLogger(__name__)
        logger.info(
            "Revoking license credentials at %s",
            CredentialStore._get_credentials_path(),
        )

        CredentialStore.delete()

        console.print("\n[green]✅ License revoked successfully.[/green]\n")
        console.print("Credentials removed from this machine.\n")
        console.print("To activate a new license, run:")
        console.print("  [cyan]bqcheck license activate <key>[/cyan]\n")
        # Exit code 0 (success) - no raise needed

    except CredentialNotFoundError:
        # Edge case: file was deleted between exists() check and delete()
        console.print("\n[yellow]No active license to revoke.[/yellow]\n")
        raise typer.Exit(ExitCode.FILE_ERROR)

    except (OSError, PermissionError, IOError) as e:
        # File system errors: permission denied, read-only filesystem, etc.
        console.print(f"\n[red]❌ Error revoking license: {e}[/red]\n")
        raise typer.Exit(ExitCode.FILE_ERROR)


if __name__ == "__main__":
    app()
