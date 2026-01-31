"""Rich console configuration and progress helpers for CLI UX (Story 5.3).

Provides centralized Rich console with progress indicators and styling for:
- Audit start/success messages (AC1, AC5)
- Metadata extraction spinner (AC2)
- Server communication progress (AC3)
- Analysis progress with timer (AC4)
"""

import asyncio
from datetime import datetime, timezone

from rich.console import Console

# Initialize Rich console (output to stderr to not interfere with stdout)
console = Console(stderr=True)


def show_start_message(project_id: str) -> None:
    """
    Display audit start message (AC1).

    Args:
        project_id: GCP project ID being audited

    Example:
        >>> show_start_message("my-gcp-project")
        🔍 Starting BigQuery audit for project: my-gcp-project
    """
    console.print(f"🔍 Starting BigQuery audit for project: [bold cyan]{project_id}[/bold cyan]")


def show_extraction_progress() -> Console.status:
    """
    Show spinner during metadata extraction (AC2).

    Returns:
        Rich status context manager with spinner

    Example:
        >>> with show_extraction_progress():
        ...     # Perform extraction
        ...     metadata = extract_metadata()
    """
    return console.status("[blue]📊 Extracting metadata from INFORMATION_SCHEMA...[/blue]")


def show_server_upload() -> None:
    """
    Display server upload message (AC3).

    Example:
        >>> show_server_upload()
        ☁️  Sending anonymized metadata to audit server...
    """
    console.print("☁️  Sending anonymized metadata to audit server...")


def show_success_message(count: int, savings: float) -> None:
    """
    Display audit completion success message (AC5).

    Args:
        count: Number of recommendations found
        savings: Total potential monthly savings in EUR

    Example:
        >>> show_success_message(5, 1234.56)
        ✅ Audit complete! Found 5 recommendations with potential savings of €1,234.56/month
    """
    console.print(
        f"[green]✅ Audit complete![/green] Found {count} recommendations "
        f"with potential savings of €{savings:,.2f}/month"
    )


async def show_analysis_progress() -> asyncio.Task:
    """
    Show analysis progress with elapsed timer (AC4).

    Displays "⚙️  Analyzing BigQuery patterns..." with elapsed time
    updated every 5 seconds.

    Returns:
        Async task that updates timer (should be cancelled when done)

    Example:
        >>> timer_task = asyncio.create_task(show_analysis_progress())
        >>> try:
        ...     response = await send_audit_request()
        ... finally:
        ...     timer_task.cancel()
        ...     try:
        ...         await timer_task
        ...     except asyncio.CancelledError:
        ...         pass
    """
    start_time = datetime.now(timezone.utc)
    console.print("⚙️  Analyzing BigQuery patterns (this may take up to 15 minutes)...")

    while True:
        await asyncio.sleep(5)
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        console.print(f"⏱️  Elapsed: {minutes}m {seconds}s")
