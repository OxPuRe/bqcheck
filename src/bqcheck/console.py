"""Rich console configuration and progress helpers for CLI UX (Story 5.3).

Provides centralized Rich console with progress indicators and styling for:
- Check start/success messages (AC1, AC5)
- Metadata extraction spinner (AC2)
- Server communication progress (AC3)
- Analysis progress with timer (AC4)
"""

import asyncio
from datetime import datetime, timezone

from rich.console import Console
from rich.status import Status

# Initialize Rich console (output to stderr to not interfere with stdout)
console = Console(stderr=True)


def show_start_message(project_id: str) -> None:
    """
    Display sanity check start message (AC1).

    Args:
        project_id: GCP project ID being checked

    Example:
        >>> show_start_message("my-gcp-project")
        🔍 Starting BigQuery sanity check for project: my-gcp-project
    """
    console.print(
        f"🔍 Starting BigQuery sanity check for project: [bold cyan]{project_id}[/bold cyan]"
    )


def show_extraction_progress() -> Status:
    """
    Show spinner during metadata extraction (AC2).

    Returns:
        Rich Status context manager with spinner

    Example:
        >>> with show_extraction_progress():
        ...     # Perform extraction
        ...     metadata = extract_metadata()
    """
    return console.status(
        "[blue]📊 Extracting metadata from INFORMATION_SCHEMA...[/blue]"
    )


def show_server_upload() -> None:
    """
    Display server upload message (AC3).

    Example:
        >>> show_server_upload()
        ☁️  Sending anonymized metadata to analysis server...
    """
    console.print("☁️  Sending anonymized metadata to analysis server...")


def show_success_message(count: int, savings: float) -> None:
    """
    Display sanity check completion success message (AC5).

    Args:
        count: Number of recommendations found
        savings: Total potential monthly savings in EUR

    Example:
        >>> show_success_message(5, 1234.56)
        ✅ Sanity check complete! Found 5 recommendations with potential savings of €1,234.56/month
    """
    console.print(
        f"[green]✅ Sanity check complete![/green] Found {count} recommendations "
        f"with potential savings of €{savings:,.2f}/month"
    )


async def show_analysis_progress() -> None:
    """
    Show analysis progress with elapsed timer (AC4).

    Displays "⚙️  Analyzing BigQuery patterns..." with elapsed time
    updated every 5 seconds. Runs indefinitely until cancelled by caller.

    This is an async coroutine that should be wrapped in an asyncio.Task
    by the caller using asyncio.create_task(), then cancelled when done.

    console.print() is blocking I/O.
    Using run_in_executor() to prevent event loop blocking on slow terminals
    (NFS mounts, SSH lag, pipe redirection).

    Use get_running_loop() instead of deprecated
    get_event_loop() for correct async context behavior (Python 3.10+).

    Added timeout protection on executor tasks
    to prevent deadlock if console.print() hangs (slow SSH, NFS mount, etc).

    Returns:
        None (runs until cancelled, never returns normally)

    Example:
        >>> timer_task = asyncio.create_task(show_analysis_progress())
        >>> try:
        ...     response = await send_check_request()
        ... finally:
        ...     timer_task.cancel()
        ...     try:
        ...         await timer_task
        ...     except asyncio.CancelledError:
        ...         pass
    """
    import logging

    from bqcheck.constants import GLOBAL_CHECK_TIMEOUT_SECONDS

    logger = logging.getLogger(__name__)
    start_time = datetime.now(timezone.utc)
    loop = asyncio.get_running_loop()  # Correct for async context (not deprecated)

    async def safe_print(msg: str, timeout: float = 2.0) -> None:
        """Print with timeout protection to prevent executor thread starvation."""
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, console.print, msg), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(f"Console print timed out after {timeout}s (slow terminal?)")

    # Non-blocking initial message
    await safe_print(
        "⚙️  Analyzing BigQuery patterns (this may take up to 15 minutes)..."
    )

    while True:
        await asyncio.sleep(5)
        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        # Story 5.3: Add max timeout protection to prevent infinite loop
        # Uses same timeout as executor.py execute_check() for consistency
        if elapsed >= GLOBAL_CHECK_TIMEOUT_SECONDS:
            await safe_print(
                f"[yellow]⚠️  Maximum timeout reached ({int(GLOBAL_CHECK_TIMEOUT_SECONDS // 60)} minutes)[/yellow]"
            )
            break

        minutes = int(elapsed // 60)
        seconds = int(elapsed % 60)
        await safe_print(f"⏱️  Elapsed: {minutes}m {seconds}s")
