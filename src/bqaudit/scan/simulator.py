"""
Simulated BigQuery scan for Epic 3 testing (Story 3.4, Task 5).

This simulator mimics a real BigQuery audit scan without actually querying
INFORMATION_SCHEMA. The real implementation will come in Epic 4.
"""

import logging
import math
import os
import time

import typer

from bqaudit.scan.models import ScanResult

logger = logging.getLogger(__name__)


def _get_simulation_delay() -> float:
    """
    Get simulation delay with validation.

    Code Review Round 10, Issue #1 & #5: Validate float from environment variable.
    Prevents DoS attacks via inf/nan/negative/excessive delay values.

    Returns:
        Validated float delay in seconds (0.0 to 3600.0)

    Raises:
        ValueError: If delay is invalid (non-numeric, inf, nan, negative, or >1 hour)
    """
    default = "2.0"
    value_str = os.getenv("BQAUDIT_SIMULATED_SCAN_DELAY", default)

    try:
        value = float(value_str)
    except ValueError:
        raise ValueError(
            f"Invalid BQAUDIT_SIMULATED_SCAN_DELAY: {value_str!r}. Must be numeric."
        )

    # Reject special float values (inf, -inf, nan)
    if math.isnan(value) or math.isinf(value):
        raise ValueError(
            f"Invalid BQAUDIT_SIMULATED_SCAN_DELAY: {value_str!r}. "
            "Cannot be NaN or infinity."
        )

    # Reject negative or excessively large delays
    if value < 0 or value > 3600.0:
        raise ValueError(
            f"Invalid BQAUDIT_SIMULATED_SCAN_DELAY: {value}. "
            "Must be between 0 and 3600 seconds (1 hour)."
        )

    return value


# Configurable simulation delay (default 2 seconds for realistic UX, 0.1 for tests)
DEFAULT_SIMULATION_DELAY = _get_simulation_delay()


def simulate_scan(project_id: str, ephemeral_token: str) -> ScanResult:
    """
    Execute a simulated BigQuery scan for Epic 3 testing.

    Epic 4 will replace this with real INFORMATION_SCHEMA extraction.

    Args:
        project_id: GCP project ID to scan
        ephemeral_token: Ephemeral token for scan authentication

    Returns:
        ScanResult with simulated=True flag

    Security:
        - AC4: Token NEVER logged (only project_id logged)
        - AC7: Simulation notice displayed to user
    """
    # AC4: Token NEVER logged - only log project_id
    logger.info(f"Starting simulated scan for project: {project_id}")

    # AC7: Display simulation notice
    typer.echo(f"\n🔍 [SIMULATED] Scanning BigQuery project: {project_id}")
    typer.echo("🔐 [SIMULATED] Using ephemeral token (secured)")
    typer.echo("📊 [SIMULATED] Extracting INFORMATION_SCHEMA metadata...")

    # AC7: Simulate work (configurable delay, default 2 seconds)
    time.sleep(DEFAULT_SIMULATION_DELAY)

    typer.echo("✅ [SIMULATED] Scan completed successfully!")
    typer.echo("\n📝 Note: This is a simulated scan for Epic 3 token testing.")
    typer.echo("   Full BigQuery audit coming in Epic 4.")

    return ScanResult(
        success=True,
        project_id=project_id,
        simulated=True,
        findings=[],
    )
