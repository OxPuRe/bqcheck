"""
Simulated BigQuery scan for Epic 3 testing (Story 3.4, Task 5).

This simulator mimics a real BigQuery sanity check scan without actually querying
INFORMATION_SCHEMA. The real implementation will come in Epic 4.
"""

import logging
import os
import time

import typer

from bqcheck.scan.models import ScanResult

logger = logging.getLogger(__name__)


def _get_simulation_delay() -> float:
    """Get simulation delay from environment variable."""
    return float(os.getenv("BQCHECK_SIMULATED_SCAN_DELAY", "2.0"))


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
    typer.echo("   Full BigQuery sanity check coming in Epic 4.")

    return ScanResult(
        success=True,
        project_id=project_id,
        simulated=True,
        findings=[],
    )
