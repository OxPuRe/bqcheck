"""
Simulated BigQuery scan for local testing.

This simulator mimics a real BigQuery sanity check scan without actually querying
INFORMATION_SCHEMA.
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
    Execute a simulated BigQuery scan for local testing.

    Args:
        project_id: GCP project ID to scan
        ephemeral_token: Ephemeral token for scan authentication

    Returns:
        ScanResult with simulated=True flag

    Security:
        - Token NEVER logged (only project_id logged)
        - Simulation notice displayed to user
    """
    # Token NEVER logged - only log project_id
    logger.info(f"Starting simulated scan for project: {project_id}")

    # Display simulation notice
    typer.echo(f"\n🔍 [SIMULATED] Scanning BigQuery project: {project_id}")
    typer.echo("🔐 [SIMULATED] Using ephemeral token (secured)")
    typer.echo("📊 [SIMULATED] Extracting INFORMATION_SCHEMA metadata...")

    # Simulate work (configurable delay, default 2 seconds)
    time.sleep(DEFAULT_SIMULATION_DELAY)

    typer.echo("✅ [SIMULATED] Scan completed successfully!")
    typer.echo("\n📝 Note: This is a simulated scan for local testing.")
    typer.echo("   Set BQCHECK_REAL_SCAN=true to run a real BigQuery sanity check.")

    return ScanResult(
        success=True,
        project_id=project_id,
        simulated=True,
        findings=[],
    )
