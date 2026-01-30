"""
Scan executor with token lifecycle management (Story 3.4, Task 2).

Manages ephemeral token lifecycle:
- Load credentials
- Execute scan (simulated for Epic 3)
- Renew token after success
- Atomic token consumption (preserve on failure)
"""

import logging

import typer

from bqaudit.api.client import BQAuditAPIClient
from bqaudit.license.storage import (
    CredentialNotFoundError,
    CredentialStore,
    UnsafePermissionsError,
)
from bqaudit.scan.models import ScanResult
from bqaudit.scan.simulator import simulate_scan

logger = logging.getLogger(__name__)


class ScanExecutor:
    """
    Manages scan execution with automatic token lifecycle.

    Responsibilities:
    - Load credentials from storage
    - Execute scan with ephemeral token
    - Renew token after successful scan (AC3)
    - Preserve token on failure (AC2 - atomic consumption)
    - Update credentials atomically (AC6)
    """

    def __init__(self, api_client: BQAuditAPIClient):
        """
        Initialize scan executor.

        Args:
            api_client: API client for token renewal
        """
        self.api_client = api_client

    def execute_scan_with_tokens(self, project_id: str) -> ScanResult:
        """
        Execute scan with automatic token management.

        Process:
        1. Load credentials
        2. Execute scan (simulated for Epic 3)
        3. On success: renew token + decrement balance + save
        4. On failure: preserve token (atomic consumption)

        Args:
            project_id: GCP project ID to scan

        Returns:
            ScanResult with scan results

        Raises:
            Exception: If scan fails (token preserved - AC2)

        Security:
        - AC4: Tokens NEVER logged
        - AC5: Master key ONLY for renewal (not during scan)
        """
        # Step 1: Load credentials (with specific error handling)
        try:
            credentials = CredentialStore.load()
        except CredentialNotFoundError:
            typer.echo("❌ Error: No active license found.")
            typer.echo("Run: bqaudit license activate <your-license-key>")
            raise
        except UnsafePermissionsError:
            typer.echo("❌ Error: Credentials file has unsafe permissions.")
            typer.echo("Run: chmod 600 ~/.bqaudit/credentials.json")
            raise
        except Exception as e:
            # Handle Pydantic ValidationError for corrupted credentials
            from pydantic import ValidationError

            if isinstance(e, ValidationError):
                typer.echo("❌ Error: Credentials file has invalid data (e.g., negative balance).")
                typer.echo("Run: bqaudit license revoke && bqaudit license activate <key>")
                raise
            # Re-raise other exceptions
            raise

        # Step 2: Execute scan (SIMULATED for Epic 3)
        try:
            # AC1, AC7: Simulated scan
            # AC4: Token never logged - passed to simulator but not logged
            result = self._execute_simulated_scan(
                project_id, credentials["ephemeral_token"]
            )

            # Step 3: Report success to server (AC1)
            self.api_client.report_scan_success(
                project_id,
                {"simulated": result.simulated, "success": result.success}
            )

            # Step 4: Renew token (AC3)
            # AC5: Master key ONLY for renewal (not during scan)
            new_token_data = self.api_client.renew_token(
                credentials["master_key"],
                current_balance=credentials["token_pool_balance"]
            )

            # Step 5: Update credentials atomically (AC6, AC8)
            # AC8: Mark old token as used (client-side tracking)
            old_token = credentials["ephemeral_token"]
            credentials["ephemeral_token"] = new_token_data.ephemeral_token

            # Track used tokens (AC8: Single-use enforcement)
            if "used_tokens" not in credentials:
                credentials["used_tokens"] = []
            credentials["used_tokens"].append({
                "token": old_token[:16] + "...",  # Truncated for security
                "used_at": new_token_data.ephemeral_token,  # Use new token timestamp as proxy
            })
            # Keep only last 5 used tokens to prevent bloat
            credentials["used_tokens"] = credentials["used_tokens"][-5:]

            # Use server-provided balance (server decrements on its side)
            # In mock mode: mock calculates new_balance = current - 1
            # In real mode: server tracks balance and returns new balance
            credentials["token_pool_balance"] = new_token_data.token_pool_balance
            CredentialStore.update(credentials)

            # AC1: Display success with balance
            typer.echo(f"\n✅ Scan completed successfully!")
            typer.echo(
                f"Token pool balance: {credentials['token_pool_balance']} scans remaining\n"
            )

            return result

        except Exception as e:
            # AC2: CRITICAL - Token preserved on failure
            # Credentials NOT updated
            logger.error(f"Scan failed: {e}")
            typer.echo(f"❌ Error: Scan failed. Token preserved for retry.")
            raise

    def _execute_simulated_scan(
        self, project_id: str, ephemeral_token: str
    ) -> ScanResult:
        """
        Execute SIMULATED BigQuery scan for Epic 3.

        Epic 4 will replace with real INFORMATION_SCHEMA extraction.

        Args:
            project_id: GCP project ID to scan
            ephemeral_token: Ephemeral token for scan authentication

        Returns:
            ScanResult with simulated=True

        Security:
        - AC4: Token NEVER logged (delegated to simulator)
        """
        return simulate_scan(project_id, ephemeral_token)
