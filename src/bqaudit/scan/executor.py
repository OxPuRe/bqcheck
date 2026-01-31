"""
Scan executor with token lifecycle management (Story 3.4, Task 2).

Manages ephemeral token lifecycle:
- Load credentials
- Execute scan (simulated for Epic 3)
- Renew token after success
- Atomic token consumption (preserve on failure)
"""

import logging
import os

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
                typer.echo(
                    "❌ Error: Credentials file has invalid data "  # noqa: E501
                    "(e.g., negative balance)."
                )
                typer.echo(
                    "Run: bqaudit license revoke && bqaudit license activate <key>"
                )
                raise
            # Re-raise other exceptions
            raise

        # Step 2: Execute scan (SIMULATED for Epic 3)
        try:
            # AC1, AC7: Simulated scan
            # AC4: Token never logged - passed to simulator but not logged
            # Choose scan mode based on environment variable
            use_real_scan = os.getenv('BQAUDIT_REAL_SCAN', '').lower() == 'true'
            
            if use_real_scan:
                # Epic 5: Execute real audit with server
                logger.info('Executing REAL audit (BQAUDIT_REAL_SCAN=true)')
                import asyncio
                audit_response = asyncio.run(
                    self.execute_real_scan(project_id, credentials['ephemeral_token'])
                )
                # Update credentials with new token from audit response
                credentials['ephemeral_token'] = audit_response.new_ephemeral_token
                credentials['token_pool_balance'] -= 1
                CredentialStore.update(credentials)
                
                typer.echo(f'\n✅ Audit complete! {audit_response.summary.total_recommendations} recommendations found.')
                typer.echo(f'💰 Potential monthly savings: €{audit_response.summary.total_potential_savings_eur:.2f}')
                typer.echo(f'Token pool balance: {credentials["token_pool_balance"]} scans remaining\n')
                
                # Create a ScanResult wrapper for compatibility
                result = ScanResult(
                    simulated=False,
                    success=True,
                    project_id=project_id,
                    audit_response=audit_response,
                )
            else:
                # Epic 3: Simulated scan (original behavior)
                logger.info('Executing SIMULATED audit (Epic 3)')
                result = self._execute_simulated_scan(
                    project_id, credentials["ephemeral_token"]
                )

            # Step 3: Report success to server (AC1)
            self.api_client.report_scan_success(
                project_id, {"simulated": result.simulated, "success": result.success}
            )

            # Step 4: Renew token (AC3)
            # AC5: Master key ONLY for renewal (not during scan)
            new_token_data = self.api_client.renew_token(
                credentials["master_key"],
                current_balance=credentials["token_pool_balance"],
            )

            # Step 5: Update credentials atomically (AC6, AC8)
            # AC8: Mark old token as used (client-side tracking)
            old_token = credentials["ephemeral_token"]
            credentials["ephemeral_token"] = new_token_data.ephemeral_token

            # Track used tokens (AC8: Single-use enforcement)
            if "used_tokens" not in credentials:
                credentials["used_tokens"] = []
            credentials["used_tokens"].append(
                {
                    "token": old_token[:16] + "...",  # Truncated for security
                    # Use new token timestamp as proxy  # noqa: E501
                    "used_at": new_token_data.ephemeral_token,
                }
            )
            # Keep only last 5 used tokens to prevent bloat
            credentials["used_tokens"] = credentials["used_tokens"][-5:]

            # Use server-provided balance (server decrements on its side)
            # In mock mode: mock calculates new_balance = current - 1
            # In real mode: server tracks balance and returns new balance
            credentials["token_pool_balance"] = new_token_data.token_pool_balance
            CredentialStore.update(credentials)

            # AC1: Display success with balance
            typer.echo("\n✅ Scan completed successfully!")
            typer.echo(
                f"Token pool balance: {credentials['token_pool_balance']} "
                "scans remaining\n"
            )

            return result

        except Exception as e:
            # AC2: CRITICAL - Token preserved on failure
            # Credentials NOT updated
            logger.error(f"Scan failed: {e}")
            typer.echo("❌ Error: Scan failed. Token preserved for retry.")
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

    async def execute_real_scan(
        self, project_id: str, ephemeral_token: str
    ) -> "AuditResponse":
        """
        Execute REAL BigQuery scan with server integration (Story 5.1).

        Process:
        1. Extract metadata from BigQuery INFORMATION_SCHEMA (Epic 2)
        2. Anonymize project_id (SHA-256)
        3. Send to POST /v1/audit with ephemeral token
        4. Return AuditResponse with recommendations

        Args:
            project_id: GCP project ID to scan
            ephemeral_token: Ephemeral token for authentication

        Returns:
            AuditResponse with recommendations and new ephemeral token

        Raises:
            NetworkError: If server communication fails after retries
            AuthenticationError: If BigQuery authentication fails

        Security:
        - Metadata anonymized before transmission
        - Ephemeral token in header (single-use)
        - HTTPS-only enforcement
        """
        import hashlib
        from bqaudit.api.models import AuditRequest, AuditResponse
        from bqaudit.scanner import authenticate_bigquery

        # Step 1: Extract BigQuery metadata (Epic 2)
        logger.info(f"Extracting metadata from project: {project_id}")
        client = authenticate_bigquery(project_id)

        # Epic 2 Integration: Extract real metadata
        from bqaudit.scanner.metadata_extractor import (
            extract_table_metadata,
            extract_query_metadata,
            extract_access_patterns,
        )

        # Extract all metadata types
        logger.info("Extracting table metadata...")
        table_metadata = extract_table_metadata(client, project_id)

        logger.info("Extracting query metadata...")
        query_metadata = extract_query_metadata(client, project_id, days=90)

        logger.info("Extracting access patterns...")
        access_patterns = extract_access_patterns(client, project_id, days=90)

        # Convert Pydantic models to dicts for JSON serialization
        metadata = {
            "tables": [table.model_dump() for table in table_metadata],
            "queries": [query.model_dump() for query in query_metadata],
            "access_patterns": [pattern.model_dump() for pattern in access_patterns],
        }

        logger.info(
            f"Extracted metadata: {len(table_metadata)} tables, "
            f"{len(query_metadata)} queries, {len(access_patterns)} access patterns"
        )

        # Step 2: Anonymize project_id (SHA-256)
        project_id_hash = hashlib.sha256(project_id.encode()).hexdigest()

        # Step 3: Create audit request
        audit_request = AuditRequest(
            project_id=project_id_hash,
            metadata=metadata,
        )

        # Step 4: Send to server with retry logic
        logger.info("Sending audit request to server...")
        response = await self.api_client.execute_audit(
            audit_request=audit_request,
            ephemeral_token=ephemeral_token,
        )

        logger.info(f"Audit complete: {response.summary.total_recommendations} recommendations")
        return response

    def execute_scan_with_real_audit(self, project_id: str, ephemeral_token: str):
        """
        Execute real audit (Story 5.1) - synchronous wrapper for CLI.
        
        This wraps the async execute_real_scan for use in the synchronous CLI context.
        
        Args:
            project_id: GCP project ID to scan
            ephemeral_token: Ephemeral token for authentication
            
        Returns:
            AuditResponse from server
        """
        import asyncio
        return asyncio.run(self.execute_real_scan(project_id, ephemeral_token))
