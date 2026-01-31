"""
Scan executor with token lifecycle management (Story 3.4, Task 2).

Manages ephemeral token lifecycle:
- Load credentials
- Execute scan (simulated for Epic 3)
- Renew token after success
- Atomic token consumption (preserve on failure)
"""

from __future__ import annotations

import logging
import os

import httpx
import typer
from google.api_core.exceptions import Forbidden, NotFound, PermissionDenied

from bqaudit.api.client import BQAuditAPIClient
from bqaudit.api.models import AuditResponse
from bqaudit.console import (
    console,
    show_analysis_progress,
    show_extraction_progress,
    show_server_upload,
    show_start_message,
    show_success_message,
)
from bqaudit.error_handlers import (
    handle_bigquery_forbidden_error,
    handle_bigquery_not_found_error,
    handle_bigquery_permission_error,
    handle_network_error,
    handle_timeout_error,
)
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
        2. Execute scan (simulated or real based on BQAUDIT_REAL_SCAN env var)
        3. On success: renew token + decrement balance + save
        4. On failure: preserve token (atomic consumption)

        Args:
            project_id: GCP project ID to scan

        Returns:
            ScanResult with scan results

        Raises:
            Exception: If scan fails (token preserved - AC2)

        Environment Variables:
            BQAUDIT_REAL_SCAN: Set to 'true' to execute real audit with server.
                              Default: 'false' (simulated scan for Epic 3)

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

        # Step 2: Execute scan (SIMULATED for Epic 3, or REAL for Epic 5)
        try:
            # AC1, AC7: Simulated scan
            # AC4: Token never logged - passed to simulator but not logged
            # Choose scan mode based on environment variable
            # Note: BQAUDIT_REAL_SCAN controls scan execution (simulated vs real)
            # Note: BQAUDIT_REAL_MODE controls API client mode (mock vs real server)
            use_real_scan = os.getenv('BQAUDIT_REAL_SCAN', '').lower() == 'true'
            
            if use_real_scan:
                # Epic 5: Execute real audit with server
                logger.info('Executing REAL audit (BQAUDIT_REAL_SCAN=true)')
                import asyncio
                audit_response = asyncio.run(
                    self.execute_real_scan(project_id, credentials['ephemeral_token'])
                )

                # AC5: Display audit results immediately (credentials updated later atomically)
                show_success_message(
                    audit_response.summary.total_recommendations,
                    audit_response.summary.total_potential_savings_eur
                )

                # Generate and save Markdown report (Story 5.2)
                from bqaudit.report_generator import MarkdownReportGenerator

                generator = MarkdownReportGenerator(audit_response, project_name=project_id)
                report_path = generator.save_report()
                typer.echo(f'\n📄 Audit report saved to: {report_path}')

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

            # AC1: Display success with balance (for simulated scans only)
            # Real scan already displayed results earlier
            if not use_real_scan:
                typer.echo("\n✅ Scan completed successfully!")

            # Display token balance for both real and simulated scans
            typer.echo(
                f"💰 Token pool balance: {credentials['token_pool_balance']} "
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
    ) -> AuditResponse:
        """
        Execute REAL BigQuery scan with server integration (Story 5.1 + 5.3).

        Process:
        1. Display start message (AC1)
        2. Extract metadata from BigQuery INFORMATION_SCHEMA with spinner (AC2)
        3. Anonymize project_id (SHA-256)
        4. Send to POST /v1/audit with progress indicators (AC3, AC4)
        5. Return AuditResponse with recommendations

        Args:
            project_id: GCP project ID to scan
            ephemeral_token: Ephemeral token for authentication

        Returns:
            AuditResponse with recommendations and new ephemeral token

        Raises:
            SystemExit: Via error handlers (AC6, AC7, AC8)
                - Exit code 3: BigQuery permission/auth errors
                - Exit code 2: Project not found
                - Exit code 1: Network/timeout errors

        Security:
        - Metadata anonymized before transmission
        - Ephemeral token in header (single-use)
        - HTTPS-only enforcement
        """
        import asyncio
        import hashlib
        from bqaudit.api.models import AuditRequest
        from bqaudit.scanner import authenticate_bigquery

        # AC1: Display start message
        show_start_message(project_id)

        # Step 1: Extract BigQuery metadata (Epic 2) with progress indicator (AC2)
        # and error handling (AC6)
        try:
            logger.info(f"Extracting metadata from project: {project_id}")

            with show_extraction_progress():
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

        except PermissionDenied:
            # AC6: BigQuery permission error
            # Get user email for IAM binding command
            import subprocess
            try:
                email = subprocess.check_output(
                    ["gcloud", "config", "get-value", "account"],
                    text=True,
                ).strip()
            except Exception:
                email = "<your-email@example.com>"
            handle_bigquery_permission_error(console, project_id, email)

        except NotFound:
            # Project not found error
            handle_bigquery_not_found_error(console, project_id)

        except Forbidden:
            # Access forbidden error
            handle_bigquery_forbidden_error(console, project_id)

        # Step 2: Anonymize project_id (SHA-256)
        project_id_hash = hashlib.sha256(project_id.encode()).hexdigest()

        # Step 3: Create audit request
        audit_request = AuditRequest(
            project_id=project_id_hash,
            metadata=metadata,
        )

        # Step 4: Send to server with progress indicators (AC3, AC4) and error handling (AC7, AC8)
        try:
            # AC3: Display server upload message
            show_server_upload()

            # AC4: Start timer task for analysis progress
            logger.info("Sending audit request to server...")
            timer_task = asyncio.create_task(show_analysis_progress())

            try:
                response = await self.api_client.execute_audit(
                    audit_request=audit_request,
                    ephemeral_token=ephemeral_token,
                )
            finally:
                # Cancel timer when request completes
                timer_task.cancel()
                try:
                    await timer_task
                except asyncio.CancelledError:
                    pass

        except httpx.TimeoutException:
            # AC8: Timeout error
            handle_timeout_error(console)

        except (httpx.ConnectError, httpx.NetworkError):
            # AC7: Network error
            handle_network_error(console)

        except Exception as e:
            # Catch RetryError from tenacity and check underlying cause
            from tenacity import RetryError
            if isinstance(e, RetryError):
                # Extract the last exception from the retry history
                if e.last_attempt and e.last_attempt.exception():
                    original_exc = e.last_attempt.exception()
                    if isinstance(original_exc, httpx.TimeoutException):
                        handle_timeout_error(console)
                    elif isinstance(original_exc, (httpx.ConnectError, httpx.NetworkError)):
                        handle_network_error(console)
            # Re-raise if not handled
            raise

        logger.info(f"Audit complete: {response.summary.total_recommendations} recommendations")
        return response
