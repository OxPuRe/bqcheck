"""
Scan executor with token lifecycle management.

Manages ephemeral token lifecycle:
- Load credentials
- Execute scan (simulated for Epic 3, real implementation in Epic 4)
- Renew token after success
- Atomic token consumption (preserve on failure)

Note on Memory Security:
Sensitive data (master_key, ephemeral_token) is stored in Python dicts and
cannot be truly scrubbed from process memory due to Python's immutable strings
and garbage collection. This is a known limitation acceptable for CLI tools
with short-lived processes. If attacker gains process memory access (debugger,
core dump), credentials may be recoverable.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

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


class ScanError(Exception):
    """
    Base exception for scan errors that should exit the CLI.

    Attributes:
        exit_code: The exit code to use when terminating the CLI
        message: Human-readable error message
    """

    def __init__(self, exit_code: int, message: str):
        self.exit_code = exit_code
        self.message = message
        super().__init__(message)


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

    def execute_scan_with_tokens(
        self,
        project_id: str,
        query_project: "str | None" = None,
        output_path: "Path | None" = None,
        force: bool = False,
    ) -> ScanResult:
        """
        Execute scan with automatic token management.

        Process:
        1. Load credentials
        2. Execute scan (simulated or real based on BQAUDIT_REAL_SCAN env var)
        3. On success: renew token + decrement balance + save
        4. On failure: preserve token (atomic consumption)

        Args:
            project_id: GCP project ID to scan for table metadata
            query_project: Optional GCP project ID for query metadata.
                          If None, uses project_id for both tables and queries.
                          Use this for separated storage/processing architectures.
            output_path: Optional custom output file path
            force: Force overwrite existing file without prompt

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
            # Unexpected errors - log and re-raise to preserve stack trace
            logger.exception("Unexpected error loading credentials")
            raise

        # Step 2: Execute scan (SIMULATED for Epic 3, or REAL for Epic 5)
        try:
            # AC1, AC7: Simulated scan
            # AC4: Token never logged - passed to simulator but not logged
            # Choose scan mode based on environment variable
            # Note: BQAUDIT_REAL_SCAN controls scan execution (simulated vs real)
            # Note: BQAUDIT_REAL_MODE controls API client mode (mock vs real server)
            from bqaudit.constants import is_real_scan

            use_real_scan = is_real_scan()

            if use_real_scan:
                # Epic 5: Execute real audit with server
                from bqaudit.constants import ENV_VAR_REAL_SCAN

                logger.info(f"Executing REAL audit ({ENV_VAR_REAL_SCAN}=true)")
                import asyncio

                # Note: Using asyncio.run() in sync context. This creates a new event loop.
                # LIMITATION: Cannot be called from existing async context (would raise RuntimeError).
                # This is acceptable for CLI entry point but limits future async refactoring.
                try:
                    audit_response = asyncio.run(
                        self.execute_real_scan(
                            project_id, credentials["ephemeral_token"], query_project
                        )
                    )
                except ScanError as e:
                    # Story 5.3: Handle errors from async context properly
                    # Error handlers already displayed messages, just exit with code
                    sys.exit(e.exit_code)

                # AC5: Display audit results immediately (credentials updated later atomically)
                show_success_message(
                    audit_response.summary.total_recommendations,
                    audit_response.summary.total_potential_savings_eur,
                )

                # Generate and save Markdown report (Story 5.2, 5.4)
                from bqaudit.report_generator import MarkdownReportGenerator

                generator = MarkdownReportGenerator(
                    audit_response, project_name=project_id
                )
                report_path = generator.save_report(
                    output_path=output_path,
                    force=force,
                    interactive=False,  # Never prompt user; return None if file exists without force
                )
                if report_path is None:
                    # File exists and user/config declined overwrite
                    console.print(
                        "[yellow]⚠️  Report not saved: file exists (use --force to overwrite)[/yellow]"
                    )
                else:
                    console.print(
                        f"[green]✅ Audit report saved to:[/green] {report_path}"
                    )

                # Create a ScanResult wrapper for compatibility
                result = ScanResult(
                    simulated=False,
                    success=True,
                    project_id=project_id,
                    audit_response=audit_response,
                )
            else:
                # Epic 3: Simulated scan (original behavior)
                logger.info("Executing SIMULATED audit (Epic 3)")
                result = self._execute_simulated_scan(
                    project_id, credentials["ephemeral_token"]
                )

            # Step 3: Get renewed token from audit response
            # Server should return new_ephemeral_token in /v1/audit response
            # If not available (server not implemented yet), use mock renewal
            if result.audit_response and result.audit_response.new_ephemeral_token:
                new_ephemeral_token = result.audit_response.new_ephemeral_token
                new_balance = credentials["token_pool_balance"] - 1
            else:
                # Fallback: Mock renewal until server implements token rotation
                # TODO: Remove when server populates new_ephemeral_token in /v1/audit
                logger.warning(
                    "Server did not return new_ephemeral_token. Using mock renewal."
                )
                mock_renewal = self.api_client._mock_renew(
                    credentials["master_key"],
                    current_balance=credentials["token_pool_balance"],
                )
                new_ephemeral_token = mock_renewal.ephemeral_token
                new_balance = mock_renewal.token_pool_balance

            # Step 4: Update credentials atomically (AC6, AC8)
            # AC8: Mark old token as used (client-side tracking)
            old_token = credentials["ephemeral_token"]
            credentials["ephemeral_token"] = new_ephemeral_token

            # Track used tokens (AC8: Single-use enforcement)
            # Use hash instead of truncation
            # Truncation loses entropy and makes tokens guessable. Hash preserves
            # uniqueness while being irreversible.
            import hashlib

            token_hash = hashlib.sha256(old_token.encode("utf-8")).hexdigest()

            if "used_tokens" not in credentials:
                credentials["used_tokens"] = []

            # Validate used_tokens length before append
            # Prevent unbounded growth and log when truncation occurs
            max_used_tokens = 100  # Reasonable limit for audit trail

            if len(credentials["used_tokens"]) >= max_used_tokens:
                logger.warning(
                    f"used_tokens list at maximum capacity ({max_used_tokens}). "
                    "Keeping only last 5 tokens for recent audit trail."
                )
                credentials["used_tokens"] = credentials["used_tokens"][
                    -4:
                ]  # Keep 4, add 1 = 5

            credentials["used_tokens"].append(
                {
                    "token_hash": token_hash,  # SHA-256 hash for security
                    "used_at": datetime.now(timezone.utc).isoformat(),
                }
            )

            # Keep only last 5 used tokens in normal operation to prevent credential file bloat
            if len(credentials["used_tokens"]) > 5:
                credentials["used_tokens"] = credentials["used_tokens"][-5:]

            # Use server-provided balance (server decrements on its side)
            # Validate balance after renewal
            # Prevent server bugs/MITM from corrupting token pool
            old_balance = credentials["token_pool_balance"]

            if new_balance < 0:
                raise ValueError(
                    f"Server returned invalid token pool balance: {new_balance}. "
                    "Balance cannot be negative. Please contact support."
                )

            if new_balance > old_balance:
                logger.warning(
                    f"Token pool balance INCREASED after scan: {old_balance} → {new_balance}. "
                    "This is unexpected and may indicate a server-side issue."
                )

            credentials["token_pool_balance"] = new_balance
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
        self, project_id: str, ephemeral_token: str, query_project: "str | None" = None
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
            project_id: GCP project ID to scan for table metadata
            ephemeral_token: Ephemeral token for authentication
            query_project: Optional GCP project ID for query metadata.
                          If None, uses project_id for both tables and queries.

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
                from bqaudit.scanner.aggregator import aggregate_query_metadata
                from bqaudit.scanner.anonymizer import (
                    anonymize_access_patterns,
                    anonymize_metadata,
                    generate_salt,
                    merge_table_metadata,
                )
                from bqaudit.scanner.metadata_extractor import (
                    extract_access_patterns,
                    extract_query_metadata,
                    extract_table_metadata,
                    extract_table_schemas,
                )

                # Extract all metadata types
                logger.info("Extracting table metadata...")
                table_metadata = extract_table_metadata(client, project_id)

                # Use query_project if specified, otherwise use project_id
                query_project_id = query_project or project_id
                logger.info(f"Extracting query metadata from project: {query_project_id}")
                query_metadata = extract_query_metadata(client, query_project_id, days=90)

                logger.info("Extracting access patterns...")
                access_patterns = extract_access_patterns(client, project_id)

                logger.info("Extracting table schemas...")
                table_schemas = extract_table_schemas(client, project_id)

            # Merge metadata into enriched format with table_id, last_modified_time, schema, query_stats
            enriched_tables = merge_table_metadata(
                table_metadata, access_patterns, query_metadata, table_schemas
            )

            # Generate cryptographic salt for anonymization (privacy-critical)
            logger.info("Anonymizing metadata...")
            salt = generate_salt()

            # Anonymize enriched tables (apply anonymize_metadata to each dict)
            anonymized_tables = [
                anonymize_metadata(table_dict, salt) for table_dict in enriched_tables
            ]

            # Aggregate and anonymize queries (groups by pattern, calculates stats)
            aggregated_queries = aggregate_query_metadata(
                query_metadata, salt, scan_days=90
            )

            # Anonymize access patterns
            anonymized_patterns = anonymize_access_patterns(access_patterns, salt)

            # Convert Pydantic models to dicts and create validated AuditMetadata
            from bqaudit.api.models import AuditMetadata

            metadata = AuditMetadata(
                tables=anonymized_tables,
                queries=aggregated_queries,
                access_patterns=anonymized_patterns,
            )

            logger.info(
                f"Extracted and anonymized metadata: {len(table_metadata)} tables, "
                f"{len(aggregated_queries)} query patterns (from {len(query_metadata)} queries), "
                f"{len(access_patterns)} access patterns"
            )

        except PermissionDenied:
            # AC6: BigQuery permission error
            # Get user email for IAM binding command
            # Add timeout, validation, stderr capture
            try:
                email = subprocess.check_output(
                    ["gcloud", "config", "get-value", "account"],
                    text=True,
                    timeout=5,  # Prevent hanging if gcloud is stuck
                    stdin=subprocess.DEVNULL,  # Prevent stdin inheritance
                    stderr=subprocess.DEVNULL,  # Suppress stderr noise
                ).strip()

                # Basic validation (gcloud output is trusted)
                if not email or "@" not in email:
                    raise ValueError(f"Invalid email from gcloud: {email!r}")
            except subprocess.TimeoutExpired:
                # Code Review Round 7: gcloud hung, can't get email
                logger.warning("gcloud command timed out, cannot retrieve user email")
                email = None
            except (
                subprocess.CalledProcessError,
                FileNotFoundError,
                ValueError,
                OSError,
            ):
                # Story 5.3: Narrow exception catching to specific gcloud CLI failures
                # CalledProcessError: gcloud command failed
                # FileNotFoundError: gcloud not installed
                # ValueError: invalid email format
                # OSError: permission issues
                email = None
            exit_code = handle_bigquery_permission_error(console, project_id, email)
            # Story 5.3: Raise exception instead of sys.exit() from async context
            raise ScanError(exit_code, "BigQuery permission denied")

        except NotFound:
            # Project not found error
            exit_code = handle_bigquery_not_found_error(console, project_id)
            raise ScanError(exit_code, "BigQuery project not found")

        except Forbidden:
            # Access forbidden error
            exit_code = handle_bigquery_forbidden_error(console, project_id)
            raise ScanError(exit_code, "BigQuery access forbidden")

        # Step 2: Anonymize project_id (SHA-256)
        project_id_hash = hashlib.sha256(project_id.encode("utf-8")).hexdigest()

        # Story 5.3: Validate SHA-256 hash format (64 hex characters)
        # Use explicit check instead of assert (assertions disabled with python -O)
        if len(project_id_hash) != 64 or not all(
            c in "0123456789abcdef" for c in project_id_hash
        ):
            raise ValueError(
                f"Invalid SHA-256 hash format (expected 64 hex chars): {project_id_hash}"
            )

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
                # Story 5.3: Global timeout for execute_audit
                # Prevents indefinite waits during retries or server-side processing
                from bqaudit.constants import GLOBAL_AUDIT_TIMEOUT_SECONDS

                response = await asyncio.wait_for(
                    self.api_client.execute_audit(
                        audit_request=audit_request,
                        ephemeral_token=ephemeral_token,
                    ),
                    timeout=GLOBAL_AUDIT_TIMEOUT_SECONDS,
                )
            finally:
                # IMPORTANT: This finally block executes BEFORE exception handlers below.
                # Timer is guaranteed to be cancelled before any error handler runs.
                # This prevents resource leaks (timer keeps running after error).
                from bqaudit.constants import TIMER_CANCEL_TIMEOUT_SECONDS

                # Robust task cancellation with exception handling
                if not timer_task.done():
                    timer_task.cancel()

                try:
                    # Story 5.3: Add timeout to prevent race condition where timer doesn't cancel
                    await asyncio.wait_for(
                        timer_task, timeout=TIMER_CANCEL_TIMEOUT_SECONDS
                    )
                except asyncio.CancelledError:
                    # Expected: timer was cancelled successfully
                    pass
                except asyncio.TimeoutError:
                    # Unexpected: timer didn't cancel within timeout (console.print() blocked?)
                    logger.warning(
                        f"Timer task did not cancel within {TIMER_CANCEL_TIMEOUT_SECONDS}s. "
                        "Possible console.print() blocking (slow terminal/NFS)."
                    )
                except Exception as e:
                    # Catch unexpected timer exceptions
                    # Timer task might raise from run_in_executor() or other failures
                    logger.error(f"Unexpected timer task exception during cleanup: {e}")
                    # Don't re-raise - we're in cleanup, audit error takes precedence

        except asyncio.TimeoutError:
            # Story 5.3: Global timeout exceeded (20 minutes)
            exit_code = handle_timeout_error(console)
            raise ScanError(exit_code, "Audit timeout exceeded")

        except httpx.TimeoutException:
            # AC8: Timeout error
            exit_code = handle_timeout_error(console)
            raise ScanError(exit_code, "HTTP timeout")

        except (httpx.ConnectError, httpx.NetworkError):
            # AC7: Network error
            exit_code = handle_network_error(console)
            raise ScanError(exit_code, "Network error")

        except Exception as e:
            # Catch RetryError from tenacity and check underlying cause
            from tenacity import RetryError

            if isinstance(e, RetryError):
                # Extract the last exception from the retry history
                if e.last_attempt and e.last_attempt.exception():
                    original_exc = e.last_attempt.exception()
                    if isinstance(original_exc, httpx.TimeoutException):
                        exit_code = handle_timeout_error(console)
                        raise ScanError(exit_code, "Timeout after retries")
                    elif isinstance(
                        original_exc, (httpx.ConnectError, httpx.NetworkError)
                    ):
                        exit_code = handle_network_error(console)
                        raise ScanError(exit_code, "Network error after retries")
            # Unexpected error - log with full traceback before re-raising
            logger.exception("Unexpected error during audit execution")
            raise

        logger.info(
            f"Audit complete: {response.summary.total_recommendations} recommendations"
        )
        return response
