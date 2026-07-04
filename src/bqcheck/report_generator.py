"""Markdown sanity check report generator.

Generates well-formatted Markdown reports from CheckResponse data.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from bqcheck.api.models import CheckResponse, Recommendation
from bqcheck.scanner.encryption import IdentifierEncryptor

logger = logging.getLogger(__name__)


class MarkdownReportGenerator:
    """
    Generate Markdown sanity check reports from CheckResponse.

    Features:
    - Executive Summary with aggregate statistics
    - Quick Wins (top 3-5 HIGH priority recommendations)
    - Detailed Recommendations sorted by priority and savings
    - Zero-recommendations handling

    Usage:
        >>> response = CheckResponse(...)
        >>> generator = MarkdownReportGenerator(response, project_name="my-project")
        >>> report_path = generator.generate_and_save()
    """

    def __init__(
        self,
        check_response: CheckResponse,
        project_name: str = "Unknown",
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize report generator.

        Args:
            check_response: CheckResponse from server
            project_name: GCP project name for report title
            encryption_key: Optional 32-byte AES-256 encryption key for decrypting identifiers.
                          If provided, encrypted table/dataset names in recommendations
                          will be decrypted to human-readable names.
        """
        self.check_response = check_response
        self.project_name = project_name
        self.timestamp = datetime.now(timezone.utc)
        self.encryption_key = encryption_key

        # Initialize encryptor if key provided
        self.encryptor: Optional[IdentifierEncryptor]
        if encryption_key:
            self.encryptor = IdentifierEncryptor(encryption_key)
        else:
            self.encryptor = None

    def _decrypt_identifiers_in_text(self, text: str) -> str:
        """
        Decrypt encrypted table identifiers in text.

        Finds encrypted table references (e.g., "Table ABC123.DEF456" or
        "dataset.table format like ABC123.DEF456") and replaces them
        with decrypted names. Also handles standalone encrypted identifiers.

        Args:
            text: Text containing encrypted identifiers

        Returns:
            Text with identifiers decrypted (if encryption key available)

        Example:
            >>> from bqcheck.scanner.encryption import IdentifierEncryptor
            >>> key = IdentifierEncryptor.generate_key()
            >>> encryptor = IdentifierEncryptor(key)
            >>> dataset_enc = encryptor.encrypt_with_nonce("analytics", "dataset")
            >>> table_enc = encryptor.encrypt_with_nonce("users", "table")
            >>> text = f"Table {dataset_enc}.{table_enc} (100 GB)"
            >>> # After decryption: "Table analytics.users (100 GB)"
        """
        if not self.encryptor:
            # No encryption key - return original text
            return text

        # Store encryptor in local variable for type narrowing
        encryptor = self.encryptor

        # Pattern 1: Match "project.dataset.table" format (encrypted triple)
        # Base64url chars: A-Za-z0-9_-
        # Use negative lookahead/lookbehind instead of \b to handle leading/trailing hyphens
        pattern_triple = r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]+)(?![A-Za-z0-9_-])"

        def decrypt_triple(match: re.Match[str]) -> str:
            encrypted_project = match.group(1)
            encrypted_dataset = match.group(2)
            table_name = match.group(3)  # Table name may or may not be encrypted

            try:
                # Try to decrypt project and dataset
                project = encryptor.decrypt_with_nonce(encrypted_project, "project")
                dataset = encryptor.decrypt_with_nonce(encrypted_dataset, "dataset")
                # Successfully decrypted - return decrypted version
                return f"{project}.{dataset}.{table_name}"
            except (ValueError, Exception):
                # Decryption failed - return original
                return match.group(0)

        # First pass: decrypt project.dataset.table triples
        text = re.sub(pattern_triple, decrypt_triple, text)

        # Pattern 2: Match "dataset.table" format (encrypted pairs)
        # Use negative lookahead/lookbehind instead of \b to handle leading/trailing hyphens
        pattern_pair = r"(?<![A-Za-z0-9_-])([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]{20,})(?![A-Za-z0-9_-])"

        def decrypt_pair(match: re.Match[str]) -> str:
            encrypted_dataset = match.group(1)
            encrypted_table = match.group(2)

            try:
                # Try to decrypt both parts
                dataset = encryptor.decrypt_with_nonce(encrypted_dataset, "dataset")
                table = encryptor.decrypt_with_nonce(encrypted_table, "table")
                # Successfully decrypted - return decrypted version
                return f"{dataset}.{table}"
            except (ValueError, Exception):
                # Decryption failed - likely not an encrypted identifier
                # Return original text
                return match.group(0)

        # Second pass: decrypt dataset.table pairs
        text = re.sub(pattern_pair, decrypt_pair, text)

        # Pattern 3: Match standalone encrypted identifiers (not already decrypted)
        # These appear after spaces, dots (like backup_dataset.XXX), or at word boundaries
        # Avoid matching regular words by requiring minimum length and base64 chars
        pattern_standalone = (
            r"(?<=[\s\.])([A-Za-z0-9_-]{30,})(?=\s|$|\)|\,|&&|\||\.(?!\w))"
        )

        def decrypt_standalone(match: re.Match[str]) -> str:
            encrypted = match.group(1)

            # Try to decrypt as table name first (most common in implementation steps)
            try:
                table = encryptor.decrypt_with_nonce(encrypted, "table")
                return table
            except (ValueError, Exception):
                pass

            # Try dataset if table failed
            try:
                dataset = encryptor.decrypt_with_nonce(encrypted, "dataset")
                return dataset
            except (ValueError, Exception):
                pass

            # Not an encrypted identifier - return as is
            return match.group(0)

        # Third pass: decrypt standalone identifiers
        text = re.sub(pattern_standalone, decrypt_standalone, text)

        return text

    @staticmethod
    def _truncate_query_hash(text: str) -> str:
        """
        Truncate long query pattern hashes for readability.

        Replaces 64-character SHA-256 hashes with shortened version (first 8 + last 4 chars).

        Args:
            text: Text containing query pattern hashes

        Returns:
            Text with truncated hashes

        Example:
            >>> _truncate_query_hash("Query pattern e2a46e6117ae58453f6fcf9c747fa74329873e38cd68b426ae14eab0e3ec4f2e executes")
            "Query pattern e2a46e61...4f2e executes"
        """
        import re

        # Match SHA-256 hashes (64 hex characters)
        def truncate_hash(match: re.Match[str]) -> str:
            hash_value = match.group(1)
            # Only truncate if it's a full 64-char hash
            if len(hash_value) == 64:
                return f"{hash_value[:8]}...{hash_value[-4:]}"
            return hash_value

        # Pattern: "Query pattern" followed by 64-character hex hash
        pattern = r"Query pattern ([a-f0-9]{64})\b"
        return re.sub(pattern, lambda m: f"Query pattern {truncate_hash(m)}", text)

    def _extract_query_preview_from_steps(
        self, implementation_steps: list[str]
    ) -> Optional[str]:
        """
        Extract query preview from implementation steps.

        Looks for CREATE MATERIALIZED VIEW statements in implementation steps
        and extracts a preview of the query.

        Args:
            implementation_steps: List of implementation step strings

        Returns:
            Query preview (first 300 chars) or None if not found
        """
        import re

        for step in implementation_steps:
            # Look for CREATE MATERIALIZED VIEW ... AS <query>
            match = re.search(
                r"CREATE MATERIALIZED VIEW.*?AS\s+(.+)", step, re.IGNORECASE | re.DOTALL
            )
            if match:
                query = match.group(1).strip()
                # Decrypt identifiers if encryption key available
                decrypted_query = self._decrypt_identifiers_in_text(query)
                # Return first 300 characters for preview
                if len(decrypted_query) > 300:
                    return decrypted_query[:300] + "..."
                return decrypted_query

        return None

    @staticmethod
    def _build_evidence_points(rec_type: str, description: str) -> list[str]:
        """Extract high-level confidence signals without exposing detector logic."""
        evidence: list[str] = []

        if rec_type == "storage":
            match = re.search(
                r"\(([\d.]+\s(?:GB|TB))\) is about (\d+) days old and no query "
                r"activity was observed",
                description,
                re.IGNORECASE,
            )
            if match:
                evidence.append("Large table with no observed workload activity")

        elif rec_type == "partitioning":
            match = re.search(
                r"\(([\d.]+\s(?:GB|TB))\).*?queries scan (\d+)% of the table on "
                r"average \(([\d.]+\s(?:GB|TB)) per query\).*?Partitioning on "
                r"([A-Za-z0-9_]+)",
                description,
                re.IGNORECASE,
            )
            if match:
                evidence.append(
                    "Queries are repeatedly scanning a broad share of the table"
                )
                evidence.append(
                    f"A time-based column stands out as a strong partitioning candidate: "
                    f"`{match.group(4)}`"
                )

        elif rec_type == "clustering":
            match = re.search(
                r"\(([\d.]+\s(?:GB|TB))\).*?Queries scan ([\d.]+\sTB) with frequent "
                r"filters on (.+?)\.",
                description,
                re.IGNORECASE,
            )
            if match:
                evidence.append("A meaningful share of the workload hits this table")
                evidence.append(
                    f"Similar filter patterns recur on these columns: {match.group(3)}"
                )

        elif rec_type == "queries":
            match = re.search(
                r"executes ([\d.]+) times/day.*?processing ([\d.]+\sTB) per execution "
                r"\(([\d.]+\sTB) total\)",
                description,
                re.IGNORECASE,
            )
            if match:
                evidence.append(
                    "This query pattern appears frequently enough to create repeat waste"
                )
                evidence.append(
                    "Each execution scans enough data for materialization to be worth a look"
                )

            window = re.search(
                r"\((\d+) executions over ([\d.]+) days, on (\d+) distinct day",
                description,
                re.IGNORECASE,
            )
            if window:
                evidence.append(
                    "The pattern repeats across multiple days, which suggests a stable workload"
                )

            last_run = re.search(r"Last run:\s+(\d+) days ago", description)
            if last_run:
                evidence.append(
                    "The workload is still recent, not just historical noise"
                )

        evidence = [point.rstrip(".") for point in evidence if point]
        return evidence

    @staticmethod
    def _extract_job_ids_from_steps(implementation_steps: list[str]) -> list[str]:
        """
        Extract BigQuery job IDs from implementation steps.

        Looks for job ID references in implementation steps to help users
        locate queries in BigQuery Console.

        Args:
            implementation_steps: List of implementation step strings

        Returns:
            List of job IDs found in implementation steps
        """
        import re

        job_ids = []
        for step in implementation_steps:
            # Look for "Find query in BigQuery Console using job ID: xxx"
            # Job ID is now encrypted (base64 string) or unencrypted format (project:location.job_xxx)
            # Match any alphanumeric+hyphens+underscores string after "job ID: "
            match = re.search(r"job ID:\s+([a-zA-Z0-9_:-]+)", step)
            if match:
                job_ids.append(match.group(1))

        return job_ids

    @staticmethod
    def _format_recommendation_type(rec_type: str) -> str:
        """Convert internal recommendation types into user-facing labels."""
        labels = {
            "storage": "Storage Hygiene",
            "unused_storage": "Storage Hygiene",
            "partitioning": "Table Layout",
            "clustering": "Table Layout",
            "queries": "Query Efficiency",
            "temporal": "Lifecycle Management",
        }
        return labels.get(rec_type, rec_type.replace("_", " ").title())

    @staticmethod
    def _build_summary_assessment(
        total_recommendations: int,
        total_savings_eur: float,
    ) -> str:
        """Produce a short executive assessment paragraph."""
        if total_recommendations == 0:
            return (
                "No material optimization opportunities were detected in this scan. "
                "The current BigQuery setup looks disciplined on the signals reviewed."
            )

        if total_savings_eur >= 100:
            return (
                "This scan found a worthwhile set of optimizations, mostly concentrated "
                "in medium-impact improvements."
            )

        return (
            "This scan found a small number of lower-impact optimizations. They are "
            "worth addressing if you want to tighten long-tail costs."
        )

    def _build_focus_highlights(self) -> list[str]:
        """Surface the main commercial takeaways from the recommendation mix."""
        recommendations = self.check_response.recommendations
        if not recommendations:
            return []

        category_totals: dict[str, dict[str, float]] = {}
        for rec in recommendations:
            bucket = category_totals.setdefault(
                rec.type,
                {"count": 0.0, "savings": 0.0},
            )
            bucket["count"] += 1
            bucket["savings"] += rec.savings_eur

        top_category, top_category_stats = max(
            category_totals.items(),
            key=lambda item: (item[1]["savings"], item[1]["count"]),
        )
        top_recommendation = max(recommendations, key=lambda rec: rec.savings_eur)

        return [
            (
                "Primary focus area: "
                f"{self._format_recommendation_type(top_category)} "
                f"(€{top_category_stats['savings']:.2f}/month across "
                f"{int(top_category_stats['count'])} recommendation(s))"
            ),
            (
                "Best single starting point: "
                f"{self._clean_title(top_recommendation.title)} "
                f"(€{top_recommendation.savings_eur:.2f}/month)"
            ),
        ]

    def _sorted_recommendations(self) -> list[Recommendation]:
        """Sort recommendations for client-facing output."""
        return sorted(
            self.check_response.recommendations,
            key=lambda rec: (
                -rec.savings_eur,
                self._format_recommendation_type(rec.type),
            ),
        )

    @staticmethod
    def _extract_storage_facts(description: str) -> Optional[dict[str, str]]:
        """Extract structured facts from a storage recommendation description."""
        match = re.search(
            r"Table\s+([A-Za-z0-9_.-]+)\s+\(([\d.]+\s(?:GB|TB))\)\s+is about\s+"
            r"(\d+)\s+days old and no query activity was observed",
            description,
            re.IGNORECASE,
        )
        if not match:
            return None

        return {
            "table_id": match.group(1),
            "size": match.group(2),
            "age_days": match.group(3),
        }

    @staticmethod
    def _format_table_identifier(table_id: str, max_length: int = 88) -> str:
        """Format long table identifiers without repeating them across the report."""
        if len(table_id) <= max_length:
            return f"`{table_id}`"

        if "." not in table_id:
            return f"`{table_id[: max_length - 3]}...`"

        dataset, table_name = table_id.split(".", 1)
        if len(dataset) + len(table_name) + 1 <= max_length:
            return f"`{table_id}`"

        keep = max_length - len(dataset) - 8
        shortened = f"{table_name[: max(keep, 16)]}..."
        return f"`{dataset}.{shortened}`"

    def _build_compact_summary(self, rec: Recommendation, description: str) -> str:
        """Turn detector descriptions into concise report summaries."""
        if rec.type in {"storage", "unused_storage"}:
            facts = self._extract_storage_facts(description)
            if facts:
                return (
                    f"{facts['size']} stored, about {facts['age_days']} days old, "
                    "and no query activity observed in the scanned 90-day window."
                )

        return description

    def _build_asset_label(
        self, rec: Recommendation, description: str
    ) -> Optional[str]:
        """Extract the main asset affected by the recommendation."""
        if rec.type in {"storage", "unused_storage"}:
            facts = self._extract_storage_facts(description)
            if facts:
                return self._format_table_identifier(facts["table_id"])

        file_ref = None
        for step in rec.implementation_steps:
            file_ref = self._extract_file_reference(step)
            if file_ref:
                return f"`{file_ref}`"

        return None

    def _build_suggested_action(
        self, rec: Recommendation, implementation_steps: list[str]
    ) -> Optional[str]:
        """Return a compact action statement suited for engineers."""
        if rec.type in {"storage", "unused_storage"}:
            return (
                "Confirm ownership and downstream dependencies, then archive or "
                "delete the table if it is truly obsolete."
            )

        if not implementation_steps:
            return None

        return implementation_steps[0]

    @staticmethod
    def _summarize_steps(implementation_steps: list[str], limit: int = 3) -> list[str]:
        """Return the first actionable implementation steps in report-friendly form."""
        summarized = []
        for step in implementation_steps[:limit]:
            summarized.append(step.strip())
        return summarized

    def _sanitize_step_for_report(self, step: str) -> Optional[str]:
        """Prepare implementation text for report display."""
        sanitized = self._decrypt_identifiers_in_text(step).strip()
        sanitized = self._truncate_sql_in_step(sanitized)

        job_id_match = re.search(r"job ID:\s+([a-zA-Z0-9_:-]+)", sanitized)
        if job_id_match:
            job_id = job_id_match.group(1)
            if self.encryptor:
                try:
                    decrypted_job_id = self.encryptor.decrypt_with_nonce(
                        job_id, context="job_id"
                    )
                    return sanitized.replace(
                        job_id, self._format_job_id_link(decrypted_job_id)
                    )
                except (ValueError, Exception):
                    return None
            return None

        return sanitized

    @staticmethod
    def _format_job_id_link(job_id: str) -> str:
        """
        Format job ID as clickable BigQuery Console link.

        Args:
            job_id: BigQuery job ID in format "project:location.job_abc123"

        Returns:
            Markdown link to BigQuery Console query results
        """
        import re

        # Parse job ID format: project:location.{job_id} (e.g., roam-prod:EU.bquxjob_xxx)
        # Accept any alphanumeric job ID, not just those starting with "job_"
        match = re.match(r"([a-zA-Z0-9_-]+)[:.]([ A-Z0-9]+)\.([a-zA-Z0-9_-]+)", job_id)
        if not match:
            # Return plain text if format doesn't match
            return f"`{job_id}`"

        project, location, job_short = match.groups()

        # Create BigQuery Console link
        # Format: https://console.cloud.google.com/bigquery?project=PROJECT&j=bq:LOCATION:JOB_ID&page=queryresults
        console_url = f"https://console.cloud.google.com/bigquery?project={project}&j=bq:{location}:{job_short}&page=queryresults"

        return f"[`{job_id}`]({console_url})"

    @staticmethod
    def _format_size_human_readable(text: str) -> str:
        """
        Convert large GB values to TB for better readability.

        Converts sizes >= 1000 GB to TB format in titles and descriptions.

        Args:
            text: Text containing size values like "268695GB" or "268695.41 GB"

        Returns:
            Text with large sizes converted to TB

        Example:
            >>> _format_size_human_readable("Remove unused 268695GB table")
            "Remove unused 262TB table"
            >>> _format_size_human_readable("Table test (1500.50 GB)")
            "Table test (1.47 TB)"
            >>> _format_size_human_readable("Table test (500 GB)")
            "Table test (500 GB)"
        """
        import re

        def convert_to_tb(match: re.Match[str]) -> str:
            # Extract the numeric value and the format (with or without decimal/space)
            size_str = match.group(1)
            has_space = match.group(2) == " "

            size_gb = float(size_str)

            # Only convert if >= 1000 GB
            if size_gb >= 1000:
                size_tb = size_gb / 1024
                # Format with appropriate precision
                if size_tb >= 100:
                    formatted = f"{size_tb:.0f}"
                elif size_tb >= 10:
                    formatted = f"{size_tb:.1f}"
                else:
                    formatted = f"{size_tb:.2f}"

                return f"{formatted}{' ' if has_space else ''}TB"
            else:
                # Keep as GB
                return match.group(0)

        # Pattern matches:
        # - "268695GB" (no space, no decimal)
        # - "268695.41 GB" (space and decimal)
        # - "1500 GB" (space, no decimal)
        pattern = r"(\d+(?:\.\d+)?)(\s?)GB"

        return re.sub(pattern, convert_to_tb, text)

    @staticmethod
    def _clean_title(title: Optional[str]) -> str:
        """
        Clean recommendation title by rounding decimals and converting large sizes to TB.

        Args:
            title: Raw title from server (may be None)

        Returns:
            Cleaned title with rounded decimals and TB conversion, or "Untitled" if None

        Example:
            >>> _clean_title("Materialize repeated query (6.048781288508676/day)")
            "Materialize repeated query (6.0/day)"
            >>> _clean_title("Remove unused 268695GB table")
            "Remove unused 262TB table"
        """
        if title is None:
            return "Untitled"

        # Round decimals like "6.048781288508676/day" -> "6.0/day"
        def round_decimal(match: re.Match[str]) -> str:
            value = float(match.group(1))
            # Round to 1 decimal place
            return f"{value:.1f}/{match.group(2)}"

        title = re.sub(r"(\d+\.\d+)/(\w+)", round_decimal, title)

        # Convert large GB values to TB for readability
        title = MarkdownReportGenerator._format_size_human_readable(title)

        return title

    @staticmethod
    def _extract_file_reference(text: str) -> Optional[str]:
        """
        Extract file path reference from text (e.g., SQL comment).

        Args:
            text: Text that may contain file reference

        Returns:
            File path if found, None otherwise

        Example:
            >>> _extract_file_reference("-- Query logic taken from mobility/queries/compute.sql")
            "mobility/queries/compute.sql"
        """
        # Look for patterns like "mobility/*/queries/*.sql" or similar file paths
        match = re.search(
            r"(?:taken from |from |see |in )?([a-zA-Z0-9_/-]+/[a-zA-Z0-9_/-]*\.sql)",
            text,
            re.IGNORECASE,
        )
        return match.group(1) if match else None

    @staticmethod
    def _truncate_sql_in_step(step: str, max_lines: int = 10) -> str:
        """
        Truncate large SQL blocks in implementation steps.

        Args:
            step: Implementation step text
            max_lines: Maximum SQL lines to show before truncating

        Returns:
            Step with truncated SQL if applicable

        Example:
            >>> step = "Create view: CREATE TABLE foo AS SELECT ... (100 lines)"
            >>> _truncate_sql_in_step(step, max_lines=5)
            "Create view: CREATE TABLE foo AS SELECT ...\n  [SQL truncated - 95 more lines]"
        """
        # Check if step contains SQL statements (more specific patterns)
        # Look for SQL keywords at line start or after specific patterns
        has_sql = re.search(
            r"(^|\n)\s*(CREATE|DROP|ALTER|SELECT|INSERT|UPDATE|DELETE)\s",
            step,
            re.IGNORECASE | re.MULTILINE,
        ) or re.search(
            r"\bWITH\s+\w+\s+AS\s*\(", step, re.IGNORECASE
        )  # WITH clause pattern

        if not has_sql:
            return step

        lines = step.split("\n")

        # If step has more than max_lines, truncate
        if len(lines) > max_lines:
            # Extract file reference before truncating
            file_ref = MarkdownReportGenerator._extract_file_reference(step)

            # Build truncated version
            truncated_lines = lines[:max_lines]
            num_hidden = len(lines) - max_lines

            result = "\n".join(truncated_lines)
            result += f"\n  [SQL truncated - {num_hidden} more lines]"

            # Add file reference hint if found
            if file_ref:
                result += f"\n  See full query in: `{file_ref}`"

            return result

        return step

    def generate_header(self) -> str:
        """
        Generate report header with project name and timestamps.

        Returns:
            Markdown-formatted header
        """
        check_date = self.timestamp.strftime("%Y-%m-%d")
        timestamp_iso = self.timestamp.isoformat()

        return f"""# BigQuery Sanity Check Report - {self.project_name}

**Check Date:** {check_date}
**Generated:** {timestamp_iso}

---
"""

    def generate_executive_summary(self) -> str:
        """
        Generate Executive Summary section with aggregate statistics.

        Returns:
            Markdown-formatted Executive Summary
        """
        summary = self.check_response.summary

        # Build summary table
        exec_summary = f"""
## Executive Summary

{
            self._build_summary_assessment(
                summary.total_recommendations,
                summary.total_potential_savings_eur,
            )
        }

| Metric | Value |
|--------|-------|
| Total Recommendations | {summary.total_recommendations} |
| Potential Monthly Savings | €{summary.total_potential_savings_eur:.2f} |
| Dominant Category | {
            self._format_recommendation_type(
                max(
                    self.check_response.summary.categories_breakdown or {"storage": 0},
                    key=lambda key: self.check_response.summary.categories_breakdown.get(
                        key, 0
                    )
                    if self.check_response.summary.categories_breakdown
                    else 0,
                )
            )
            if self.check_response.recommendations
            else "None"
        } |
"""

        # Add category breakdown if we have recommendations
        if summary.categories_breakdown:
            # Calculate savings per category from recommendations
            category_savings = {}
            for rec in self.check_response.recommendations:
                category = rec.type  # Use type as category proxy
                if category not in category_savings:
                    category_savings[category] = 0.0
                category_savings[category] += rec.savings_eur

            exec_summary += """
### Savings Breakdown by Category

| Category | Count | Monthly Savings |
|----------|-------|-----------------|
"""
            for category, count in sorted(summary.categories_breakdown.items()):
                if count == 0:
                    continue
                savings = category_savings.get(category, 0.0)
                exec_summary += (
                    f"| {category.capitalize()} | {count} | €{savings:.2f} |\n"
                )

        focus_highlights = self._build_focus_highlights()
        if focus_highlights:
            exec_summary += """
### Focus Areas

"""
            for highlight in focus_highlights:
                exec_summary += f"- {highlight}\n"

        return exec_summary

    def generate_action_plan(self) -> str:
        """Generate a neutral shortlist of starting points."""
        if not self.check_response.recommendations:
            return ""

        candidates = self._sorted_recommendations()[:4]
        total_shortlist_value = sum(rec.savings_eur for rec in candidates)

        action_plan = """
## Suggested Starting Points

_A pragmatic shortlist ordered by estimated savings, not by business criticality._

"""
        action_plan += (
            f"**Estimated value across these starting points:** "
            f"€{total_shortlist_value:.2f}/month\n\n"
        )
        action_plan += "| Opportunity | Category | Estimated Savings |\n"
        action_plan += "|-------------|----------|-------------------|\n"
        for rec in candidates:
            clean_title = self._clean_title(rec.title)
            action_plan += (
                f"| {clean_title} | {self._format_recommendation_type(rec.type)} | "
                f"€{rec.savings_eur:.2f}/month |\n"
            )

        if len(self.check_response.recommendations) > len(candidates):
            remaining = len(self.check_response.recommendations) - len(candidates)
            action_plan += (
                f"\n{remaining} additional opportunity"
                f"{'ies' if remaining > 1 else 'y'} are documented below.\n"
            )

        return action_plan

    def generate_detailed_recommendations(self) -> str:
        """
        Generate Detailed Recommendations section.

        All recommendations sorted by priority (HIGH → MEDIUM → LOW),
        then by savings within same priority.

        Returns:
            Markdown-formatted Detailed Recommendations section
        """
        if not self.check_response.recommendations:
            return """
## Detailed Recommendations

**No optimization opportunities detected. Your BigQuery setup is well-optimized!** ✅
"""

        sorted_recs = self._sorted_recommendations()

        detailed = """
## Detailed Recommendations

"""
        for i, rec in enumerate(sorted_recs, 1):
            clean_title = self._clean_title(rec.title)
            file_ref = None
            for step in rec.implementation_steps:
                file_ref = self._extract_file_reference(step)
                if file_ref:
                    break

            decrypted_description = self._decrypt_identifiers_in_text(rec.description)
            decrypted_description = self._format_size_human_readable(
                decrypted_description
            )
            decrypted_description = self._truncate_query_hash(decrypted_description)

            summary_text = self._build_compact_summary(rec, decrypted_description)
            asset_label = self._build_asset_label(rec, decrypted_description)
            implementation_steps = [
                sanitized
                for step in rec.implementation_steps
                if (sanitized := self._sanitize_step_for_report(step))
            ]
            suggested_action = self._build_suggested_action(rec, implementation_steps)

            detailed += f"""### Recommendation {i}: {clean_title}

| Field | Value |
|-------|-------|
| Category | {self._format_recommendation_type(rec.type)} |
| Estimated Monthly Savings | €{rec.savings_eur:.2f} |

"""

            if asset_label:
                detailed += f"""**Asset:** {asset_label}

"""

            if file_ref and rec.type == "queries":
                detailed += f"""**Query Source:** `{file_ref}`

"""

            if rec.type == "queries":
                query_preview = self._extract_query_preview_from_steps(
                    rec.implementation_steps
                )
                if query_preview:
                    detailed += f"""**Query Preview:**
```sql
{query_preview}
```

"""

                # Add BigQuery job ID for easy query lookup
                job_ids = self._extract_job_ids_from_steps(rec.implementation_steps)
                if job_ids and self.encryptor:
                    # Decrypt the encrypted job ID (contains project ID, encrypted for privacy)
                    encrypted_job_id = job_ids[0]
                    try:
                        decrypted_job_id = self.encryptor.decrypt_with_nonce(
                            encrypted_job_id, context="job_id"
                        )
                        job_link = self._format_job_id_link(decrypted_job_id)
                        detailed += f"""**Find in BigQuery Console:** {job_link}

"""
                    except (ValueError, Exception):
                        # If decryption fails, skip the job ID link
                        logger.debug(
                            f"Failed to decrypt job ID: {encrypted_job_id[:20]}..."
                        )
                        pass

            detailed += f"""> **Why It Was Flagged**\
{summary_text}

"""

            if suggested_action:
                detailed += f"""> **Suggested Action**\
{suggested_action}

"""

            evidence_points = self._build_evidence_points(
                rec.type, decrypted_description
            )
            if evidence_points:
                detailed += """**Confidence Signals:**
"""
                for point in evidence_points:
                    detailed += f"- {point}\n"
                detailed += "\n"

            detailed += """---

"""

        return detailed

    @staticmethod
    def _find_available_path(base_path: Path) -> Path:
        """
        Find an available file path by adding numeric suffix if needed.

        If base_path exists, tries base_path-1, base_path-2, etc.
        until an available name is found.

        Args:
            base_path: Original file path (e.g., sanity-check-report-2026-02-03.md)

        Returns:
            Available file path (may be same as base_path if it doesn't exist)

        Example:
            >>> _find_available_path(Path("report.md"))
            Path("report-1.md")  # if report.md exists
        """
        if not base_path.exists():
            return base_path

        # Extract stem and suffix
        stem = base_path.stem
        suffix = base_path.suffix
        parent = base_path.parent

        # Try sequential numbers until we find an available name
        counter = 1
        while True:
            new_path = parent / f"{stem}-{counter}{suffix}"
            if not new_path.exists():
                return new_path
            counter += 1
            # Safety limit to prevent infinite loop
            if counter > 1000:
                raise ValueError(
                    f"Could not find available filename after 1000 attempts for {base_path}"
                )

    def generate_implementation_guidance(self) -> str:
        """Generate concise operator notes for the recommendation mix."""
        if not self.check_response.recommendations:
            return ""

        rec_types = set(rec.type for rec in self.check_response.recommendations)

        guidance = """
## Operator Notes

- Treat recommendations as decision support, not auto-remediation.
- Start with the largest monthly savings and confirm ownership before changing anything.
- Prefer reversible moves first: snapshot, clone, side-by-side replacement, then cleanup.

"""

        if "storage" in rec_types:
            guidance += """### Storage Hygiene

- Confirm the table is not required by scheduled jobs, dashboards, or downstream exports.
- Snapshot or copy large tables before any destructive action.
- Archive first when ownership is unclear; delete only after a quiet observation period.

"""

        if "clustering" in rec_types:
            guidance += """### Table Layout

- Use clustering only on stable columns that repeatedly appear in filters or grouping.
- Roll out on a copy first if the table supports critical production workloads.
- Compare bytes scanned before and after to validate the improvement.

"""

        if "partitioning" in rec_types:
            guidance += """### Partitioning

- Favor columns already used in recurring date or timestamp predicates.
- Backfill through a replacement table instead of hot-editing heavily used datasets.
- Validate partition pruning on representative queries before switching traffic.

"""

        if "queries" in rec_types:
            guidance += """### Query Efficiency

- Prefer the lightest intervention that removes repeated scan cost.
- Check freshness and refresh cost before moving workloads to materialized outputs.
- Keep the operational footprint small: an optimization is only useful if it stays maintainable.

"""

        if "temporal" in rec_types:
            guidance += """### Lifecycle Management

- Separate true cold data from data that is just queried infrequently.
- Export or tier historical slices before deleting them from expensive serving tables.
- Document restore paths before adopting aggressive retention changes.

"""

        return guidance

    def generate_report(self) -> str:
        """
        Generate complete Markdown report.

        Returns:
            Full Markdown report content
        """
        # Start with header
        report = self.generate_header()

        # Add Executive Summary
        report += self.generate_executive_summary()

        # Add Suggested Action Plan
        report += self.generate_action_plan()

        # Add Detailed Recommendations
        report += self.generate_detailed_recommendations()

        # Add Implementation Guidance
        report += self.generate_implementation_guidance()

        return report

    def save_report(
        self,
        output_dir: Optional[Path] = None,
        output_path: Optional[Path] = None,
        force: bool = False,
        interactive: bool = False,
    ) -> Optional[Path]:
        """
        Generate and save report to file.

        Args:
            output_dir: Directory to save report (deprecated, use output_path instead)
            output_path: Custom output file path (absolute or relative)
            force: Force overwrite without prompt
            interactive: Enable interactive prompts for overwrite

        Returns:
            Absolute path to saved report file if successfully saved.
            Returns None in these cases:
            - File exists, interactive=True, and user declines overwrite
            - File exists, interactive=False, force=False

            **IMPORTANT for callers**: Always check for None return value.
            Example:
                path = generator.save_report(...)
                if path is None:
                    # Handle file not saved (already exists)
                    print("Warning: Report not saved")
                else:
                    print(f"Report saved to {path}")

        Raises:
            PermissionError: If permission denied creating directory or writing file
            ValueError: If output_path is a directory instead of a file path
        """
        # Call Path.cwd() once at the beginning
        # to avoid race conditions and duplicate exception handling
        try:
            current_dir = Path.cwd()
        except FileNotFoundError as e:
            raise ValueError(
                "Current directory no longer exists (was it deleted?). "
                "Please specify an absolute path with --output."
            ) from e

        # Determine final output path
        if output_path is not None:
            # Detect trailing slash (user might think it's a directory)
            if str(output_path).endswith("/") or str(output_path).endswith("\\"):
                raise ValueError(
                    f"output_path appears to be a directory (ends with slash): {output_path}. "
                    "Please specify a filename, e.g., 'reports/sanity-check.md' not 'reports/'"
                )

            # Custom path provided - resolve to absolute
            if not output_path.is_absolute():
                # Relative path - resolve against cwd
                final_path = current_dir / output_path
            else:
                final_path = output_path

            # Validate that output_path is not a directory
            if final_path.exists() and final_path.is_dir():
                raise ValueError(
                    f"output_path must be a file path, not a directory: {final_path}"
                )
        else:
            # Default behavior - use output_dir (legacy) or cwd
            # Include full timestamp to avoid naming conflicts
            timestamp_str = self.timestamp.strftime("%Y-%m-%d-%H%M%S")
            filename = f"sanity-check-report-{timestamp_str}.md"

            if output_dir is None:
                output_dir = current_dir

            final_path = output_dir / filename

        # Ensure parent directory exists
        try:
            final_path.parent.mkdir(parents=True, exist_ok=True)
        except PermissionError as e:
            raise PermissionError(
                f"Permission denied creating directory {final_path.parent}"
            ) from e

        # Check if file exists and handle overwrite
        if final_path.exists() and not force:
            if interactive:
                # Prompt user for overwrite
                # Validate input, handle non-TTY, limit length
                try:
                    response = input(
                        f"File exists: {final_path}. Overwrite? [y/N] "
                    ).strip()[:10]
                    if response.lower() not in ("y", "yes"):
                        # User declined - return None to indicate no action taken
                        return None
                except (EOFError, KeyboardInterrupt):
                    # Handle non-TTY or user cancellation
                    # EOFError: No TTY (batch mode, piped input)
                    # KeyboardInterrupt: User pressed Ctrl+C
                    return None
            else:
                # Non-interactive and not force - find available filename with suffix
                # This ensures scan results are always saved (no wasted tokens)
                final_path = self._find_available_path(final_path)

        # Generate and save report
        report_content = self.generate_report()
        try:
            final_path.write_text(report_content, encoding="utf-8")
        except PermissionError as e:
            raise PermissionError(f"Permission denied writing to {final_path}") from e
        except (OSError, IOError, UnicodeEncodeError) as e:
            # Catch all file operation errors
            # OSError: disk full, filesystem errors
            # IOError: I/O operation failed
            # UnicodeEncodeError: encoding failed
            raise IOError(f"Failed to write report to {final_path}: {e}") from e

        return final_path
