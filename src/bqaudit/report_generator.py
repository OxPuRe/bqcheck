"""Markdown audit report generator (Story 5.2).

Generates well-formatted Markdown reports from AuditResponse data.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from bqaudit.api.models import AuditResponse
from bqaudit.scanner.encryption import IdentifierEncryptor


class MarkdownReportGenerator:
    """
    Generate Markdown audit reports from AuditResponse.

    Features:
    - Executive Summary with aggregate statistics
    - Quick Wins (top 3-5 HIGH priority recommendations)
    - Detailed Recommendations sorted by priority and savings
    - Zero-recommendations handling

    Usage:
        >>> response = AuditResponse(...)
        >>> generator = MarkdownReportGenerator(response, project_name="my-project")
        >>> report_path = generator.generate_and_save()
    """

    def __init__(
        self,
        audit_response: AuditResponse,
        project_name: str = "Unknown",
        encryption_key: Optional[bytes] = None,
    ):
        """
        Initialize report generator.

        Args:
            audit_response: AuditResponse from server
            project_name: GCP project name for report title
            encryption_key: Optional 32-byte AES-256 encryption key for decrypting identifiers.
                          If provided, encrypted table/dataset names in recommendations
                          will be decrypted to human-readable names.
        """
        self.audit_response = audit_response
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
            >>> from bqaudit.scanner.encryption import IdentifierEncryptor
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

        # Pattern 1: Match "dataset.table" format (encrypted pairs)
        # Base64url chars: A-Za-z0-9_-
        pattern_pair = r"\b([A-Za-z0-9_-]{20,})\.([A-Za-z0-9_-]{20,})\b"

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

        # First pass: decrypt dataset.table pairs
        text = re.sub(pattern_pair, decrypt_pair, text)

        # Pattern 2: Match standalone encrypted identifiers (not already decrypted)
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

        # Second pass: decrypt standalone identifiers
        text = re.sub(pattern_standalone, decrypt_standalone, text)

        return text

    @staticmethod
    def _clean_title(title: Optional[str]) -> str:
        """
        Clean recommendation title by rounding decimals.

        Args:
            title: Raw title from server (may be None)

        Returns:
            Cleaned title with rounded decimals, or "Untitled" if None

        Example:
            >>> _clean_title("Materialize repeated query (6.048781288508676/day)")
            "Materialize repeated query (6.0/day)"
        """
        if title is None:
            return "Untitled"

        # Round decimals like "6.048781288508676/day" -> "6.0/day"
        def round_decimal(match: re.Match[str]) -> str:
            value = float(match.group(1))
            # Round to 1 decimal place
            return f"{value:.1f}/{match.group(2)}"

        return re.sub(r"(\d+\.\d+)/(\w+)", round_decimal, title)

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
        audit_date = self.timestamp.strftime("%Y-%m-%d")
        timestamp_iso = self.timestamp.isoformat()

        return f"""# BigQuery Audit Report - {self.project_name}

**Audit Date:** {audit_date}
**Generated:** {timestamp_iso}

---
"""

    def generate_executive_summary(self) -> str:
        """
        Generate Executive Summary section with aggregate statistics.

        Returns:
            Markdown-formatted Executive Summary
        """
        summary = self.audit_response.summary

        # Build summary table
        exec_summary = f"""
## Executive Summary

| Metric | Value |
|--------|-------|
| Total Recommendations | {summary.total_recommendations} |
| Potential Monthly Savings | €{summary.total_potential_savings_eur:.2f} |
| High Priority | {summary.high_priority_count} |
| Medium Priority | {summary.medium_priority_count} |
| Low Priority | {summary.low_priority_count} |
"""

        # Add category breakdown if we have recommendations
        if summary.categories_breakdown:
            # Calculate savings per category from recommendations
            category_savings = {}
            for rec in self.audit_response.recommendations:
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
                savings = category_savings.get(category, 0.0)
                exec_summary += (
                    f"| {category.capitalize()} | {count} | €{savings:.2f} |\n"
                )

        return exec_summary

    def generate_quick_wins(self) -> str:
        """
        Generate Quick Wins section with top HIGH priority recommendations.

        Returns:
            Markdown-formatted Quick Wins section
        """
        # Filter HIGH priority and sort by savings
        high_priority = [
            rec for rec in self.audit_response.recommendations if rec.priority == "HIGH"
        ]
        high_priority_sorted = sorted(
            high_priority, key=lambda r: r.savings_eur, reverse=True
        )

        # Take top 5
        top_wins = high_priority_sorted[:5]

        if not top_wins:
            return """
## Quick Wins

_No high-priority recommendations at this time._
"""

        quick_wins = """
## Quick Wins

Top high-priority optimizations for immediate impact:

"""
        for i, rec in enumerate(top_wins, 1):
            clean_title = self._clean_title(rec.title)
            # Decrypt identifiers in description if encryption key available
            decrypted_description = self._decrypt_identifiers_in_text(rec.description)
            quick_wins += f"""{i}. **{clean_title}** - €{rec.savings_eur:.2f}/month
   - {decrypted_description}

"""

        return quick_wins

    def generate_detailed_recommendations(self) -> str:
        """
        Generate Detailed Recommendations section.

        All recommendations sorted by priority (HIGH → MEDIUM → LOW),
        then by savings within same priority.

        Returns:
            Markdown-formatted Detailed Recommendations section
        """
        if not self.audit_response.recommendations:
            return """
## Detailed Recommendations

**No optimization opportunities detected. Your BigQuery setup is well-optimized!** ✅
"""

        # Define priority order
        priority_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}

        # Sort recommendations
        sorted_recs = sorted(
            self.audit_response.recommendations,
            key=lambda r: (priority_order.get(r.priority, 3), -r.savings_eur),
        )

        detailed = """
## Detailed Recommendations

"""
        for i, rec in enumerate(sorted_recs, 1):
            # Clean title (round decimals)
            clean_title = self._clean_title(rec.title)

            # Extract file reference from steps if available
            file_ref = None
            for step in rec.implementation_steps:
                file_ref = self._extract_file_reference(step)
                if file_ref:
                    break

            detailed += f"""### Recommendation {i}: {clean_title}

**Type:** {rec.type}
**Priority:** {rec.priority}
**Estimated Monthly Savings:** €{rec.savings_eur:.2f}
"""

            # Add source file reference if found (for query recommendations)
            if file_ref and rec.type == "queries":
                detailed += f"""**Query Source:** `{file_ref}`

"""

            # Decrypt identifiers in description
            decrypted_description = self._decrypt_identifiers_in_text(rec.description)

            detailed += f"""**Description:**
{decrypted_description}

---

"""

        return detailed

    @staticmethod
    def _find_available_path(base_path: Path) -> Path:
        """
        Find an available file path by adding numeric suffix if needed.

        If base_path exists, tries base_path-1, base_path-2, etc.
        until an available name is found.

        Args:
            base_path: Original file path (e.g., audit-report-2026-02-03.md)

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
        """
        Generate Implementation Guidance section with context-specific instructions.

        Analyzes recommendation types present in the report and generates
        relevant implementation guidance for each type.

        Returns:
            Markdown-formatted Implementation Guidance section
        """
        if not self.audit_response.recommendations:
            return ""

        # Detect which recommendation types are present
        rec_types = set(rec.type for rec in self.audit_response.recommendations)

        guidance = """
## Implementation Guidance

### Getting Started

1. **Prioritize High-Impact Changes**: Start with HIGH priority recommendations that offer the largest monthly savings
2. **Test in Non-Production**: Always test changes in a development or staging environment first
3. **Backup Before Changes**: Create table snapshots before making destructive changes
4. **Monitor After Changes**: Verify that queries continue to work and performance improves

"""

        # Add type-specific implementation sections
        if "storage" in rec_types:
            guidance += """### Removing Unused Tables

For tables identified as unused:

1. **Verify table is truly unused**
   - Check application code and documentation
   - Confirm with data owners and stakeholders
   - Review any data retention policies

2. **Create backup** (if needed)
   ```bash
   # Create backup dataset if it doesn't exist
   bq mk --dataset backup_dataset

   # Copy table to backup
   bq cp project.dataset.table_name backup_dataset.table_name
   ```

3. **Delete the table**
   ```sql
   DROP TABLE `project.dataset.table_name`
   ```

4. **Verify and monitor**
   - Monitor application logs for errors
   - Check for failed scheduled queries
   - If issues arise, restore from backup

"""

        if "clustering" in rec_types:
            guidance += """### Adding Clustering

For tables that would benefit from clustering:

1. **Identify clustering columns**
   - Review WHERE and GROUP BY clauses in your queries
   - Choose columns with high cardinality
   - Order columns by query filter frequency (max 4 columns)

2. **Create clustered table**
   ```sql
   -- Option A: Create new table with clustering
   CREATE TABLE `project.dataset.table_clustered`
   CLUSTER BY column1, column2, column3
   AS SELECT * FROM `project.dataset.table_original`

   -- Option B: Copy to new table
   bq mk --table \\
     --clustering_fields=column1,column2,column3 \\
     project:dataset.table_clustered

   bq cp project:dataset.table_original project:dataset.table_clustered
   ```

3. **Validate query performance**
   - Run test queries and compare bytes scanned
   - Verify cost reduction in query execution details
   - Update application to use new table name

"""

        if "partitioning" in rec_types:
            guidance += """### Adding Partitioning

For tables that would benefit from partitioning:

1. **Choose partition column**
   - Prefer DATE or TIMESTAMP columns
   - Select column frequently used in WHERE clauses
   - Consider data distribution (avoid skewed partitions)

2. **Create partitioned table**
   ```sql
   -- Daily partitioning example
   CREATE TABLE `project.dataset.table_partitioned`
   PARTITION BY DATE(timestamp_column)
   AS SELECT * FROM `project.dataset.table_original`
   ```

3. **Verify partition pruning**
   - Add partition filter to queries (WHERE DATE(timestamp_column) = '2024-01-01')
   - Check query execution details for partition pruning
   - Compare bytes scanned before/after

"""

        if "queries" in rec_types:
            guidance += """### Materializing Repeated Queries

For frequently-run expensive queries:

1. **Create materialized view or scheduled query**
   ```sql
   -- Option A: Materialized view (auto-refresh)
   CREATE MATERIALIZED VIEW `project.dataset.mv_name`
   AS
   SELECT ... FROM ...

   -- Option B: Scheduled table update
   -- Set up via Cloud Console > Scheduled Queries
   ```

2. **Update application queries**
   - Replace original query with simple SELECT from materialized view
   - Test query performance improvement
   - Monitor view refresh costs vs. query savings

3. **Configure refresh schedule**
   - Balance freshness requirements vs. refresh costs
   - Consider incremental updates for large datasets

"""

        if "temporal" in rec_types:
            guidance += """### Archiving Old Data

For tables with historical data that's rarely accessed:

1. **Identify data to archive**
   - Determine cutoff date based on business requirements
   - Separate active vs. historical data

2. **Export to Cloud Storage**
   ```bash
   # Export old data to cheaper storage
   bq extract \\
     --destination_format=PARQUET \\
     'project:dataset.table_name$20230101-20231231' \\
     gs://bucket/archive/table_name_2023_*.parquet
   ```

3. **Delete archived data**
   ```sql
   -- For partitioned tables
   DELETE FROM `project.dataset.table_name`
   WHERE DATE(partition_column) < '2024-01-01'
   ```

4. **Document archive location**
   - Maintain inventory of archived data
   - Document restore procedure if needed

"""

        # Add general footer
        guidance += """### Need Help?

- **BigQuery Documentation**: [Best Practices](https://cloud.google.com/bigquery/docs/best-practices)
- **Cost Optimization**: [Controlling Costs](https://cloud.google.com/bigquery/docs/best-practices-costs)
- **Table Management**: [Managing Tables](https://cloud.google.com/bigquery/docs/managing-tables)

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

        # Add Quick Wins
        report += self.generate_quick_wins()

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
            Returns None in these cases (Story 5.3):
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
            # Story 5.3: Detect trailing slash (user might think it's a directory)
            if str(output_path).endswith("/") or str(output_path).endswith("\\"):
                raise ValueError(
                    f"output_path appears to be a directory (ends with slash): {output_path}. "
                    "Please specify a filename, e.g., 'reports/audit.md' not 'reports/'"
                )

            # Custom path provided - resolve to absolute
            if not output_path.is_absolute():
                # Relative path - resolve against cwd
                final_path = current_dir / output_path
            else:
                final_path = output_path

            # Story 5.3: Validate that output_path is not a directory
            if final_path.exists() and final_path.is_dir():
                raise ValueError(
                    f"output_path must be a file path, not a directory: {final_path}"
                )
        else:
            # Default behavior - use output_dir (legacy) or cwd
            # Include full timestamp to avoid naming conflicts
            timestamp_str = self.timestamp.strftime("%Y-%m-%d-%H%M%S")
            filename = f"audit-report-{timestamp_str}.md"

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
