"""Markdown audit report generator (Story 5.2).

Generates well-formatted Markdown reports from AuditResponse data.
"""

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from bqaudit.api.models import AuditResponse


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

    def __init__(self, audit_response: AuditResponse, project_name: str = "Unknown"):
        """
        Initialize report generator.

        Args:
            audit_response: AuditResponse from server
            project_name: GCP project name for report title
        """
        self.audit_response = audit_response
        self.project_name = project_name
        self.timestamp = datetime.now(timezone.utc)

    @staticmethod
    def _clean_title(title: str) -> str:
        """
        Clean recommendation title by rounding decimals.

        Args:
            title: Raw title from server

        Returns:
            Cleaned title with rounded decimals

        Example:
            >>> _clean_title("Materialize repeated query (6.048781288508676/day)")
            "Materialize repeated query (6.0/day)"
        """
        # Round decimals like "6.048781288508676/day" -> "6.0/day"
        def round_decimal(match):
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
            quick_wins += f"""{i}. **{clean_title}** - €{rec.savings_eur:.2f}/month
   - {rec.description}

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

            detailed += f"""**Description:**
{rec.description}

**Implementation Steps:**
"""
            for step_num, step in enumerate(rec.implementation_steps, 1):
                # Truncate large SQL blocks
                cleaned_step = self._truncate_sql_in_step(step, max_lines=10)
                detailed += f"{step_num}. {cleaned_step}\n"

            detailed += "\n---\n\n"

        return detailed

    def generate_implementation_guidance(self) -> str:
        """
        Generate Implementation Guidance section.

        Returns:
            Markdown-formatted Implementation Guidance section
        """
        if not self.audit_response.recommendations:
            return ""

        guidance = """
## Implementation Guidance

### Getting Started

1. **Prioritize High-Impact Changes**: Start with HIGH priority recommendations that offer the largest monthly savings
2. **Test in Non-Production**: Always test changes in a development or staging environment first
3. **Monitor Query Performance**: Use BigQuery's query execution details to validate improvements
4. **Backup Before Changes**: Create table snapshots before modifying partitioning or clustering

### Best Practices

- **Partitioning**: Implement date-based partitioning for time-series data to reduce scan costs
- **Clustering**: Add clustering keys for columns frequently used in WHERE and GROUP BY clauses
- **Storage Cleanup**: Schedule regular reviews of unused tables and datasets
- **Query Optimization**: Review and optimize queries identified as expensive or repetitive

### Need Help?

Refer to [BigQuery Best Practices](https://cloud.google.com/bigquery/docs/best-practices) for detailed guidance on implementing these recommendations.

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
            date_str = self.timestamp.strftime("%Y-%m-%d")
            filename = f"audit-report-{date_str}.md"

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
        # Story 5.3: Return None instead of raising exception for better separation of concerns
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
                # Non-interactive and not force - return None to let caller decide
                return None

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
