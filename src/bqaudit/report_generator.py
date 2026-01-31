"""Markdown audit report generator (Story 5.2).

Generates well-formatted Markdown reports from AuditResponse data.
"""

from datetime import datetime, timezone
from pathlib import Path

from bqaudit.api.models import AuditResponse, Recommendation


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
            exec_summary += """
### Savings Breakdown by Category

| Category | Count |
|----------|-------|
"""
            for category, count in sorted(summary.categories_breakdown.items()):
                exec_summary += f"| {category.capitalize()} | {count} |\n"

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
            quick_wins += f"""{i}. **{rec.title}** - €{rec.savings_eur:.2f}/month
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
            detailed += f"""### Recommendation {i}: {rec.title}

**Type:** {rec.type}
**Priority:** {rec.priority}
**Estimated Monthly Savings:** €{rec.savings_eur:.2f}

**Description:**
{rec.description}

**Implementation Steps:**
"""
            for step_num, step in enumerate(rec.implementation_steps, 1):
                detailed += f"{step_num}. {step}\n"

            detailed += "\n---\n\n"

        return detailed

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

        return report

    def save_report(self, output_dir: Path | None = None) -> Path:
        """
        Generate and save report to file.

        Args:
            output_dir: Directory to save report (defaults to current working directory)

        Returns:
            Absolute path to saved report file
        """
        # Generate filename with date
        date_str = self.timestamp.strftime("%Y-%m-%d")
        filename = f"audit-report-{date_str}.md"

        # Determine output directory
        if output_dir is None:
            output_dir = Path.cwd()

        # Ensure directory exists
        output_dir.mkdir(parents=True, exist_ok=True)

        # Full path
        output_path = output_dir / filename

        # Generate and save report
        report_content = self.generate_report()
        output_path.write_text(report_content, encoding="utf-8")

        return output_path
