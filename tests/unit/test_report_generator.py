"""Unit tests for Markdown report generator (Story 5.2)."""

import pytest

from bqaudit.api.models import AuditResponse, AuditSummary, Recommendation
from bqaudit.report_generator import MarkdownReportGenerator


@pytest.fixture
def sample_recommendations():
    """Create sample recommendations for testing."""
    return [
        Recommendation(
            type="unused_storage",
            priority="HIGH",
            title="Remove unused table 'staging.tmp_data'",
            description="Table has not been accessed in 90 days",
            savings_eur=150.0,
            implementation_steps=[
                "Verify table is not in use",
                "DROP TABLE staging.tmp_data",
            ],
        ),
        Recommendation(
            type="partitioning",
            priority="MEDIUM",
            title="Add partitioning to analytics.events",
            description="Large table would benefit from date partitioning",
            savings_eur=75.0,
            implementation_steps=[
                "Create partitioned table",
                "Copy data",
                "Swap tables",
            ],
        ),
        Recommendation(
            type="clustering",
            priority="LOW",
            title="Add clustering to analytics.sessions",
            description="Improve query performance with clustering",
            savings_eur=25.0,
            implementation_steps=["ALTER TABLE ADD CLUSTERING"],
        ),
    ]


@pytest.fixture
def sample_audit_response(sample_recommendations):
    """Create sample AuditResponse for testing."""
    return AuditResponse(
        recommendations=sample_recommendations,
        summary=AuditSummary(
            total_recommendations=3,
            total_potential_savings_eur=250.0,
            high_priority_count=1,
            medium_priority_count=1,
            low_priority_count=1,
            categories_breakdown={"storage": 1, "partitioning": 1, "clustering": 1},
        ),
        audit_id="test_audit_123",
        new_ephemeral_token="eph_new_token",
    )


class TestReportHeader:
    """Test report header generation (Task 1.2)."""

    def test_header_includes_project_name(self, sample_audit_response):
        """Test that header includes project name."""
        generator = MarkdownReportGenerator(
            sample_audit_response, project_name="test-project"
        )

        header = generator.generate_header()

        assert "# BigQuery Audit Report - test-project" in header

    def test_header_includes_audit_date(self, sample_audit_response):
        """Test that header includes audit date."""
        generator = MarkdownReportGenerator(sample_audit_response)

        header = generator.generate_header()

        # Should contain **Audit Date:** line
        assert "**Audit Date:**" in header

    def test_header_includes_timestamp(self, sample_audit_response):
        """Test that header includes ISO timestamp."""
        generator = MarkdownReportGenerator(sample_audit_response)

        header = generator.generate_header()

        # Should contain **Generated:** line with ISO format
        assert "**Generated:**" in header
        assert "T" in header  # ISO format has 'T' separator


class TestReportGeneration:
    """Test complete report generation."""

    def test_generate_report_returns_string(self, sample_audit_response):
        """Test that generate_report returns a string."""
        generator = MarkdownReportGenerator(sample_audit_response)

        report = generator.generate_report()

        assert isinstance(report, str)
        assert len(report) > 0

    def test_generate_report_includes_header(self, sample_audit_response):
        """Test that report includes header."""
        generator = MarkdownReportGenerator(
            sample_audit_response, project_name="my-project"
        )

        report = generator.generate_report()

        assert "# BigQuery Audit Report - my-project" in report


class TestExecutiveSummary:
    """Test Executive Summary generation (Task 2)."""

    def test_executive_summary_includes_total_recommendations(
        self, sample_audit_response
    ):
        """Test that Executive Summary includes total count."""
        generator = MarkdownReportGenerator(sample_audit_response)

        summary = generator.generate_executive_summary()

        assert "Total Recommendations | 3" in summary

    def test_executive_summary_includes_total_savings(self, sample_audit_response):
        """Test that Executive Summary includes total potential savings."""
        generator = MarkdownReportGenerator(sample_audit_response)

        summary = generator.generate_executive_summary()

        assert "Potential Monthly Savings | €250.00" in summary

    def test_executive_summary_includes_priority_breakdown(self, sample_audit_response):
        """Test that Executive Summary includes priority counts."""
        generator = MarkdownReportGenerator(sample_audit_response)

        summary = generator.generate_executive_summary()

        assert "High Priority | 1" in summary
        assert "Medium Priority | 1" in summary
        assert "Low Priority | 1" in summary

    def test_executive_summary_zero_recommendations(self):
        """Test Executive Summary with 0 recommendations."""
        empty_response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test_audit_empty",
            new_ephemeral_token="eph_token",
        )
        generator = MarkdownReportGenerator(empty_response)

        summary = generator.generate_executive_summary()

        assert "Total Recommendations | 0" in summary
        assert "€0.00" in summary


class TestQuickWins:
    """Test Quick Wins section generation (Task 3)."""

    def test_quick_wins_shows_top_5_high_priority(self):
        """Test Quick Wins shows top 5 HIGH priority recommendations."""
        # Create 7 HIGH priority recommendations
        recommendations = [
            Recommendation(
                type=f"type_{i}",
                priority="HIGH",
                title=f"High priority {i}",
                description=f"Description {i}",
                savings_eur=float(100 - i * 10),  # Descending savings
                implementation_steps=["Step 1"],
            )
            for i in range(7)
        ]
        response = AuditResponse(
            recommendations=recommendations,
            summary=AuditSummary(
                total_recommendations=7,
                total_potential_savings_eur=700.0,
                high_priority_count=7,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        quick_wins = generator.generate_quick_wins()

        # Should show exactly 5 recommendations
        assert quick_wins.count("1. **") == 1
        assert quick_wins.count("5. **") == 1
        assert quick_wins.count("6. **") == 0

    def test_quick_wins_with_only_2_high_priority(self):
        """Test Quick Wins with fewer than 5 HIGH priority recs."""
        recommendations = [
            Recommendation(
                type="type_1",
                priority="HIGH",
                title="High 1",
                description="Desc 1",
                savings_eur=100.0,
                implementation_steps=["Step 1"],
            ),
            Recommendation(
                type="type_2",
                priority="HIGH",
                title="High 2",
                description="Desc 2",
                savings_eur=50.0,
                implementation_steps=["Step 1"],
            ),
        ]
        response = AuditResponse(
            recommendations=recommendations,
            summary=AuditSummary(
                total_recommendations=2,
                total_potential_savings_eur=150.0,
                high_priority_count=2,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        quick_wins = generator.generate_quick_wins()

        # Should show only 2
        assert quick_wins.count("1. **") == 1
        assert quick_wins.count("2. **") == 1
        assert quick_wins.count("3. **") == 0

    def test_quick_wins_with_zero_high_priority(self):
        """Test Quick Wins with 0 HIGH priority recommendations."""
        # Create recommendations with no HIGH priority
        recommendations = [
            Recommendation(
                type=f"type_{i}",
                priority="MEDIUM",
                title=f"Medium priority {i}",
                description=f"Description {i}",
                savings_eur=float(50 - i * 5),
                implementation_steps=["Step 1"],
            )
            for i in range(7)
        ] + [
            Recommendation(
                type="type_low",
                priority="LOW",
                title="Low priority",
                description="Low priority desc",
                savings_eur=10.0,
                implementation_steps=["Step 1"],
            )
        ]
        response = AuditResponse(
            recommendations=recommendations,
            summary=AuditSummary(
                total_recommendations=8,
                total_potential_savings_eur=200.0,
                high_priority_count=0,
                medium_priority_count=7,
                low_priority_count=1,
                categories_breakdown={},
            ),
            audit_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        quick_wins = generator.generate_quick_wins()

        # Should show message about no high-priority recommendations
        assert "_No high-priority recommendations at this time._" in quick_wins


class TestDetailedRecommendations:
    """Test Detailed Recommendations section (Task 4)."""

    def test_detailed_recs_sorted_by_priority(self, sample_recommendations):
        """Test that recommendations are sorted by priority."""
        response = AuditResponse(
            recommendations=sample_recommendations,
            summary=AuditSummary(
                total_recommendations=3,
                total_potential_savings_eur=250.0,
                high_priority_count=1,
                medium_priority_count=1,
                low_priority_count=1,
                categories_breakdown={},
            ),
            audit_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        detailed = generator.generate_detailed_recommendations()

        # HIGH should come before MEDIUM before LOW
        high_pos = detailed.find("unused_storage")  # HIGH priority
        medium_pos = detailed.find("partitioning")  # MEDIUM priority
        low_pos = detailed.find("clustering")  # LOW priority

        assert high_pos < medium_pos < low_pos

    def test_detailed_recs_includes_all_fields(self, sample_recommendations):
        """Test that all recommendation fields are included."""
        response = AuditResponse(
            recommendations=sample_recommendations[:1],  # Just first one
            summary=AuditSummary(
                total_recommendations=1,
                total_potential_savings_eur=150.0,
                high_priority_count=1,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        detailed = generator.generate_detailed_recommendations()

        assert "**Type:**" in detailed
        assert "**Priority:**" in detailed
        assert "**Estimated Monthly Savings:**" in detailed
        assert "**Description:**" in detailed
        # Implementation Steps removed - guidance now in separate section


class TestFileSaving:
    """Test file saving logic (Task 5)."""

    def test_save_report_creates_file(self, sample_audit_response, tmp_path):
        """Test that save_report creates a file."""
        generator = MarkdownReportGenerator(sample_audit_response)

        output_path = generator.save_report(output_dir=tmp_path)

        assert output_path.exists()
        assert output_path.is_file()

    def test_save_report_filename_format(self, sample_audit_response, tmp_path):
        """Test that filename follows audit-report-YYYY-MM-DD.md format."""
        generator = MarkdownReportGenerator(sample_audit_response)

        output_path = generator.save_report(output_dir=tmp_path)

        # Should match pattern
        assert output_path.name.startswith("audit-report-")
        assert output_path.name.endswith(".md")

    def test_save_report_contains_full_report(self, sample_audit_response, tmp_path):
        """Test that saved file contains complete report."""
        generator = MarkdownReportGenerator(
            sample_audit_response, project_name="test-project"
        )

        output_path = generator.save_report(output_dir=tmp_path)
        content = output_path.read_text()

        # Should contain all sections
        assert "# BigQuery Audit Report - test-project" in content
        assert "## Executive Summary" in content
        assert "## Quick Wins" in content
        assert "## Detailed Recommendations" in content

    def test_save_report_auto_suffix_when_file_exists(
        self, sample_audit_response, tmp_path
    ):
        """Test that save_report adds suffix when file exists (non-interactive)."""

        generator = MarkdownReportGenerator(sample_audit_response)
        output_file = tmp_path / "test-report.md"

        # Save first report (interactive=False, force=False)
        path1 = generator.save_report(
            output_path=output_file, interactive=False, force=False
        )
        assert path1 == output_file
        assert path1.exists()

        # Save second report with same name - should add -1 suffix
        path2 = generator.save_report(
            output_path=output_file, interactive=False, force=False
        )
        assert path2 == tmp_path / "test-report-1.md"
        assert path2.exists()
        assert path1.exists()  # Original still exists

        # Save third report - should add -2 suffix
        path3 = generator.save_report(
            output_path=output_file, interactive=False, force=False
        )
        assert path3 == tmp_path / "test-report-2.md"
        assert path3.exists()
        assert path1.exists()
        assert path2.exists()

    def test_save_report_force_overwrites_existing(
        self, sample_audit_response, tmp_path
    ):
        """Test that force=True overwrites existing file without suffix."""

        generator = MarkdownReportGenerator(sample_audit_response)
        output_file = tmp_path / "test-report.md"

        # Create existing file with different content
        output_file.write_text("old content")

        # Save with force=True - should overwrite
        path = generator.save_report(output_path=output_file, force=True)
        assert path == output_file
        assert "old content" not in path.read_text()
        assert "# BigQuery Audit Report" in path.read_text()


class TestFindAvailablePath:
    """Test automatic filename suffix generation."""

    def test_find_available_path_returns_base_when_not_exists(self, tmp_path):
        """Test that base path is returned when it doesn't exist."""

        base_path = tmp_path / "report.md"
        available = MarkdownReportGenerator._find_available_path(base_path)

        assert available == base_path

    def test_find_available_path_adds_suffix_when_exists(self, tmp_path):
        """Test that -1 suffix is added when base path exists."""

        base_path = tmp_path / "report.md"
        base_path.write_text("existing")

        available = MarkdownReportGenerator._find_available_path(base_path)

        assert available == tmp_path / "report-1.md"
        assert not available.exists()

    def test_find_available_path_increments_suffix(self, tmp_path):
        """Test that suffix increments when multiple files exist."""

        base_path = tmp_path / "report.md"
        (tmp_path / "report.md").write_text("0")
        (tmp_path / "report-1.md").write_text("1")
        (tmp_path / "report-2.md").write_text("2")

        available = MarkdownReportGenerator._find_available_path(base_path)

        assert available == tmp_path / "report-3.md"
        assert not available.exists()

    def test_find_available_path_handles_gaps_in_sequence(self, tmp_path):
        """Test that first available number is used (even with gaps)."""

        base_path = tmp_path / "report.md"
        (tmp_path / "report.md").write_text("0")
        (tmp_path / "report-2.md").write_text("2")  # Gap at -1

        available = MarkdownReportGenerator._find_available_path(base_path)

        # Should use -1 (first available), not -3
        assert available == tmp_path / "report-1.md"
        assert not available.exists()

    def test_find_available_path_preserves_extension(self, tmp_path):
        """Test that file extension is preserved correctly."""

        base_path = tmp_path / "audit-report-2026-02-03.md"
        base_path.write_text("existing")

        available = MarkdownReportGenerator._find_available_path(base_path)

        assert available == tmp_path / "audit-report-2026-02-03-1.md"
        assert available.suffix == ".md"


class TestRecommendationFormatting:
    """Test recommendation formatting helpers."""

    def test_clean_title_rounds_decimals(self):
        """Test that _clean_title rounds long decimals."""
        title = "Materialize repeated query (6.048781288508676/day)"
        cleaned = MarkdownReportGenerator._clean_title(title)
        assert cleaned == "Materialize repeated query (6.0/day)"

    def test_clean_title_preserves_integer_decimals(self):
        """Test that _clean_title handles integer-like decimals."""
        title = "Optimize query (10.0/month)"
        cleaned = MarkdownReportGenerator._clean_title(title)
        assert cleaned == "Optimize query (10.0/month)"

    def test_clean_title_no_decimals_unchanged(self):
        """Test that titles without decimals are unchanged."""
        title = "Remove unused table"
        cleaned = MarkdownReportGenerator._clean_title(title)
        assert cleaned == "Remove unused table"

    def test_extract_file_reference_from_comment(self):
        """Test extracting file path from SQL comment."""
        text = "-- Query logic taken from mobility/mobility/queries/compute_pickwell.sql"
        file_ref = MarkdownReportGenerator._extract_file_reference(text)
        assert file_ref == "mobility/mobility/queries/compute_pickwell.sql"

    def test_extract_file_reference_from_text(self):
        """Test extracting file path from descriptive text."""
        text = "See full query in mobility/queries/report.sql for details"
        file_ref = MarkdownReportGenerator._extract_file_reference(text)
        assert file_ref == "mobility/queries/report.sql"

    def test_extract_file_reference_none_when_missing(self):
        """Test that None is returned when no file reference found."""
        text = "This is a regular description without any file paths"
        file_ref = MarkdownReportGenerator._extract_file_reference(text)
        assert file_ref is None

    def test_truncate_sql_in_step_short_sql(self):
        """Test that short SQL is not truncated."""
        step = "CREATE TABLE foo AS SELECT * FROM bar LIMIT 10"
        truncated = MarkdownReportGenerator._truncate_sql_in_step(step, max_lines=10)
        assert truncated == step
        assert "[SQL truncated" not in truncated

    def test_truncate_sql_in_step_long_sql(self):
        """Test that long SQL is truncated with message."""
        lines = ["CREATE TABLE foo AS ("] + [f"  SELECT col{i}," for i in range(20)] + [")"]
        step = "\n".join(lines)

        truncated = MarkdownReportGenerator._truncate_sql_in_step(step, max_lines=10)

        assert "[SQL truncated - 12 more lines]" in truncated
        assert truncated.count("\n") < step.count("\n")

    def test_truncate_sql_in_step_with_file_reference(self):
        """Test that file reference is extracted and shown in truncation."""
        lines = (
            ["CREATE VIEW AS -- Query from mobility/queries/test.sql"]
            + [f"SELECT col{i}," for i in range(20)]
        )
        step = "\n".join(lines)

        truncated = MarkdownReportGenerator._truncate_sql_in_step(step, max_lines=5)

        assert "[SQL truncated" in truncated
        assert "See full query in: `mobility/queries/test.sql`" in truncated

    def test_truncate_sql_in_step_non_sql_unchanged(self):
        """Test that non-SQL steps are not truncated."""
        step = "This is a regular step\nwith multiple lines\nbut no SQL keywords"
        truncated = MarkdownReportGenerator._truncate_sql_in_step(step, max_lines=2)
        assert truncated == step


class TestEdgeCases:
    """Test edge case handling (Task 6)."""

    def test_zero_recommendations_message(self):
        """Test report with 0 recommendations shows optimized message."""
        empty_response = AuditResponse(
            recommendations=[],
            summary=AuditSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            audit_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(empty_response)

        report = generator.generate_report()

        assert "No optimization opportunities detected" in report
        assert "well-optimized" in report
        assert "€0.00" in report

    def test_large_recommendations_set(self):
        """Test report generation with 100+ recommendations."""
        # Create 150 recommendations with mixed priorities
        recommendations = []
        for i in range(150):
            priority = "HIGH" if i < 50 else "MEDIUM" if i < 120 else "LOW"
            recommendations.append(
                Recommendation(
                    type=f"type_{i % 5}",
                    priority=priority,
                    title=f"Recommendation {i}",
                    description=f"Description for recommendation {i}",
                    savings_eur=float(1000 - i),
                    implementation_steps=[f"Step {j}" for j in range(1, 4)],
                )
            )

        response = AuditResponse(
            recommendations=recommendations,
            summary=AuditSummary(
                total_recommendations=150,
                total_potential_savings_eur=sum(r.savings_eur for r in recommendations),
                high_priority_count=50,
                medium_priority_count=70,
                low_priority_count=30,
                categories_breakdown={
                    "storage": 30,
                    "queries": 40,
                    "partitioning": 40,
                    "clustering": 30,
                    "temporal": 10,
                },
            ),
            audit_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        report = generator.generate_report()

        # Verify report generates successfully
        assert "# BigQuery Audit Report" in report
        assert "Total Recommendations | 150" in report
        assert "## Quick Wins" in report
        assert "## Detailed Recommendations" in report

        # Verify all 150 recommendations are in detailed section
        assert report.count("### Recommendation") == 150
