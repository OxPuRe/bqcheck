"""Unit tests for Markdown report generator (Story 5.2)."""

from datetime import datetime, timezone

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

    def test_executive_summary_includes_priority_breakdown(
        self, sample_audit_response
    ):
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
        assert "**Implementation Steps:**" in detailed


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
                categories_breakdown={"storage": 30, "queries": 40, "partitioning": 40, "clustering": 30, "temporal": 10},
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
