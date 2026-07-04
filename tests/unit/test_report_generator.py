"""Unit tests for Markdown report generator (Story 5.2)."""

import re
from datetime import date, datetime, timezone

import pytest

from bqcheck.api.models import CheckResponse, CheckSummary, Recommendation
from bqcheck.report_generator import MarkdownReportGenerator


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
def sample_check_response(sample_recommendations):
    """Create sample CheckResponse for testing."""
    return CheckResponse(
        recommendations=sample_recommendations,
        summary=CheckSummary(
            total_recommendations=3,
            total_potential_savings_eur=250.0,
            high_priority_count=1,
            medium_priority_count=1,
            low_priority_count=1,
            categories_breakdown={"storage": 1, "partitioning": 1, "clustering": 1},
        ),
        check_id="test_check_123",
        new_ephemeral_token="eph_new_token",
    )


class TestReportHeader:
    """Test report header generation (Task 1.2)."""

    def test_header_includes_project_name(self, sample_check_response):
        """Test that header includes project name."""
        generator = MarkdownReportGenerator(
            sample_check_response, project_name="test-project"
        )

        header = generator.generate_header()

        assert "# BigQuery Sanity Check Report" in header
        assert "> Scope: `test-project`" in header

    def test_header_includes_check_date(self, sample_check_response):
        """Test that header includes check date."""
        generator = MarkdownReportGenerator(sample_check_response)

        header = generator.generate_header()

        assert "| Check Date |" in header

    def test_header_includes_timestamp(self, sample_check_response):
        """Test that header includes ISO timestamp."""
        generator = MarkdownReportGenerator(sample_check_response)

        header = generator.generate_header()

        assert "| Generated |" in header
        assert "T" in header  # ISO format has 'T' separator


class TestReportGeneration:
    """Test complete report generation."""

    def test_generate_report_returns_string(self, sample_check_response):
        """Test that generate_report returns a string."""
        generator = MarkdownReportGenerator(sample_check_response)

        report = generator.generate_report()

        assert isinstance(report, str)
        assert len(report) > 0

    def test_generate_report_includes_header(self, sample_check_response):
        """Test that report includes header."""
        generator = MarkdownReportGenerator(
            sample_check_response, project_name="my-project"
        )

        report = generator.generate_report()

        assert "# BigQuery Sanity Check Report" in report
        assert "> Scope: `my-project`" in report


class TestExecutiveSummary:
    """Test Executive Summary generation (Task 2)."""

    def test_executive_summary_includes_total_recommendations(
        self, sample_check_response
    ):
        """Test that Executive Summary includes total count."""
        generator = MarkdownReportGenerator(sample_check_response)

        summary = generator.generate_executive_summary()

        assert "| Recommendations | 3 |" in summary

    def test_executive_summary_includes_total_savings(self, sample_check_response):
        """Test that Executive Summary includes total potential savings."""
        generator = MarkdownReportGenerator(sample_check_response)

        summary = generator.generate_executive_summary()

        assert "| Estimated Savings | €250.00/month |" in summary

    def test_executive_summary_includes_priority_breakdown(self, sample_check_response):
        """Test that Executive Summary includes focus information."""
        generator = MarkdownReportGenerator(sample_check_response)

        summary = generator.generate_executive_summary()

        assert "Dominant Category | Storage Hygiene" in summary
        assert "### Savings Breakdown by Category" in summary

    def test_executive_summary_zero_recommendations(self):
        """Test Executive Summary with 0 recommendations."""
        empty_response = CheckResponse(
            recommendations=[],
            summary=CheckSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            check_id="test_check_empty",
            new_ephemeral_token="eph_token",
        )
        generator = MarkdownReportGenerator(empty_response)

        summary = generator.generate_executive_summary()

        assert "| Recommendations | 0 |" in summary
        assert "€0.00/month" in summary
        assert "No material optimization opportunities were detected" in summary


class TestDetailedRecommendations:
    """Test Detailed Recommendations section (Task 4)."""

    def test_detailed_recs_sorted_by_priority(self, sample_recommendations):
        """Test that recommendations are sorted by savings."""
        response = CheckResponse(
            recommendations=sample_recommendations,
            summary=CheckSummary(
                total_recommendations=3,
                total_potential_savings_eur=250.0,
                high_priority_count=1,
                medium_priority_count=1,
                low_priority_count=1,
                categories_breakdown={},
            ),
            check_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        detailed = generator.generate_detailed_recommendations()

        storage_pos = detailed.find("Storage Hygiene")
        partitioning_pos = detailed.find("Table Layout")
        clustering_pos = detailed.rfind("Table Layout")

        assert storage_pos < partitioning_pos < clustering_pos

    def test_detailed_recs_includes_all_fields(self, sample_recommendations):
        """Test that all recommendation fields are included."""
        response = CheckResponse(
            recommendations=sample_recommendations[:1],  # Just first one
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=150.0,
                high_priority_count=1,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            check_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        detailed = generator.generate_detailed_recommendations()

        assert "Category: Storage Hygiene" in detailed
        assert "Estimated Monthly Savings: €150.00" in detailed
        assert "##### Observation" in detailed
        assert "##### Recommended Change" in detailed

    def test_storage_recommendation_mentions_long_table_once_in_asset_block(self):
        """Long storage table names should not be repeated throughout the recommendation."""
        long_table = (
            "synthetic_data."
            "mobility_synthetic_gb_antrim_and_newtownabbey_ards_and_north_down_"
            "armagh_city_banbridge_and_craigavon_belfast_lisburn_and_castlereagh_"
            "newry_mourne_and_down"
        )
        response = CheckResponse(
            recommendations=[
                Recommendation(
                    type="storage",
                    priority="LOW",
                    title="Review idle 95GB table",
                    description=(
                        f"Table {long_table} (94.77 GB) is about 204 days old and no "
                        "query activity was observed for it in the scanned 90-day "
                        "workload window. The table has not appeared in the observed "
                        "90-day query history."
                    ),
                    savings_eur=2.13,
                    implementation_steps=[
                        f"Confirm with the data owner and downstream jobs that {long_table} is no longer required",
                        f"DROP TABLE {long_table}",
                    ],
                )
            ],
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=2.13,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=1,
                categories_breakdown={"storage": 1},
            ),
            check_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        detailed = generator.generate_detailed_recommendations()

        assert "Asset: `synthetic_data." in detailed
        assert detailed.count(long_table) <= 1
        assert "94.77 GB stored, about 204 days old" in detailed
        assert "archive or delete the table" in detailed

    def test_detailed_recs_include_confidence_signals_for_query_recommendation(self):
        """Report should inspire trust without exposing detector internals."""
        response = CheckResponse(
            recommendations=[
                Recommendation(
                    type="queries",
                    priority="HIGH",
                    title="Materialize repeated query (12.0/day)",
                    description=(
                        "Query pattern abcdef1234567890 executes 12.0 times/day "
                        "(36 executions over 14.0 days, on 9 distinct day(s)), "
                        "processing 1.50 TB per execution (54.00 TB total). "
                        "Last run: 2 days ago. Materialized view would eliminate "
                        "these repeated query costs."
                    ),
                    savings_eur=320.0,
                    implementation_steps=[
                        "Create materialized view from mobility/queries/reporting.sql"
                    ],
                )
            ],
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=320.0,
                high_priority_count=1,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={"queries": 1},
            ),
            check_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        detailed = generator.generate_detailed_recommendations()

        assert "##### Supporting Signals" in detailed
        assert (
            "This query pattern appears frequently enough to create repeat waste"
            in detailed
        )
        assert (
            "Each execution scans enough data for materialization to be worth a look"
            in detailed
        )
        assert (
            "The pattern repeats across multiple days, which suggests a stable workload"
            in detailed
        )
        assert "Most recent execution seen: 2 days ago" not in detailed
        assert "| Asset |" not in detailed
        assert "Query Source: `mobility/queries/reporting.sql`" in detailed

    def test_partition_pruning_recommendation_shows_asset_and_signals(self):
        """Partition-pruning recommendations should expose asset and evidence."""
        response = CheckResponse(
            recommendations=[
                Recommendation(
                    type="queries",
                    priority="HIGH",
                    title="Fix partition pruning on 5.27TB table",
                    description=(
                        "Table user.user_attribute (5.27 TB) is partitioned on month, "
                        "but queries still scan 88% of the table on average "
                        "(4.64 TB per query). This usually means date filters are "
                        "missing or not aligned with the partition column."
                    ),
                    savings_eur=3180.84,
                    implementation_steps=[
                        "Review queries hitting user.user_attribute and confirm they filter on month"
                    ],
                )
            ],
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=3180.84,
                high_priority_count=1,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={"queries": 1},
            ),
            check_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        detailed = generator.generate_detailed_recommendations()

        assert "Asset: `user.user_attribute`" in detailed
        assert "##### Supporting Signals" in detailed
        assert "Observed queries are still scanning a large share" in detailed
        assert "The partition field to verify first is `month`" in detailed

    def test_hot_view_recommendation_shows_asset_and_signals(self):
        """Hot-view recommendations should identify the affected logical view."""
        response = CheckResponse(
            recommendations=[
                Recommendation(
                    type="queries",
                    priority="HIGH",
                    title="Materialize hot logical view",
                    description=(
                        "Logical view device_associations_identifiers.ip_maid_mapping_input_vw "
                        "is queried repeatedly and drives about 3.87 TB scanned per "
                        "execution (340.68 TB observed in this scan window). "
                        "Recomputing the same view logic at read time is likely "
                        "creating avoidable query spend."
                    ),
                    savings_eur=477.25,
                    implementation_steps=[
                        "Review the definition of device_associations_identifiers.ip_maid_mapping_input_vw and identify whether it fits a materialized view or a scheduled precomputed table"
                    ],
                )
            ],
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=477.25,
                high_priority_count=1,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={"queries": 1},
            ),
            check_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        detailed = generator.generate_detailed_recommendations()

        assert (
            "Asset: `device_associations_identifiers.ip_maid_mapping_input_vw`"
            in detailed
        )
        assert (
            "Repeated reads are recomputing the same logical view definition"
            in detailed
        )
        assert "Each execution still scans about 3.87 TB" in detailed

    def test_detailed_recs_format_category_label(self, sample_recommendations):
        """Internal types should render as user-facing category labels."""
        response = CheckResponse(
            recommendations=sample_recommendations[:1],
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=150.0,
                high_priority_count=1,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            check_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        detailed = generator.generate_detailed_recommendations()

        assert "Category: Storage Hygiene" in detailed


class TestFileSaving:
    """Test file saving logic (Task 5)."""

    def test_save_report_creates_file(self, sample_check_response, tmp_path):
        """Test that save_report creates a file."""
        generator = MarkdownReportGenerator(sample_check_response)

        output_path = generator.save_report(output_dir=tmp_path)

        assert output_path.exists()
        assert output_path.is_file()

    def test_save_report_filename_format(self, sample_check_response, tmp_path):
        """Test that filename follows sanity-check-report-YYYY-MM-DD.md format."""
        generator = MarkdownReportGenerator(sample_check_response)

        output_path = generator.save_report(output_dir=tmp_path)

        # Should match pattern
        assert output_path.name.startswith("sanity-check-report-")
        assert output_path.name.endswith(".md")

    def test_save_report_contains_full_report(self, sample_check_response, tmp_path):
        """Test that saved file contains complete report."""
        generator = MarkdownReportGenerator(
            sample_check_response, project_name="test-project"
        )

        output_path = generator.save_report(output_dir=tmp_path)
        content = output_path.read_text()

        # Should contain all sections
        assert "# BigQuery Sanity Check Report" in content
        assert "> Scope: `test-project`" in content
        assert "## Executive Summary" in content
        assert "## Detailed Recommendations" in content

    def test_save_report_auto_suffix_when_file_exists(
        self, sample_check_response, tmp_path
    ):
        """Test that save_report adds suffix when file exists (non-interactive)."""

        generator = MarkdownReportGenerator(sample_check_response)
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
        self, sample_check_response, tmp_path
    ):
        """Test that force=True overwrites existing file without suffix."""

        generator = MarkdownReportGenerator(sample_check_response)
        output_file = tmp_path / "test-report.md"

        # Create existing file with different content
        output_file.write_text("old content")

        # Save with force=True - should overwrite
        path = generator.save_report(output_path=output_file, force=True)
        assert path == output_file
        assert "old content" not in path.read_text()
        assert "# BigQuery Sanity Check Report" in path.read_text()


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

        base_path = tmp_path / "sanity-check-report-2026-02-03.md"
        base_path.write_text("existing")

        available = MarkdownReportGenerator._find_available_path(base_path)

        assert available == tmp_path / "sanity-check-report-2026-02-03-1.md"
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
        text = (
            "-- Query logic taken from mobility/mobility/queries/compute_pickwell.sql"
        )
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
        lines = (
            ["CREATE TABLE foo AS ("] + [f"  SELECT col{i}," for i in range(20)] + [")"]
        )
        step = "\n".join(lines)

        truncated = MarkdownReportGenerator._truncate_sql_in_step(step, max_lines=10)

        assert "[SQL truncated - 12 more lines]" in truncated
        assert truncated.count("\n") < step.count("\n")

    def test_truncate_sql_in_step_with_file_reference(self):
        """Test that file reference is extracted and shown in truncation."""
        lines = ["CREATE VIEW AS -- Query from mobility/queries/test.sql"] + [
            f"SELECT col{i}," for i in range(20)
        ]
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
        empty_response = CheckResponse(
            recommendations=[],
            summary=CheckSummary(
                total_recommendations=0,
                total_potential_savings_eur=0.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=0,
                categories_breakdown={},
            ),
            check_id="test",
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

        response = CheckResponse(
            recommendations=recommendations,
            summary=CheckSummary(
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
            check_id="test",
            new_ephemeral_token="token",
        )
        generator = MarkdownReportGenerator(response)

        report = generator.generate_report()

        # Verify report generates successfully
        assert "# BigQuery Sanity Check Report" in report
        assert "| Recommendations | 150 |" in report
        assert "## Detailed Recommendations" in report

        # Verify all 150 recommendations are in detailed section
        assert (
            len(
                re.findall(
                    r"^### Recommendation \d+ - .+$",
                    report,
                    flags=re.MULTILINE,
                )
            )
            == 150
        )


class TestJobIdHandling:
    """Test suite for BigQuery job ID handling in recommendations."""

    def test_job_id_decryption_failure_handled_gracefully(self):
        """Test that corrupted/invalid encrypted job_id doesn't break report generation."""
        from bqcheck.scanner.encryption import IdentifierEncryptor

        # Create a recommendation with an encrypted job_id in implementation steps
        # Use a corrupted/invalid encrypted string to trigger decryption failure
        rec = Recommendation(
            type="queries",
            priority="MEDIUM",
            title="Test query recommendation",
            savings_eur=100.0,
            description="Test description",
            implementation_steps=[
                "Review query pattern abc123",
                "Find query in BigQuery Console using job ID: CORRUPTED_INVALID_BASE64_STRING",
                "Create materialized view",
            ],
        )

        response = CheckResponse(
            project_id="test-project",
            check_date=date.today(),
            generated_at=datetime.now(timezone.utc),
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=100.0,
                high_priority_count=0,
                medium_priority_count=1,
                low_priority_count=0,
                category_breakdown={"queries": {"count": 1, "savings": 100.0}},
            ),
            recommendations=[rec],
            check_id="test",
            new_ephemeral_token="token",
        )

        # Create generator with encryption key
        encryption_key = IdentifierEncryptor.generate_key()
        generator = MarkdownReportGenerator(response, encryption_key=encryption_key)

        # Generate report - should not raise exception despite invalid job_id
        report = generator.generate_report()

        # Verify report was generated successfully
        assert "# BigQuery Sanity Check Report" in report
        assert "Test query recommendation" in report
        # Job ID link should be skipped (not included) due to decryption failure
        assert "CORRUPTED_INVALID_BASE64_STRING" not in report


class TestTableNameDecryption:
    """Test suite for encrypted table name decryption in reports."""

    def test_double_format_decryption(self):
        """Test decryption of dataset.table format (existing functionality)."""
        from bqcheck.scanner.encryption import IdentifierEncryptor

        encryption_key = IdentifierEncryptor.generate_key()
        encryptor = IdentifierEncryptor(encryption_key)

        # Encrypt dataset and table names
        encrypted_dataset = encryptor.encrypt_with_nonce("my_dataset", "dataset")
        encrypted_table = encryptor.encrypt_with_nonce("my_table", "table")

        # Create recommendation with encrypted dataset.table reference
        query_text = f"SELECT * FROM {encrypted_dataset}.{encrypted_table} WHERE date > '2024-01-01'"
        rec = Recommendation(
            type="queries",
            priority="LOW",
            title="Test query",
            savings_eur=50.0,
            description=f"Query: {query_text}",
            implementation_steps=["Step 1"],
        )

        response = CheckResponse(
            project_id="test-project",
            check_date=date.today(),
            generated_at=datetime.now(timezone.utc),
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=50.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=1,
                category_breakdown={"queries": {"count": 1, "savings": 50.0}},
            ),
            recommendations=[rec],
            check_id="test",
            new_ephemeral_token="token",
        )

        generator = MarkdownReportGenerator(response, encryption_key=encryption_key)
        report = generator.generate_report()

        # Verify decrypted table reference appears in report
        assert "my_dataset.my_table" in report
        # Verify encrypted reference does not appear
        assert encrypted_dataset not in report
        assert encrypted_table not in report

    def test_triple_format_decryption(self):
        """Test decryption of project.dataset.table format (new functionality)."""
        from bqcheck.scanner.encryption import IdentifierEncryptor

        encryption_key = IdentifierEncryptor.generate_key()
        encryptor = IdentifierEncryptor(encryption_key)

        # Encrypt project, dataset, and table names
        encrypted_project = encryptor.encrypt_with_nonce("my-project-123", "project")
        encrypted_dataset = encryptor.encrypt_with_nonce("analytics", "dataset")
        table_name = "events"  # Table names are not encrypted

        # Create recommendation with encrypted project.dataset.table reference
        query_text = f"SELECT * FROM {encrypted_project}.{encrypted_dataset}.{table_name} WHERE timestamp > CURRENT_TIMESTAMP()"
        rec = Recommendation(
            type="queries",
            priority="LOW",
            title="Materialize repeated query",
            savings_eur=100.0,
            description=f"Query pattern accesses: {query_text}",
            implementation_steps=["Create materialized view"],
        )

        response = CheckResponse(
            project_id="test-project",
            check_date=date.today(),
            generated_at=datetime.now(timezone.utc),
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=100.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=1,
                category_breakdown={"queries": {"count": 1, "savings": 100.0}},
            ),
            recommendations=[rec],
            check_id="test",
            new_ephemeral_token="token",
        )

        generator = MarkdownReportGenerator(response, encryption_key=encryption_key)
        report = generator.generate_report()

        # Verify decrypted full table reference appears in report
        assert "my-project-123.analytics.events" in report
        # Verify encrypted references do not appear
        assert encrypted_project not in report
        assert encrypted_dataset not in report

    def test_mixed_format_decryption(self):
        """Test that both double and triple format decryption work together."""
        from bqcheck.scanner.encryption import IdentifierEncryptor

        encryption_key = IdentifierEncryptor.generate_key()
        encryptor = IdentifierEncryptor(encryption_key)

        # Encrypt identifiers
        enc_project = encryptor.encrypt_with_nonce("prod-project", "project")
        enc_dataset1 = encryptor.encrypt_with_nonce("dataset_one", "dataset")
        enc_dataset2 = encryptor.encrypt_with_nonce("dataset_two", "dataset")
        enc_table = encryptor.encrypt_with_nonce("table_a", "table")

        # Create recommendation with both formats
        description = (
            f"Query joins {enc_project}.{enc_dataset1}.events "
            f"with {enc_dataset2}.{enc_table}"
        )
        rec = Recommendation(
            type="queries",
            priority="MEDIUM",
            title="Complex join query",
            savings_eur=200.0,
            description=description,
            implementation_steps=["Optimize join"],
        )

        response = CheckResponse(
            project_id="test-project",
            check_date=date.today(),
            generated_at=datetime.now(timezone.utc),
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=200.0,
                high_priority_count=0,
                medium_priority_count=1,
                low_priority_count=0,
                category_breakdown={"queries": {"count": 1, "savings": 200.0}},
            ),
            recommendations=[rec],
            check_id="test",
            new_ephemeral_token="token",
        )

        generator = MarkdownReportGenerator(response, encryption_key=encryption_key)
        report = generator.generate_report()

        # Verify both formats are decrypted
        assert "prod-project.dataset_one.events" in report
        assert "dataset_two.table_a" in report
        # Verify encrypted strings don't appear
        assert enc_project not in report
        assert enc_dataset1 not in report
        assert enc_dataset2 not in report

    def test_decryption_failure_preserves_original_text(self):
        """Test that decryption failures don't corrupt the report."""
        from bqcheck.scanner.encryption import IdentifierEncryptor

        encryption_key = IdentifierEncryptor.generate_key()

        # Use invalid encrypted-looking strings that will fail decryption
        fake_encrypted_project = "INVALID_BASE64_PROJECT_STRING_XXXXX"
        fake_encrypted_dataset = "INVALID_BASE64_DATASET_STRING_YYYYY"

        description = (
            f"Query uses {fake_encrypted_project}.{fake_encrypted_dataset}.table_name"
        )
        rec = Recommendation(
            type="queries",
            priority="LOW",
            title="Test recommendation",
            savings_eur=50.0,
            description=description,
            implementation_steps=["Step 1"],
        )

        response = CheckResponse(
            project_id="test-project",
            check_date=date.today(),
            generated_at=datetime.now(timezone.utc),
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=50.0,
                high_priority_count=0,
                medium_priority_count=0,
                low_priority_count=1,
                category_breakdown={"queries": {"count": 1, "savings": 50.0}},
            ),
            recommendations=[rec],
            check_id="test",
            new_ephemeral_token="token",
        )

        generator = MarkdownReportGenerator(response, encryption_key=encryption_key)
        report = generator.generate_report()

        # Verify report generation succeeds
        assert "# BigQuery Sanity Check Report" in report
        # Original text should be preserved when decryption fails
        assert (
            "INVALID_BASE64_PROJECT_STRING_XXXXX.INVALID_BASE64_DATASET_STRING_YYYYY.table_name"
            in report
        )

    def test_standalone_identifier_decryption(self):
        """Test decryption of standalone encrypted identifiers in description text."""
        from bqcheck.scanner.encryption import IdentifierEncryptor

        encryption_key = IdentifierEncryptor.generate_key()
        encryptor = IdentifierEncryptor(encryption_key)

        # Encrypt table and dataset names
        encrypted_table = encryptor.encrypt_with_nonce("orders_2024", "table")
        encrypted_dataset = encryptor.encrypt_with_nonce("sales_data", "dataset")

        # Create recommendation with standalone encrypted identifiers in description
        # These appear as standalone words, not in dotted format
        description = f"Table {encrypted_table} in dataset {encrypted_dataset} has not been accessed recently."
        rec = Recommendation(
            type="storage",
            priority="MEDIUM",
            title="Remove unused table",
            savings_eur=75.0,
            description=description,
            implementation_steps=["Verify table is unused", "Drop table"],
        )

        response = CheckResponse(
            project_id="test-project",
            check_date=date.today(),
            generated_at=datetime.now(timezone.utc),
            summary=CheckSummary(
                total_recommendations=1,
                total_potential_savings_eur=75.0,
                high_priority_count=0,
                medium_priority_count=1,
                low_priority_count=0,
                category_breakdown={"storage": {"count": 1, "savings": 75.0}},
            ),
            recommendations=[rec],
            check_id="test",
            new_ephemeral_token="token",
        )

        generator = MarkdownReportGenerator(response, encryption_key=encryption_key)
        report = generator.generate_report()

        # Verify standalone identifiers are decrypted in description
        assert "orders_2024" in report
        assert "sales_data" in report
        # Verify encrypted strings don't appear
        assert encrypted_table not in report
        assert encrypted_dataset not in report
