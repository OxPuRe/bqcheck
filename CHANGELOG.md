# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Query aggregation pipeline for server-side detection algorithms
  - Groups raw query metadata by anonymized pattern hash
  - Calculates executions per day and average bytes per execution
  - Enables repeated query detection and materialized view recommendations
- Filtered columns extraction for clustering recommendations (Story 4.4)
  - Regex-based WHERE clause parser to identify frequently filtered columns
  - Single-pass aggregation across all tables (O(n) vs O(n*m) complexity)
  - Enables server-side clustering column recommendations
- BigQuery `referenced_tables` metadata integration
  - Uses native BigQuery table resolution instead of regex parsing
  - More reliable handling of complex queries (subqueries, CTEs, temp tables)
  - Backwards compatible fallback to regex when metadata unavailable
- Privacy enhancements:
  - Cryptographic salt generation for all anonymization operations
  - Full anonymization of tables, queries, and access patterns before server transmission
  - SHA-256 hashing of table_id field (dataset.table format)
- Comprehensive test suites:
  - Query aggregation: 17 tests (100% pass rate)
  - Filtered columns: 24 tests (100% pass rate)
  - Referenced tables: 6 additional tests (100% pass rate)
- Support for BigQuery timezone offset format (`+00` suffix)
- Multi-project scanning support with `--query-project` flag
  - Enables scanning storage and query projects separately
  - Essential for separated architectures (e.g., *-dt-cur-0 storage + *-dt-prc-0 processing)
  - Dramatically improves query-based recommendation detection
  - Example: `bqaudit scan --project storage-proj --query-project query-proj`

### Changed
- Scan executor now properly anonymizes all metadata before sending to server
- Query metadata transformed from raw job records to aggregated pattern statistics
- Improved logging to show query pattern aggregation results

### Fixed
- Privacy issue: raw metadata was being sent to server without anonymization
- Data format mismatch between client and server for query detection algorithms
- Timestamp parsing now correctly handles BigQuery's `+00` timezone offset format (e.g., `2025-12-15 15:06:24.456+00`)

## [0.2.0] - 2026-02-02

### Added
- Two-tier token architecture (master keys + ephemeral tokens)
- Automatic token renewal after each successful scan
- Token pool balance tracking in credentials
- Mock mode for testing and CI/CD (BQAUDIT_REAL_MODE, BQAUDIT_REAL_SCAN)
- Comprehensive documentation in README (architecture, features, quickstart)
- License activation and status commands

### Changed
- Default mode switched to real scanning (mock mode must be explicitly enabled)
- Environment variables for controlling real vs mock behavior

## [0.1.0] - 2026-01-15

### Added
- Initial release with BigQuery metadata extraction
- CLI commands: scan, license (activate/status/revoke)
- Server API client with retry logic and timeout handling
- Markdown report generation
- Structured logging with multiple levels
- Rate limiting (10 requests/minute)
- Error handling for common scenarios (network, permissions, timeouts)
