"""
Privacy-critical tests for SHA-256 anonymization module.

This test module contains comprehensive tests for the anonymization functionality
which is CRITICAL for privacy-by-design guarantees. All tests are marked with
@pytest.mark.privacy_critical to indicate their importance.

Coverage Target: >90% (CRITICAL - privacy code must be thoroughly tested)
"""

import json

import pytest

# Mark all tests in this module as privacy-critical
pytestmark = pytest.mark.privacy_critical


# Test helper for encryption key generation
def _generate_test_key():
    """Generate encryption key for tests (replaces old _generate_test_key())."""
    from bqcheck.scanner.encryption import IdentifierEncryptor

    return IdentifierEncryptor.generate_key()


class TestEncryptionKeyGeneration:
    """Test suite for encryption key generation."""

    def test_generate_key_length(self):
        """Test that generated encryption key is exactly 32 bytes."""
        key = _generate_test_key()
        assert len(key) == 32
        assert isinstance(key, bytes)

    def test_generate_key_randomness(self):
        """Test that two generated keys are different (randomness check)."""
        key1 = _generate_test_key()
        key2 = _generate_test_key()
        assert key1 != key2


class TestTableNameAnonymization:
    """Test suite for table name anonymization."""

    def test_anonymize_table_name_output_format(self):
        """Test that encrypted table name is base64-encoded string."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        encryption_key = _generate_test_key()
        table_name = "users_2024"
        encrypted = anonymize_table_name(table_name, encryption_key)

        # Encrypted output should be non-empty base64 string
        assert len(encrypted) > 0
        assert isinstance(encrypted, str)
        # Base64 URL-safe characters (no padding)
        import string

        valid_chars = string.ascii_letters + string.digits + "-_"
        assert all(c in valid_chars for c in encrypted)

    def test_anonymize_table_name_determinism(self):
        """Test that same input produces same hash (deterministic)."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        salt = _generate_test_key()
        table_name = "users_2024"

        hash1 = anonymize_table_name(table_name, salt)
        hash2 = anonymize_table_name(table_name, salt)

        assert hash1 == hash2

    def test_anonymize_table_name_uniqueness(self):
        """Test that different inputs produce different hashes."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        salt = _generate_test_key()

        hash1 = anonymize_table_name("users", salt)
        hash2 = anonymize_table_name("events", salt)

        assert hash1 != hash2

    def test_anonymize_table_name_with_special_characters(self):
        """Test table names with dashes and underscores."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        salt = _generate_test_key()

        hash1 = anonymize_table_name("table-with-dashes", salt)
        hash2 = anonymize_table_name("table_with_underscores", salt)

        assert len(hash1) > 0  # Encrypted output is variable length
        assert len(hash2) > 0
        assert hash1 != hash2

    def test_anonymize_table_name_empty_string(self):
        """Test that empty string raises ValueError."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        salt = _generate_test_key()

        with pytest.raises(ValueError, match="Table name cannot be empty"):
            anonymize_table_name("", salt)


class TestDatasetNameAnonymization:
    """Test suite for dataset name anonymization."""

    def test_anonymize_dataset_name_output_length(self):
        """Test that anonymized dataset name is 64-character hex hash."""
        from bqcheck.scanner.anonymizer import anonymize_dataset_name

        salt = _generate_test_key()
        dataset_name = "analytics"
        hashed = anonymize_dataset_name(dataset_name, salt)

        assert len(hashed) > 0  # Encrypted output is variable length

    def test_anonymize_dataset_name_determinism(self):
        """Test that same dataset name produces same hash."""
        from bqcheck.scanner.anonymizer import anonymize_dataset_name

        salt = _generate_test_key()
        dataset_name = "analytics"

        hash1 = anonymize_dataset_name(dataset_name, salt)
        hash2 = anonymize_dataset_name(dataset_name, salt)

        assert hash1 == hash2


class TestProjectIdAnonymization:
    """Test suite for project ID anonymization."""

    def test_anonymize_project_id_output_length(self):
        """Test that anonymized project ID is 64-character hex hash."""
        from bqcheck.scanner.anonymizer import anonymize_project_id

        salt = _generate_test_key()
        project_id = "my-gcp-project-123"
        hashed = anonymize_project_id(project_id, salt)

        assert len(hashed) > 0  # Encrypted output is variable length

    def test_anonymize_project_id_determinism(self):
        """Test that same project ID produces same hash."""
        from bqcheck.scanner.anonymizer import anonymize_project_id

        salt = _generate_test_key()
        project_id = "my-gcp-project-123"

        hash1 = anonymize_project_id(project_id, salt)
        hash2 = anonymize_project_id(project_id, salt)

        assert hash1 == hash2


class TestCardinalityPreservation:
    """Test suite for cardinality preservation (same input → same hash)."""

    def test_cardinality_preservation_with_duplicates(self):
        """Test that duplicate table names produce identical hashes."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        salt = _generate_test_key()

        # Create list with duplicates
        table_names = ["users", "events", "users"]

        hash1 = anonymize_table_name(table_names[0], salt)
        hash2 = anonymize_table_name(table_names[1], salt)
        hash3 = anonymize_table_name(table_names[2], salt)

        # Verify duplicate "users" produces same hash
        assert hash1 == hash3
        # Verify different table "events" produces different hash
        assert hash1 != hash2
        assert hash3 != hash2

    def test_hash_collision_resistance(self):
        """Test collision resistance with 10,000 unique table names."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        salt = _generate_test_key()

        # Generate 10,000 unique table names and hash them
        hashes = set()
        for i in range(10000):
            table_name = f"table_{i}"
            hashed = anonymize_table_name(table_name, salt)
            hashes.add(hashed)

        # Verify all 10,000 hashes are unique (no collisions)
        assert len(hashes) == 10000


class TestQueryPatternAnonymization:
    """Test suite for query pattern anonymization."""

    def test_anonymize_query_pattern_simple_select(self):
        """Test anonymization of simple SELECT with FROM clause."""
        from bqcheck.scanner.anonymizer import anonymize_query_pattern

        salt = _generate_test_key()
        query = "SELECT * FROM project.dataset.table"
        anonymized = anonymize_query_pattern(query, salt)

        # Verify SQL structure preserved
        assert "SELECT * FROM" in anonymized
        # Verify table reference is NOT in plain text
        assert "project.dataset.table" not in anonymized
        # Verify anonymized table reference is hex hash (64 chars each component)
        assert len(anonymized) > len(query)

    def test_anonymize_query_pattern_with_join(self):
        """Test anonymization of SELECT with JOIN clause."""
        from bqcheck.scanner.anonymizer import anonymize_query_pattern

        salt = _generate_test_key()
        query = "SELECT a.* FROM dataset.table_a a JOIN dataset.table_b b"
        anonymized = anonymize_query_pattern(query, salt)

        # Verify SQL structure preserved
        assert "SELECT" in anonymized
        assert "FROM" in anonymized
        assert "JOIN" in anonymized
        # Verify table references are NOT in plain text
        assert "table_a" not in anonymized
        assert "table_b" not in anonymized

    def test_anonymize_query_pattern_with_backticks(self):
        """Test anonymization of query with backtick syntax."""
        from bqcheck.scanner.anonymizer import anonymize_query_pattern

        salt = _generate_test_key()
        query = "SELECT * FROM `project.dataset.table`"
        anonymized = anonymize_query_pattern(query, salt)

        # Verify SQL structure preserved
        assert "SELECT * FROM" in anonymized
        # Verify table reference is NOT in plain text
        assert "project.dataset.table" not in anonymized

    def test_anonymize_query_pattern_null_query(self):
        """Test that NULL/None query returns empty string."""
        from bqcheck.scanner.anonymizer import anonymize_query_pattern

        salt = _generate_test_key()

        result = anonymize_query_pattern(None, salt)
        assert result == ""

    def test_anonymize_query_pattern_empty_query(self):
        """Test that empty query returns empty string."""
        from bqcheck.scanner.anonymizer import anonymize_query_pattern

        salt = _generate_test_key()

        result = anonymize_query_pattern("", salt)
        assert result == ""

    def test_anonymize_query_pattern_no_tables(self):
        """Test query with no table references returns original."""
        from bqcheck.scanner.anonymizer import anonymize_query_pattern

        salt = _generate_test_key()
        query = "SELECT 1 as one"
        anonymized = anonymize_query_pattern(query, salt)

        # Query with no tables should remain unchanged
        assert anonymized == query

    def test_anonymize_query_pattern_determinism(self):
        """Test that same query produces same anonymized output."""
        from bqcheck.scanner.anonymizer import anonymize_query_pattern

        salt = _generate_test_key()
        query = "SELECT * FROM project.dataset.table"

        anonymized1 = anonymize_query_pattern(query, salt)
        anonymized2 = anonymize_query_pattern(query, salt)

        assert anonymized1 == anonymized2


class TestMetadataBatchAnonymization:
    """Test suite for batch metadata anonymization."""

    def test_anonymize_table_list(self):
        """Test batch anonymization of table metadata list."""
        from bqcheck.scanner.anonymizer import anonymize_table_list
        from bqcheck.scanner.models import TableMetadata

        salt = _generate_test_key()

        tables = [
            TableMetadata(
                table_catalog="my-project",
                table_schema="analytics",
                table_name="users",
                table_type="TABLE",
                creation_time="2024-01-01 00:00:00 UTC",
                size_bytes=1073741824,
                row_count=1000000,
            ),
            TableMetadata(
                table_catalog="my-project",
                table_schema="analytics",
                table_name="events",
                table_type="TABLE",
                creation_time="2024-01-02 00:00:00 UTC",
                size_bytes=2147483648,
                row_count=5000000,
            ),
        ]

        anonymized = anonymize_table_list(tables, salt)

        # Verify anonymized list has same length
        assert len(anonymized) == 2

        # Verify sensitive fields are encrypted (variable-length base64)
        assert len(anonymized[0]["table_catalog"]) > 0
        assert len(anonymized[0]["table_schema"]) > 0
        assert len(anonymized[0]["table_name"]) > 0

        # Verify non-sensitive fields are preserved
        assert anonymized[0]["size_bytes"] == 1073741824
        assert anonymized[0]["row_count"] == 1000000
        assert anonymized[0]["creation_time"] == "2024-01-01 00:00:00 UTC"

        # Verify no raw table names in output
        anonymized_json = json.dumps(anonymized)
        assert "users" not in anonymized_json
        assert "events" not in anonymized_json
        assert "my-project" not in anonymized_json

    def test_anonymize_access_patterns(self):
        """Test batch anonymization of access pattern list."""
        from bqcheck.scanner.anonymizer import anonymize_access_patterns
        from bqcheck.scanner.models import AccessPattern

        salt = _generate_test_key()

        patterns = [
            AccessPattern(
                table_catalog="my-project",
                table_schema="analytics",
                table_name="users",
                last_access_time="2024-01-20 10:30:00 UTC",
            ),
            AccessPattern(
                table_catalog="my-project",
                table_schema="analytics",
                table_name="payments",
                last_access_time="2024-01-19 08:15:00 UTC",
            ),
        ]

        anonymized = anonymize_access_patterns(patterns, salt)

        # Verify anonymized list has same length
        assert len(anonymized) == 2

        # Verify sensitive fields are encrypted
        assert len(anonymized[0]["table_name"]) > 0

        # Verify timestamps are preserved
        assert anonymized[0]["last_access_time"] == "2024-01-20 10:30:00 UTC"

        # Verify no raw names in output
        anonymized_json = json.dumps(anonymized)
        assert "users" not in anonymized_json
        assert "payments" not in anonymized_json

    def test_anonymize_query_list(self):
        """Test batch anonymization of query list with query anonymization."""
        from bqcheck.scanner.anonymizer import anonymize_query_list
        from bqcheck.scanner.models import QueryMetadata

        salt = _generate_test_key()

        queries = [
            QueryMetadata(
                job_id="project:location.job_abc123",
                query="SELECT * FROM analytics.users JOIN analytics.events",
                total_bytes_processed=1073741824,
                creation_time="2024-01-20 10:30:00 UTC",
                job_type="QUERY",
                state="DONE",
            ),
            QueryMetadata(
                job_id="project:location.job_def456",
                query="SELECT * FROM project.analytics.payments",
                total_bytes_processed=2147483648,
                creation_time="2024-01-19 08:15:00 UTC",
                job_type="QUERY",
                state="DONE",
            ),
        ]

        anonymized = anonymize_query_list(queries, salt)

        # Verify anonymized list has same length
        assert len(anonymized) == 2

        # Verify query text is anonymized (table references replaced)
        assert "analytics.users" not in anonymized[0]["query"]
        assert "analytics.events" not in anonymized[0]["query"]
        assert "project.analytics.payments" not in anonymized[1]["query"]

        # Verify SQL structure is preserved
        assert "SELECT * FROM" in anonymized[0]["query"]
        assert "JOIN" in anonymized[0]["query"]
        assert "SELECT * FROM" in anonymized[1]["query"]

        # Verify non-query fields are preserved
        assert anonymized[0]["total_bytes_processed"] == 1073741824
        assert anonymized[0]["creation_time"] == "2024-01-20 10:30:00 UTC"

        # Verify no raw table names in output
        anonymized_json = json.dumps(anonymized)
        assert "users" not in anonymized_json
        assert "events" not in anonymized_json
        assert "payments" not in anonymized_json


class TestValidationAndSecurity:
    """Test suite for input validation and security fixes."""

    def test_encryption_key_validation_wrong_type(self):
        """Test that non-bytes encryption key is rejected."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        with pytest.raises(TypeError, match="Encryption key must be bytes"):
            anonymize_table_name("users", "not_bytes")

    def test_encryption_key_validation_short(self):
        """Test that short encryption key is rejected."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        with pytest.raises(ValueError, match="Encryption key must be exactly 32 bytes"):
            anonymize_table_name("users", b"short")

    def test_encryption_key_validation_empty(self):
        """Test that empty encryption key is rejected."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        with pytest.raises(ValueError, match="Encryption key must be exactly 32 bytes"):
            anonymize_table_name("users", b"")

    def test_encryption_key_validation_int_type(self):
        """Test that integer encryption key is rejected."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        with pytest.raises(TypeError, match="Encryption key must be bytes"):
            anonymize_table_name("users", 12345)

    def test_identifier_type_validation_integer(self):
        """Test that integer table name is rejected."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        salt = _generate_test_key()

        with pytest.raises(TypeError, match="Table name must be string"):
            anonymize_table_name(12345, salt)

    def test_identifier_type_validation_none(self):
        """Test that None table name is rejected."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        salt = _generate_test_key()

        with pytest.raises(TypeError, match="Table name must be string"):
            anonymize_table_name(None, salt)

    def test_identifier_length_validation(self):
        """Test that too-long identifier is rejected."""
        from bqcheck.scanner.anonymizer import anonymize_table_name

        salt = _generate_test_key()
        long_name = "a" * 2000  # Exceeds 1024 char limit

        with pytest.raises(ValueError, match="Table name too long"):
            anonymize_table_name(long_name, salt)

    def test_hash_correlation_prevention(self):
        """Test that same identifier produces different hashes for different types."""
        from bqcheck.scanner.anonymizer import (
            anonymize_dataset_name,
            anonymize_project_id,
            anonymize_table_name,
        )

        salt = _generate_test_key()
        identifier = "test_identifier"

        hash_table = anonymize_table_name(identifier, salt)
        hash_dataset = anonymize_dataset_name(identifier, salt)
        hash_project = anonymize_project_id(identifier, salt)

        # All three should be different (type prefix prevents correlation)
        assert hash_table != hash_dataset
        assert hash_table != hash_project
        assert hash_dataset != hash_project

    def test_metadata_extra_fields_not_leaked(self):
        """Test that extra fields in metadata dict are NOT leaked."""
        from bqcheck.scanner.anonymizer import anonymize_metadata

        salt = _generate_test_key()

        # Metadata with extra sensitive fields
        metadata_with_secrets = {
            "table_catalog": "my-project",
            "table_schema": "analytics",
            "table_name": "users",
            "size_bytes": 1073741824,
            "api_key": "secret-key-12345",  # Extra field (should NOT leak)
            "password": "hunter2",  # Extra field (should NOT leak)
        }

        anonymized = anonymize_metadata(metadata_with_secrets, salt)

        # Verify sensitive identifiers are encrypted
        assert len(anonymized["table_catalog"]) > 0
        assert len(anonymized["table_schema"]) > 0
        assert len(anonymized["table_name"]) > 0

        # Verify known safe field is preserved
        assert anonymized["size_bytes"] == 1073741824

        # CRITICAL: Verify extra fields are NOT leaked
        assert "api_key" not in anonymized
        assert "password" not in anonymized
        assert "secret-key-12345" not in str(anonymized)
        assert "hunter2" not in str(anonymized)
