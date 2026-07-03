"""
Client-side AES encryption for BigQuery metadata anonymization.

This module provides PRIVACY-CRITICAL functions for anonymizing sensitive
identifiers (table names, dataset names, queries) using AES-256 encryption.

Privacy-by-Design Guarantees:
- All encryption occurs client-side before transmission
- AES-256 with deterministic nonces for grouping/deduplication
- Client-side decryption enables human-readable reports
- No raw identifiers leave the user's environment
- Server operates on encrypted data only

Coverage Target: >90% (CRITICAL - privacy code must be thoroughly tested)
"""

import re
from typing import Any, Dict, List, Optional

from bqcheck.scanner.encryption import IdentifierEncryptor
from bqcheck.scanner.models import AccessPattern, QueryMetadata, TableMetadata

# Public API
__all__ = [
    "generate_salt",
    "anonymize_table_name",
    "anonymize_dataset_name",
    "anonymize_project_id",
    "anonymize_query_pattern",
    "anonymize_metadata",
    "anonymize_table_list",
    "anonymize_query_list",
    "anonymize_access_patterns",
]

# Maximum identifier lengths (BigQuery limits)
MAX_TABLE_NAME_LENGTH = 1024
MAX_DATASET_NAME_LENGTH = 1024
MAX_PROJECT_ID_LENGTH = 1024


def _validate_encryption_key(encryption_key: bytes) -> None:
    """
    Validate encryption key format and length.

    PRIVACY-CRITICAL: Ensures encryption key is valid for AES-256 (32 bytes).
    Invalid keys compromise anonymization security.

    Args:
        encryption_key: Encryption key to validate

    Raises:
        TypeError: If encryption_key is not bytes
        ValueError: If encryption_key is not exactly 32 bytes
    """
    if not isinstance(encryption_key, bytes):
        raise TypeError(
            f"Encryption key must be bytes, got {type(encryption_key).__name__}"
        )

    if len(encryption_key) != 32:
        raise ValueError(
            f"Encryption key must be exactly 32 bytes (got {len(encryption_key)}). "
            "Load from credentials or use IdentifierEncryptor.generate_key()."
        )


def _validate_identifier(
    value: Any, name: str, max_length: int = MAX_TABLE_NAME_LENGTH
) -> None:
    """
    Validate identifier type and length.

    Args:
        value: Identifier value to validate
        name: Name of identifier field (for error messages)
        max_length: Maximum allowed length (default: 1024)

    Raises:
        TypeError: If value is not a string
        ValueError: If value is empty or too long
    """
    if not isinstance(value, str):
        raise TypeError(f"{name} must be string, got {type(value).__name__}")

    if not value:
        raise ValueError(f"{name} cannot be empty")

    if len(value) > max_length:
        raise ValueError(f"{name} too long: {len(value)} characters (max {max_length})")


def generate_salt() -> str:
    """
    Deprecated: Generate encryption key (backward compatibility stub).

    This function is deprecated and exists only for backward compatibility.
    Use encryption keys from credentials instead.

    The encryption key should be loaded from ~/.bqcheck/credentials.json
    (encryption_key field) rather than generated per-scan.

    Returns:
        Empty string (placeholder for backward compatibility)

    Privacy Note:
        Encryption keys are stored in credentials and persisted across scans,
        allowing client-side decryption of identifiers in reports.
    """
    # Deprecated: encryption keys come from credentials now
    # Return empty string for backward compatibility
    return ""


def anonymize_table_name(name: str, encryption_key: bytes) -> str:
    """
    Anonymize table name using AES-256 encryption.

    PRIVACY-CRITICAL: This function encrypts table names to prevent raw data
    identifiers from leaving the user's environment. The encryption is deterministic
    (same input + same key → same ciphertext) to preserve cardinality within scans.

    Args:
        name: Raw table name (e.g., "users_2024", "events", "payments")
        encryption_key: 32-byte AES-256 encryption key from credentials

    Returns:
        Base64-encoded ciphertext (URL-safe, deterministic)

    Raises:
        TypeError: If name is not string or encryption_key is not bytes
        ValueError: If table name is empty, too long, or encryption_key is invalid

    Example:
        >>> from bqcheck.scanner.encryption import IdentifierEncryptor
        >>> key = IdentifierEncryptor.generate_key()
        >>> enc1 = anonymize_table_name("users", key)
        >>> enc2 = anonymize_table_name("users", key)
        >>> enc1 == enc2  # Deterministic
        True

    Privacy Note:
        AES-256 with deterministic nonces allows server-side grouping while
        enabling client-side decryption for human-readable reports.
        Context "table" prevents correlation with dataset/project encryption.
    """
    _validate_identifier(name, "Table name", MAX_TABLE_NAME_LENGTH)
    _validate_encryption_key(encryption_key)

    encryptor = IdentifierEncryptor(encryption_key)
    return encryptor.encrypt_with_nonce(name, context="table")


def anonymize_dataset_name(name: str, encryption_key: bytes) -> str:
    """
    Anonymize dataset name using AES-256 encryption.

    PRIVACY-CRITICAL: This function encrypts dataset names using the same
    AES-256 pattern as table names. Dataset and table anonymization use
    different contexts to prevent correlation.

    Args:
        name: Raw dataset name (e.g., "analytics", "production", "staging")
        encryption_key: 32-byte AES-256 encryption key from credentials

    Returns:
        Base64-encoded ciphertext (URL-safe, deterministic)

    Raises:
        TypeError: If name is not string or encryption_key is not bytes
        ValueError: If dataset name is empty, too long, or encryption_key is invalid

    Example:
        >>> from bqcheck.scanner.encryption import IdentifierEncryptor
        >>> key = IdentifierEncryptor.generate_key()
        >>> enc1 = anonymize_dataset_name("analytics", key)
        >>> len(enc1) > 0
        True

    Privacy Note:
        Dataset names are treated with the same privacy guarantees as
        table names. All identifiers are encrypted client-side.
        Context "dataset" prevents correlation with table/project encryption.
    """
    _validate_identifier(name, "Dataset name", MAX_DATASET_NAME_LENGTH)
    _validate_encryption_key(encryption_key)

    encryptor = IdentifierEncryptor(encryption_key)
    return encryptor.encrypt_with_nonce(name, context="dataset")


def anonymize_project_id(project_id: str, encryption_key: bytes) -> str:
    """
    Anonymize GCP project ID using AES-256 encryption.

    PRIVACY-CRITICAL: This function encrypts project IDs to prevent exposing
    GCP project information. Project IDs can reveal organizational structure
    and naming conventions, so they are anonymized using the same AES-256
    pattern as table/dataset names.

    Args:
        project_id: Raw GCP project ID (e.g., "my-prod-project-123")
        encryption_key: 32-byte AES-256 encryption key from credentials

    Returns:
        Base64-encoded ciphertext (URL-safe, deterministic)

    Raises:
        TypeError: If project_id is not string or encryption_key is not bytes
        ValueError: If project ID is empty, too long, or encryption_key is invalid

    Example:
        >>> from bqcheck.scanner.encryption import IdentifierEncryptor
        >>> key = IdentifierEncryptor.generate_key()
        >>> enc1 = anonymize_project_id("echo-analytics-prod", key)
        >>> len(enc1) > 0
        True

    Privacy Note:
        Project IDs are particularly sensitive as they can reveal
        organizational structure. Always encrypt before transmission.
        Context "project" prevents correlation with table/dataset encryption.
    """
    _validate_identifier(project_id, "Project ID", MAX_PROJECT_ID_LENGTH)
    _validate_encryption_key(encryption_key)

    encryptor = IdentifierEncryptor(encryption_key)
    return encryptor.encrypt_with_nonce(project_id, context="project")


def _extract_table_references(query: str) -> List[str]:
    """
    Extract table references from SQL query using regex.

    Identifies table references in FROM and JOIN clauses, handling various
    formats including backtick syntax and multi-part table names.

    Patterns matched:
    - FROM project.dataset.table
    - JOIN dataset.table
    - FROM `project.dataset.table`

    Args:
        query: SQL query string

    Returns:
        List of table references (e.g., ["project.dataset.table", "dataset.table"])

    Example:
        >>> query = "SELECT * FROM project.analytics.users JOIN analytics.events"
        >>> refs = _extract_table_references(query)
        >>> len(refs)
        2

    Privacy Note:
        This is a helper function for query pattern anonymization.
        Table references are extracted for hashing.
    """
    # Regex pattern for table references in FROM/JOIN clauses
    # Matches: FROM/JOIN + optional whitespace + backtick + table ref
    # Table ref format: identifier.identifier[.identifier] (2 or 3 parts)
    # Use bounded quantifiers to prevent ReDoS attacks
    pattern = (
        r"(?:FROM|JOIN)"  # Keyword
        r"\s{0,10}"  # Max 10 spaces (prevents ReDoS)
        r"`?"  # Optional backtick
        r"("  # Capture group
        r"[a-zA-Z0-9_-]{1,100}"  # First identifier (max 100 chars)
        r"\."  # Dot separator
        r"[a-zA-Z0-9_-]{1,100}"  # Second identifier
        r"(?:"  # Optional third identifier
        r"\."  # Dot separator
        r"[a-zA-Z0-9_-]{1,100}"  # Third identifier
        r")?"
        r")"
        r"`?"  # Optional backtick
    )

    matches = re.findall(pattern, query, re.IGNORECASE)
    return matches


def _replace_table_reference(query: str, original: str, hashed: str) -> str:
    """
    Replace table reference with hashed version in query.

    Preserves SQL structure and syntax while replacing table identifiers.
    Handles backtick syntax and maintains query formatting.

    Args:
        query: SQL query string
        original: Original table reference (e.g., "project.dataset.table")
        hashed: Hashed table reference (e.g., "hash1.hash2.hash3")

    Returns:
        Modified query string with replaced reference

    Example:
        >>> query = "SELECT * FROM project.dataset.table"
        >>> modified = _replace_table_reference(
        ...     query, "project.dataset.table", "aaa.bbb.ccc"
        ... )
        >>> "aaa.bbb.ccc" in modified
        True

    Privacy Note:
        This is a helper function for query pattern anonymization.
        Replaces raw table references with anonymized hashes.
    """
    # Replace both backtick and non-backtick versions
    query = query.replace(f"`{original}`", hashed)
    query = query.replace(original, hashed)
    return query


def anonymize_query_pattern(query: Optional[str], encryption_key: bytes) -> str:
    """
    Anonymize table references in SQL query pattern using AES encryption.

    PRIVACY-CRITICAL: This function extracts table references from SQL queries
    and replaces them with encrypted versions. Preserves SQL structure
    while anonymizing all table identifiers.

    Args:
        query: SQL query string (can be None or empty)
        encryption_key: 32-byte AES-256 encryption key from credentials

    Returns:
        Anonymized query string with encrypted table references

    Example:
        >>> from bqcheck.scanner.encryption import IdentifierEncryptor
        >>> key = IdentifierEncryptor.generate_key()
        >>> query = "SELECT * FROM project.dataset.table"
        >>> anonymized = anonymize_query_pattern(query, key)
        >>> "project.dataset.table" in anonymized
        False
        >>> "SELECT * FROM" in anonymized
        True

    Privacy Note:
        Query text contains sensitive table references that reveal data
        structure. All table identifiers are encrypted before transmission.
        SQL structure (SELECT, WHERE, etc.) is preserved for pattern analysis.
    """
    # Handle NULL/None/empty queries
    if not query:
        return ""

    # Extract all table references
    table_refs = _extract_table_references(query)

    # If no tables found, return original query
    if not table_refs:
        return query

    # Encrypt each table reference
    anonymized_query = query
    for table_ref in table_refs:
        # Split table reference into components (project.dataset.table or dataset.table)
        parts = table_ref.split(".")

        if len(parts) == 3:
            # Full reference: project.dataset.table
            project_encrypted = anonymize_project_id(parts[0], encryption_key)
            dataset_encrypted = anonymize_dataset_name(parts[1], encryption_key)
            table_encrypted = anonymize_table_name(parts[2], encryption_key)
            encrypted_ref = f"{project_encrypted}.{dataset_encrypted}.{table_encrypted}"
        elif len(parts) == 2:
            # Short reference: dataset.table
            dataset_encrypted = anonymize_dataset_name(parts[0], encryption_key)
            table_encrypted = anonymize_table_name(parts[1], encryption_key)
            encrypted_ref = f"{dataset_encrypted}.{table_encrypted}"
        else:
            # Single identifier (shouldn't happen with regex pattern, but handle it)
            table_encrypted = anonymize_table_name(parts[0], encryption_key)
            encrypted_ref = table_encrypted

        # Replace original reference with encrypted version
        anonymized_query = _replace_table_reference(
            anonymized_query, table_ref, encrypted_ref
        )

    return anonymized_query


def anonymize_metadata(
    metadata_dict: Dict[str, Any], encryption_key: bytes
) -> Dict[str, Any]:
    """
    Anonymize sensitive fields in metadata dictionary using AES encryption.

    This function encrypts table_catalog (project ID), table_schema
    (dataset name), and table_name fields while preserving all other
    metadata fields (size_bytes, row_count, creation_time, etc.).

    Args:
        metadata_dict: Metadata dictionary with sensitive fields
        encryption_key: 32-byte AES-256 encryption key from credentials

    Returns:
        New dictionary with encrypted sensitive fields

    Example:
        >>> from bqcheck.scanner.encryption import IdentifierEncryptor
        >>> key = IdentifierEncryptor.generate_key()
        >>> metadata = {
        ...     "table_catalog": "my-project",
        ...     "table_schema": "analytics",
        ...     "table_name": "users",
        ...     "size_bytes": 1073741824,
        ...     "row_count": 1000000
        ... }
        >>> anonymized = anonymize_metadata(metadata, key)
        >>> len(anonymized["table_catalog"]) > 0
        True
        >>> anonymized["size_bytes"]  # Non-sensitive fields preserved
        1073741824

    Privacy Note:
        Only sensitive identifier fields are encrypted. Metadata values
        (sizes, counts, timestamps) are preserved as-is.

        SECURITY: Whitelists known safe fields to prevent leaking extra
        sensitive data that might be in the input dictionary.
    """
    # Whitelist known fields to prevent leaking extra sensitive data
    # Known safe fields from TableMetadata, QueryMetadata, AccessPattern
    known_safe_fields = {
        # TableMetadata non-sensitive fields
        "table_type",
        "creation_time",
        "size_bytes",
        "row_count",
        "partition_expiration_days",
        "clustering_fields",
        "time_partitioning_type",
        "time_partitioning_field",
        # QueryMetadata non-sensitive fields
        "job_id",
        "total_bytes_processed",
        "user_email",
        "job_type",
        "state",
        # AccessPattern non-sensitive fields
        "last_modified_time",
        # Merged/enriched table fields (from merge_table_metadata)
        "table_id",  # Will be anonymized since it contains table_catalog/schema/name
        "schema",
        "query_stats",
        "filtered_columns",  # Sub-field of query_stats (column filtering patterns)
        # Aggregated query fields (from aggregate_query_metadata)
        "query_hash",
        "query_text",
        "executions_per_day",
        "bytes_per_execution",
        "has_materialized_view",
        # Derived sharded-table signals
        "is_date_sharded",
        "shard_group_id",
        "shard_group_table_count",
        "shard_group_total_size_bytes",
        "shard_group_query_stats",
    }

    anonymized: Dict[str, Any] = {}

    # Encrypt sensitive identifier fields if present
    if "table_catalog" in metadata_dict:
        anonymized["table_catalog"] = anonymize_project_id(
            metadata_dict["table_catalog"], encryption_key
        )

    if "table_schema" in metadata_dict:
        anonymized["table_schema"] = anonymize_dataset_name(
            metadata_dict["table_schema"], encryption_key
        )

    if "table_name" in metadata_dict:
        anonymized["table_name"] = anonymize_table_name(
            metadata_dict["table_name"], encryption_key
        )

    # Encrypt table_id field (format: "dataset.table") if present
    if "table_id" in metadata_dict:
        table_id = metadata_dict["table_id"]
        if table_id and "." in table_id:
            # Split "dataset.table" and encrypt each part
            parts = table_id.split(".", 1)  # Split on first dot only
            dataset_encrypted = anonymize_dataset_name(parts[0], encryption_key)
            table_encrypted = anonymize_table_name(parts[1], encryption_key)
            anonymized["table_id"] = f"{dataset_encrypted}.{table_encrypted}"
        else:
            # If table_id doesn't have expected format, keep as-is (shouldn't happen)
            anonymized["table_id"] = table_id

    # Copy known safe (non-sensitive) fields
    for field, value in metadata_dict.items():
        if (
            field in known_safe_fields and field != "table_id"
        ):  # Skip table_id (handled above)
            anonymized[field] = value

    return anonymized


def merge_table_metadata(
    tables: List[TableMetadata],
    access_patterns: List[AccessPattern],
    queries: List[QueryMetadata],
    schemas: Dict[str, List[Dict[str, str]]],
) -> List[Dict[str, Any]]:
    """
    Merge tables, access patterns, queries, and schemas into server format.

    Creates enriched table metadata with:
    - table_id: "dataset.table" format
    - last_modified_time: from access_patterns
    - schema: column definitions
    - query_stats: aggregated query statistics (bytes, count, filtered_columns)

    Args:
        tables: List of TableMetadata
        access_patterns: List of AccessPattern (for last_modified_time)
        queries: List of QueryMetadata (for query_stats)
        schemas: Dict mapping "dataset.table" to column list

    Returns:
        List of enriched table dictionaries ready for anonymization
    """
    import hashlib
    import re

    from bqcheck.scanner.aggregator import (
        _calculate_days_in_period,
        _calculate_distinct_days,
    )
    from bqcheck.scanner.query_analyzer import aggregate_filtered_columns_all_tables

    # Build lookup maps
    access_map = {}
    for pattern in access_patterns:
        key = f"{pattern.table_schema}.{pattern.table_name}"
        access_map[key] = pattern.last_modified_time

    # Convert queries to list of dicts for query_analyzer
    query_dicts = [q.model_dump() for q in queries]

    # Detect daily sharded table families locally so the server can reason
    # about them without ever receiving raw table prefixes.
    shard_group_candidates: Dict[str, Dict[str, Any]] = {}
    table_to_shard_group: Dict[str, str] = {}
    for table in tables:
        table_match = re.match(r"^(.+)_(\d{8})$", table.table_name)
        if not table_match:
            continue

        shard_prefix = table_match.group(1)
        group_key = f"{table.table_schema}.{shard_prefix}"
        group_id = hashlib.sha256(group_key.encode("utf-8")).hexdigest()

        if group_id not in shard_group_candidates:
            shard_group_candidates[group_id] = {
                "group_id": group_id,
                "table_count": 0,
                "total_size_bytes": 0,
                "tables": set(),
            }

        shard_group_candidates[group_id]["table_count"] += 1
        shard_group_candidates[group_id]["total_size_bytes"] += table.size_bytes or 0
        shard_group_candidates[group_id]["tables"].add(
            f"{table.table_schema}.{table.table_name}"
        )

    shard_groups = {
        group_id: group_info
        for group_id, group_info in shard_group_candidates.items()
        if group_info["table_count"] >= 7
    }
    for group_id, group_info in shard_groups.items():
        for table_key in group_info["tables"]:
            table_to_shard_group[table_key] = group_id

    # Aggregate queries by table
    query_stats_map: Dict[str, Dict[str, Any]] = {}
    query_timestamps_map: Dict[str, List[str]] = {}
    shard_query_stats_map: Dict[str, Dict[str, Any]] = {}
    shard_timestamps_map: Dict[str, List[str]] = {}
    for query in queries:
        # Extract table references from query (simplified - match dataset.table patterns)
        table_refs = re.findall(r"`?([a-z0-9_-]+)\.([a-z0-9_]+)`?", query.query.lower())
        referenced_shard_groups = set()
        for dataset, table in table_refs:
            key = f"{dataset}.{table}"
            if key not in query_stats_map:
                query_stats_map[key] = {
                    "total_bytes_processed": 0,
                    "query_count": 0,
                    "filtered_columns": {},
                }
                query_timestamps_map[key] = []
            query_stats_map[key]["total_bytes_processed"] += query.total_bytes_processed
            query_stats_map[key]["query_count"] += 1
            query_timestamps_map[key].append(query.creation_time)

            shard_group_id = table_to_shard_group.get(key)
            if shard_group_id:
                referenced_shard_groups.add(shard_group_id)

        for shard_group_id in referenced_shard_groups:
            if shard_group_id not in shard_query_stats_map:
                shard_query_stats_map[shard_group_id] = {
                    "total_bytes_processed": 0,
                    "query_count": 0,
                }
                shard_timestamps_map[shard_group_id] = []
            shard_query_stats_map[shard_group_id]["total_bytes_processed"] += (
                query.total_bytes_processed
            )
            shard_query_stats_map[shard_group_id]["query_count"] += 1
            shard_timestamps_map[shard_group_id].append(query.creation_time)

    # Extract filtered columns for all tables in a single pass (much more efficient)
    all_filtered_columns = aggregate_filtered_columns_all_tables(query_dicts)
    for table_key, filtered_cols in all_filtered_columns.items():
        if table_key in query_stats_map and filtered_cols:
            query_stats_map[table_key]["filtered_columns"] = filtered_cols

    for table_key, timestamps in query_timestamps_map.items():
        query_stats_map[table_key]["query_days_in_period"] = _calculate_days_in_period(
            timestamps
        )
        query_stats_map[table_key]["query_distinct_days"] = _calculate_distinct_days(
            timestamps
        )

    for group_id, timestamps in shard_timestamps_map.items():
        shard_query_stats_map[group_id]["query_days_in_period"] = (
            _calculate_days_in_period(timestamps)
        )
        shard_query_stats_map[group_id]["query_distinct_days"] = (
            _calculate_distinct_days(timestamps)
        )

    # Merge everything
    enriched_tables = []
    for table in tables:
        table_dict = table.model_dump()
        table_key = f"{table.table_schema}.{table.table_name}"

        # Add table_id
        table_dict["table_id"] = table_key

        # Add last_modified_time
        if table_key in access_map:
            table_dict["last_modified_time"] = access_map[table_key]
        else:
            # Fallback to creation_time if no access pattern
            table_dict["last_modified_time"] = table.creation_time

        # Add schema
        if table_key in schemas:
            table_dict["schema"] = schemas[table_key]
        else:
            table_dict["schema"] = []

        # Add query_stats
        if table_key in query_stats_map:
            table_dict["query_stats"] = query_stats_map[table_key]
        else:
            table_dict["query_stats"] = {"total_bytes_processed": 0, "query_count": 0}

        shard_group_id = table_to_shard_group.get(table_key)
        if shard_group_id:
            group_info = shard_groups[shard_group_id]
            table_dict["is_date_sharded"] = True
            table_dict["shard_group_id"] = shard_group_id
            table_dict["shard_group_table_count"] = group_info["table_count"]
            table_dict["shard_group_total_size_bytes"] = group_info["total_size_bytes"]
            table_dict["shard_group_query_stats"] = shard_query_stats_map.get(
                shard_group_id,
                {"total_bytes_processed": 0, "query_count": 0},
            )

        enriched_tables.append(table_dict)

    return enriched_tables


def anonymize_table_list(
    tables: List[TableMetadata], encryption_key: bytes
) -> List[Dict[str, Any]]:
    """
    Anonymize list of TableMetadata objects using AES encryption.

    Converts Pydantic TableMetadata models to dictionaries and encrypts
    all sensitive fields (table_catalog, table_schema, table_name) while
    preserving metadata values (size_bytes, row_count, timestamps, etc.).

    Args:
        tables: List of TableMetadata Pydantic models
        encryption_key: 32-byte AES-256 encryption key from credentials

    Returns:
        List of anonymized dictionaries

    Example:
        >>> from bqcheck.scanner.models import TableMetadata
        >>> from bqcheck.scanner.encryption import IdentifierEncryptor
        >>> tables = [
        ...     TableMetadata(
        ...         table_catalog="my-project",
        ...         table_schema="analytics",
        ...         table_name="users",
        ...         table_type="TABLE",
        ...         creation_time="2024-01-01",
        ...         size_bytes=1073741824,
        ...         row_count=1000000
        ...     )
        ... ]
        >>> key = IdentifierEncryptor.generate_key()
        >>> anonymized = anonymize_table_list(tables, key)
        >>> len(anonymized[0]["table_name"]) > 0
        True
        >>> anonymized[0]["size_bytes"]
        1073741824

    Privacy Note:
        This is the primary function for anonymizing table metadata batches.
        All table identifiers are encrypted before transmission to server.
    """
    anonymized_tables = []

    for table in tables:
        # Convert Pydantic model to dict
        table_dict = table.model_dump()

        # Encrypt sensitive fields
        anonymized_dict = anonymize_metadata(table_dict, encryption_key)

        anonymized_tables.append(anonymized_dict)

    return anonymized_tables


def anonymize_query_list(
    queries: List[QueryMetadata], encryption_key: bytes
) -> List[Dict[str, Any]]:
    """
    Anonymize list of QueryMetadata objects using AES encryption.

    Converts Pydantic QueryMetadata models to dictionaries and encrypts
    query text by replacing table references with encrypted versions.

    Args:
        queries: List of QueryMetadata Pydantic models
        encryption_key: 32-byte AES-256 encryption key from credentials

    Returns:
        List of anonymized dictionaries with query text table references encrypted

    Example:
        >>> from bqcheck.scanner.models import QueryMetadata
        >>> from bqcheck.scanner.encryption import IdentifierEncryptor
        >>> queries = [
        ...     QueryMetadata(
        ...         job_id="project:location.job_abc123",
        ...         query="SELECT * FROM dataset.table",
        ...         total_bytes_processed=1073741824,
        ...         creation_time="2024-01-20 10:30:00 UTC",
        ...         job_type="QUERY",
        ...         state="DONE"
        ...     )
        ... ]
        >>> key = IdentifierEncryptor.generate_key()
        >>> anonymized = anonymize_query_list(queries, key)
        >>> len(anonymized)
        1
        >>> "dataset.table" in anonymized[0]["query"]
        False

    Privacy Note:
        Query text is anonymized using anonymize_query_pattern() which replaces
        all table references (FROM/JOIN clauses) with encrypted versions while
        preserving SQL structure.
    """
    anonymized_queries = []

    for query in queries:
        # Convert Pydantic model to dict
        query_dict = query.model_dump()

        # Encrypt query text (table references)
        if "query" in query_dict and query_dict["query"]:
            query_dict["query"] = anonymize_query_pattern(
                query_dict["query"], encryption_key
            )

        anonymized_queries.append(query_dict)

    return anonymized_queries


def anonymize_access_patterns(
    patterns: List[AccessPattern], encryption_key: bytes
) -> List[Dict[str, Any]]:
    """
    Anonymize list of AccessPattern objects using AES encryption.

    Converts Pydantic AccessPattern models to dictionaries and encrypts
    sensitive fields (table_catalog, table_schema, table_name) while
    preserving last_modified_time metadata.

    Args:
        patterns: List of AccessPattern Pydantic models
        encryption_key: 32-byte AES-256 encryption key from credentials

    Returns:
        List of anonymized dictionaries

    Example:
        >>> from bqcheck.scanner.models import AccessPattern
        >>> from bqcheck.scanner.encryption import IdentifierEncryptor
        >>> patterns = [
        ...     AccessPattern(
        ...         table_catalog="my-project",
        ...         table_schema="analytics",
        ...         table_name="users",
        ...         last_modified_time="2024-01-20 10:30:00 UTC"
        ...     )
        ... ]
        >>> key = IdentifierEncryptor.generate_key()
        >>> anonymized = anonymize_access_patterns(patterns, key)
        >>> len(anonymized[0]["table_name"]) > 0
        True

    Privacy Note:
        Access patterns reveal which tables are actively used. Table
        identifiers are encrypted while preserving timestamps for
        pattern analysis.
    """
    anonymized_patterns = []

    for pattern in patterns:
        # Convert Pydantic model to dict
        pattern_dict = pattern.model_dump()

        # Encrypt sensitive fields
        anonymized_dict = anonymize_metadata(pattern_dict, encryption_key)

        anonymized_patterns.append(anonymized_dict)

    return anonymized_patterns
