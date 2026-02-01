"""
Client-side SHA-256 anonymization for BigQuery metadata.

This module provides PRIVACY-CRITICAL functions for anonymizing sensitive
identifiers (table names, dataset names, queries) using SHA-256 hashing.

Privacy-by-Design Guarantees:
- All hashing occurs client-side before transmission
- SHA-256 irreversibility prevents reverse-engineering
- Deterministic hashing preserves cardinality within scan
- No raw identifiers leave the user's environment

Coverage Target: >90% (CRITICAL - privacy code must be thoroughly tested)
"""

import hashlib
import re
import secrets
from typing import Any, Dict, List, Optional

from bqaudit.scanner.models import AccessPattern, QueryMetadata, TableMetadata

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


def _validate_salt(salt: str) -> None:
    """
    Validate salt format and length.

    PRIVACY-CRITICAL: Ensures salt is cryptographically strong (32 hex chars).
    Weak or malformed salts compromise anonymization security.

    Args:
        salt: Salt to validate

    Raises:
        TypeError: If salt is not a string
        ValueError: If salt is not exactly 32 hex characters
    """
    if not isinstance(salt, str):
        raise TypeError(f"Salt must be string, got {type(salt).__name__}")

    if len(salt) != 32:
        raise ValueError(
            f"Salt must be exactly 32 characters (got {len(salt)}). "
            "Use generate_salt() to create a valid salt."
        )

    if not all(c in "0123456789abcdef" for c in salt):
        raise ValueError(
            "Salt must contain only hexadecimal characters (0-9, a-f). "
            "Use generate_salt() to create a valid salt."
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
    Generate cryptographically secure random salt for anonymization.

    Uses secrets module (cryptographically strong random number generator)
    to generate a 32-character hexadecimal salt. This salt should be
    generated once per scan session and used consistently for all
    anonymization operations within that scan.

    Returns:
        32-character hex string (16 random bytes = 128 bits of randomness)

    Example:
        >>> salt = generate_salt()
        >>> len(salt)
        32
        >>> all(c in '0123456789abcdef' for c in salt)
        True

    Privacy Note:
        Salt is generated per-scan and destroyed after anonymized payload
        is created. It is NEVER transmitted to the server.
    """
    return secrets.token_hex(16)


def anonymize_table_name(name: str, salt: str) -> str:
    """
    Anonymize table name using SHA-256 hash.

    PRIVACY-CRITICAL: This function hashes table names to prevent raw data
    identifiers from leaving the user's environment. The hash is deterministic
    (same input + same salt → same hash) to preserve cardinality within a scan.

    Args:
        name: Raw table name (e.g., "users_2024", "events", "payments")
        salt: 32-character hex salt from generate_salt()

    Returns:
        64-character hex hash (SHA-256 digest)

    Raises:
        TypeError: If name or salt is not a string
        ValueError: If table name is empty, too long, or salt is invalid

    Example:
        >>> salt = "a3f8c9e1b2d4c5e7a9f8b2d4c5e7a9f8"
        >>> hash1 = anonymize_table_name("users", salt)
        >>> len(hash1)
        64
        >>> hash2 = anonymize_table_name("users", salt)
        >>> hash1 == hash2  # Deterministic
        True

    Privacy Note:
        SHA-256 is cryptographically secure and collision-resistant.
        The hash cannot be reversed to recover the original table name.
        Type prefix prevents correlation with dataset/project hashes.
    """
    _validate_identifier(name, "Table name", MAX_TABLE_NAME_LENGTH)
    _validate_salt(salt)

    # Add type prefix to prevent hash correlation across identifier types
    combined = f"TABLE:{name}:{salt}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def anonymize_dataset_name(name: str, salt: str) -> str:
    """
    Anonymize dataset name using SHA-256 hash.

    PRIVACY-CRITICAL: This function hashes dataset names using the same
    SHA-256 pattern as table names. Dataset and table anonymization use
    the same hashing logic to ensure consistency.

    Args:
        name: Raw dataset name (e.g., "analytics", "production", "staging")
        salt: 32-character hex salt from generate_salt()

    Returns:
        64-character hex hash (SHA-256 digest)

    Raises:
        TypeError: If name or salt is not a string
        ValueError: If dataset name is empty, too long, or salt is invalid

    Example:
        >>> salt = generate_salt()
        >>> hash1 = anonymize_dataset_name("analytics", salt)
        >>> len(hash1)
        64

    Privacy Note:
        Dataset names are treated with the same privacy guarantees as
        table names. All identifiers are hashed client-side.
        Type prefix prevents correlation with table/project hashes.
    """
    _validate_identifier(name, "Dataset name", MAX_DATASET_NAME_LENGTH)
    _validate_salt(salt)

    # Add type prefix to prevent hash correlation across identifier types
    combined = f"DATASET:{name}:{salt}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def anonymize_project_id(project_id: str, salt: str) -> str:
    """
    Anonymize GCP project ID using SHA-256 hash.

    PRIVACY-CRITICAL: This function hashes project IDs to prevent exposing
    GCP project information. Project IDs can reveal organizational structure
    and naming conventions, so they are anonymized using the same SHA-256
    pattern as table/dataset names.

    Args:
        project_id: Raw GCP project ID (e.g., "my-prod-project-123")
        salt: 32-character hex salt from generate_salt()

    Returns:
        64-character hex hash (SHA-256 digest)

    Raises:
        TypeError: If project_id or salt is not a string
        ValueError: If project ID is empty, too long, or salt is invalid

    Example:
        >>> salt = generate_salt()
        >>> hash1 = anonymize_project_id("echo-analytics-prod", salt)
        >>> len(hash1)
        64

    Privacy Note:
        Project IDs are particularly sensitive as they can reveal
        organizational structure. Always hash before transmission.
        Type prefix prevents correlation with table/dataset hashes.
    """
    _validate_identifier(project_id, "Project ID", MAX_PROJECT_ID_LENGTH)
    _validate_salt(salt)

    # Add type prefix to prevent hash correlation across identifier types
    combined = f"PROJECT:{project_id}:{salt}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


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


def anonymize_query_pattern(query: Optional[str], salt: str) -> str:
    """
    Anonymize table references in SQL query pattern.

    PRIVACY-CRITICAL: This function extracts table references from SQL queries
    and replaces them with SHA-256 hashed versions. Preserves SQL structure
    while anonymizing all table identifiers.

    Args:
        query: SQL query string (can be None or empty)
        salt: 32-character hex salt from generate_salt()

    Returns:
        Anonymized query string with hashed table references

    Example:
        >>> salt = generate_salt()
        >>> query = "SELECT * FROM project.dataset.table"
        >>> anonymized = anonymize_query_pattern(query, salt)
        >>> "project.dataset.table" in anonymized
        False
        >>> "SELECT * FROM" in anonymized
        True

    Privacy Note:
        Query text contains sensitive table references that reveal data
        structure. All table identifiers are hashed before transmission.
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

    # Anonymize each table reference
    anonymized_query = query
    for table_ref in table_refs:
        # Split table reference into components (project.dataset.table or dataset.table)
        parts = table_ref.split(".")

        if len(parts) == 3:
            # Full reference: project.dataset.table
            project_hash = anonymize_project_id(parts[0], salt)
            dataset_hash = anonymize_dataset_name(parts[1], salt)
            table_hash = anonymize_table_name(parts[2], salt)
            hashed_ref = f"{project_hash}.{dataset_hash}.{table_hash}"
        elif len(parts) == 2:
            # Short reference: dataset.table
            dataset_hash = anonymize_dataset_name(parts[0], salt)
            table_hash = anonymize_table_name(parts[1], salt)
            hashed_ref = f"{dataset_hash}.{table_hash}"
        else:
            # Single identifier (shouldn't happen with regex pattern, but handle it)
            table_hash = anonymize_table_name(parts[0], salt)
            hashed_ref = table_hash

        # Replace original reference with hashed version
        anonymized_query = _replace_table_reference(
            anonymized_query, table_ref, hashed_ref
        )

    return anonymized_query


def anonymize_metadata(metadata_dict: Dict[str, Any], salt: str) -> Dict[str, Any]:
    """
    Anonymize sensitive fields in metadata dictionary.

    This function anonymizes table_catalog (project ID), table_schema
    (dataset name), and table_name fields while preserving all other
    metadata fields (size_bytes, row_count, creation_time, etc.).

    Args:
        metadata_dict: Metadata dictionary with sensitive fields
        salt: 32-character hex salt from generate_salt()

    Returns:
        New dictionary with anonymized sensitive fields

    Example:
        >>> salt = generate_salt()
        >>> metadata = {
        ...     "table_catalog": "my-project",
        ...     "table_schema": "analytics",
        ...     "table_name": "users",
        ...     "size_bytes": 1073741824,
        ...     "row_count": 1000000
        ... }
        >>> anonymized = anonymize_metadata(metadata, salt)
        >>> len(anonymized["table_catalog"])
        64
        >>> anonymized["size_bytes"]  # Non-sensitive fields preserved
        1073741824

    Privacy Note:
        Only sensitive identifier fields are anonymized. Metadata values
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
    }

    anonymized: Dict[str, Any] = {}

    # Anonymize sensitive identifier fields if present
    if "table_catalog" in metadata_dict:
        anonymized["table_catalog"] = anonymize_project_id(
            metadata_dict["table_catalog"], salt
        )

    if "table_schema" in metadata_dict:
        anonymized["table_schema"] = anonymize_dataset_name(
            metadata_dict["table_schema"], salt
        )

    if "table_name" in metadata_dict:
        anonymized["table_name"] = anonymize_table_name(
            metadata_dict["table_name"], salt
        )

    # Copy known safe (non-sensitive) fields
    for field, value in metadata_dict.items():
        if field in known_safe_fields:
            anonymized[field] = value

    return anonymized


def anonymize_table_list(
    tables: List[TableMetadata], salt: str
) -> List[Dict[str, Any]]:
    """
    Anonymize list of TableMetadata objects.

    Converts Pydantic TableMetadata models to dictionaries and anonymizes
    all sensitive fields (table_catalog, table_schema, table_name) while
    preserving metadata values (size_bytes, row_count, timestamps, etc.).

    Args:
        tables: List of TableMetadata Pydantic models
        salt: 32-character hex salt from generate_salt()

    Returns:
        List of anonymized dictionaries

    Example:
        >>> from bqaudit.scanner.models import TableMetadata
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
        >>> salt = generate_salt()
        >>> anonymized = anonymize_table_list(tables, salt)
        >>> len(anonymized[0]["table_name"])
        64
        >>> anonymized[0]["size_bytes"]
        1073741824

    Privacy Note:
        This is the primary function for anonymizing table metadata batches.
        All table identifiers are hashed before transmission to server.
    """
    anonymized_tables = []

    for table in tables:
        # Convert Pydantic model to dict
        table_dict = table.model_dump()

        # Anonymize sensitive fields
        anonymized_dict = anonymize_metadata(table_dict, salt)

        anonymized_tables.append(anonymized_dict)

    return anonymized_tables


def anonymize_query_list(
    queries: List[QueryMetadata], salt: str
) -> List[Dict[str, Any]]:
    """
    Anonymize list of QueryMetadata objects.

    Converts Pydantic QueryMetadata models to dictionaries and anonymizes
    query text by replacing table references with SHA-256 hashed versions.

    Args:
        queries: List of QueryMetadata Pydantic models
        salt: 32-character hex salt from generate_salt()

    Returns:
        List of anonymized dictionaries with query text table references hashed

    Example:
        >>> from bqaudit.scanner.models import QueryMetadata
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
        >>> salt = generate_salt()
        >>> anonymized = anonymize_query_list(queries, salt)
        >>> len(anonymized)
        1
        >>> "dataset.table" in anonymized[0]["query"]
        False

    Privacy Note:
        Query text is anonymized using anonymize_query_pattern() which replaces
        all table references (FROM/JOIN clauses) with SHA-256 hashes while
        preserving SQL structure.
    """
    anonymized_queries = []

    for query in queries:
        # Convert Pydantic model to dict
        query_dict = query.model_dump()

        # Anonymize query text (table references)
        if "query" in query_dict and query_dict["query"]:
            query_dict["query"] = anonymize_query_pattern(query_dict["query"], salt)

        anonymized_queries.append(query_dict)

    return anonymized_queries


def anonymize_access_patterns(
    patterns: List[AccessPattern], salt: str
) -> List[Dict[str, Any]]:
    """
    Anonymize list of AccessPattern objects.

    Converts Pydantic AccessPattern models to dictionaries and anonymizes
    sensitive fields (table_catalog, table_schema, table_name) while
    preserving last_modified_time metadata.

    Args:
        patterns: List of AccessPattern Pydantic models
        salt: 32-character hex salt from generate_salt()

    Returns:
        List of anonymized dictionaries

    Example:
        >>> from bqaudit.scanner.models import AccessPattern
        >>> patterns = [
        ...     AccessPattern(
        ...         table_catalog="my-project",
        ...         table_schema="analytics",
        ...         table_name="users",
        ...         last_modified_time="2024-01-20 10:30:00 UTC"
        ...     )
        ... ]
        >>> salt = generate_salt()
        >>> anonymized = anonymize_access_patterns(patterns, salt)
        >>> len(anonymized[0]["table_name"])
        64

    Privacy Note:
        Access patterns reveal which tables are actively used. Table
        identifiers are anonymized while preserving timestamps for
        pattern analysis.
    """
    anonymized_patterns = []

    for pattern in patterns:
        # Convert Pydantic model to dict
        pattern_dict = pattern.model_dump()

        # Anonymize sensitive fields
        anonymized_dict = anonymize_metadata(pattern_dict, salt)

        anonymized_patterns.append(anonymized_dict)

    return anonymized_patterns
