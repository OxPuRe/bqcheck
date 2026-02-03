"""Query aggregation for server-side detection algorithms.

This module transforms raw query metadata into aggregated statistics required
by the server's detection algorithms (repeated queries, etc.).

Aggregation Process:
1. Anonymize each query to create pattern hash
2. Group queries by pattern hash
3. Calculate execution frequency and byte statistics
4. Return aggregated format expected by server detectors
"""

import hashlib
import logging
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List

from bqaudit.scanner.anonymizer import anonymize_query_pattern
from bqaudit.scanner.models import QueryMetadata

logger = logging.getLogger(__name__)


def _parse_iso_timestamp(timestamp_str: str) -> datetime:
    """
    Parse ISO 8601 timestamp string to datetime.

    Args:
        timestamp_str: ISO format timestamp (e.g., "2024-01-20 10:30:00 UTC" or "2025-12-15 15:06:24.456+00")

    Returns:
        datetime object

    Raises:
        ValueError: If timestamp format is invalid
    """
    # BigQuery timestamps can be in multiple formats:
    # - "2024-01-20 10:30:00 UTC" (INFORMATION_SCHEMA.JOBS)
    # - "2025-12-15 15:06:24.456+00" (actual BigQuery format with timezone offset)

    # Python's strptime requires timezone offset to be 4 digits (+0000, not +00)
    # Normalize BigQuery's +00 format to +0000
    normalized_timestamp = timestamp_str
    if timestamp_str.endswith("+00"):
        normalized_timestamp = timestamp_str[:-3] + "+0000"
    elif timestamp_str.endswith("-00"):
        normalized_timestamp = timestamp_str[:-3] + "-0000"

    # Try multiple formats to be robust
    formats = [
        "%Y-%m-%d %H:%M:%S.%f%z",  # 2025-12-15 15:06:24.456+0000
        "%Y-%m-%d %H:%M:%S%z",  # 2025-12-15 15:06:24+0000
        "%Y-%m-%d %H:%M:%S UTC",  # 2024-01-20 10:30:00 UTC
        "%Y-%m-%d %H:%M:%S.%f UTC",  # 2024-01-20 10:30:00.123456 UTC
        "%Y-%m-%dT%H:%M:%S",  # 2024-01-20T10:30:00
        "%Y-%m-%dT%H:%M:%S.%f",  # 2024-01-20T10:30:00.123456
    ]

    for fmt in formats:
        try:
            return datetime.strptime(normalized_timestamp, fmt)
        except ValueError:
            continue

    # If none of the formats worked, raise error
    raise ValueError(
        f"Unable to parse timestamp '{timestamp_str}'. "
        f"Expected ISO 8601 format like '2024-01-20 10:30:00 UTC' or '2025-12-15 15:06:24.456+00'"
    )


def _calculate_days_in_period(timestamps: List[str]) -> float:
    """
    Calculate the number of days covered by a list of timestamps.

    Args:
        timestamps: List of ISO format timestamp strings

    Returns:
        Number of days between earliest and latest timestamp (minimum 1.0)
    """
    if not timestamps:
        return 1.0

    try:
        datetimes = [_parse_iso_timestamp(ts) for ts in timestamps]
        min_time = min(datetimes)
        max_time = max(datetimes)

        delta = max_time - min_time
        days = delta.total_seconds() / 86400.0  # 86400 seconds in a day

        # Return at least 1 day to avoid division by zero
        return max(1.0, days)

    except ValueError as e:
        logger.warning(f"Failed to parse timestamps: {e}. Using 1 day as fallback.")
        return 1.0


def aggregate_query_metadata(
    queries: List[QueryMetadata], encryption_key: bytes, scan_days: int = 90
) -> List[Dict[str, Any]]:
    """
    Aggregate raw query metadata into pattern-based statistics.

    Groups queries by encrypted pattern and calculates execution frequency
    and byte statistics required by server detection algorithms.

    Args:
        queries: List of QueryMetadata objects from INFORMATION_SCHEMA.JOBS
        encryption_key: 32-byte AES-256 encryption key from credentials
        scan_days: Number of days in scan period (default: 90)

    Returns:
        List of aggregated query statistics dictionaries with fields:
        - query_hash: SHA-256 hash of encrypted query pattern
        - query_text: Encrypted query pattern (table refs encrypted)
        - executions_per_day: Average daily execution count
        - bytes_per_execution: Average bytes processed per execution
        - total_bytes_processed: Total bytes across all executions
        - has_materialized_view: Whether materialized view exists (always False for now)

    Example:
        >>> from bqaudit.scanner.models import QueryMetadata
        >>> from bqaudit.scanner.encryption import IdentifierEncryptor
        >>> queries = [
        ...     QueryMetadata(
        ...         job_id="project:us.job1",
        ...         query="SELECT * FROM dataset.table",
        ...         total_bytes_processed=1099511627776,  # 1 TB
        ...         creation_time="2024-01-01 10:00:00 UTC",
        ...         job_type="QUERY",
        ...         state="DONE"
        ...     ),
        ...     QueryMetadata(
        ...         job_id="project:us.job2",
        ...         query="SELECT * FROM dataset.table",  # Same pattern
        ...         total_bytes_processed=1099511627776,  # 1 TB
        ...         creation_time="2024-01-02 10:00:00 UTC",
        ...         job_type="QUERY",
        ...         state="DONE"
        ...     ),
        ... ]
        >>> key = IdentifierEncryptor.generate_key()
        >>> aggregated = aggregate_query_metadata(queries, key)
        >>> len(aggregated)
        1
        >>> aggregated[0]["executions_per_day"]  # 2 executions / actual days
        2.0
    """
    if not queries:
        return []

    # Group queries by anonymized pattern
    pattern_groups: Dict[str, List[QueryMetadata]] = defaultdict(list)

    for query in queries:
        # Skip queries without text
        if not query.query:
            logger.debug(f"Skipping query {query.job_id} - no query text")
            continue

        # Encrypt query pattern (table references)
        encrypted_query = anonymize_query_pattern(query.query, encryption_key)

        # Create pattern hash from encrypted query
        pattern_hash = hashlib.sha256(encrypted_query.encode("utf-8")).hexdigest()

        # Group by pattern hash
        pattern_groups[pattern_hash].append(query)

    # Aggregate statistics for each pattern
    aggregated_queries = []

    for pattern_hash, pattern_queries in pattern_groups.items():
        # Calculate total bytes across all executions
        total_bytes = sum(q.total_bytes_processed for q in pattern_queries)

        # Calculate average bytes per execution
        execution_count = len(pattern_queries)
        bytes_per_execution = (
            total_bytes // execution_count if execution_count > 0 else 0
        )

        # Calculate executions per day using actual time range
        timestamps = [q.creation_time for q in pattern_queries]
        days_in_period = _calculate_days_in_period(timestamps)
        executions_per_day = execution_count / days_in_period

        # Get encrypted query text (same for all queries in group)
        encrypted_query = anonymize_query_pattern(
            pattern_queries[0].query, encryption_key
        )

        # Find last execution time (most recent timestamp)
        try:
            datetimes = [_parse_iso_timestamp(ts) for ts in timestamps]
            last_execution = max(datetimes).isoformat()
        except ValueError:
            # Fallback to first timestamp if parsing fails
            last_execution = timestamps[0]

        # Create aggregated entry
        aggregated_entry = {
            "query_hash": pattern_hash,
            "query_text": encrypted_query,
            "executions_per_day": executions_per_day,
            "bytes_per_execution": bytes_per_execution,
            "total_bytes_processed": total_bytes,
            "has_materialized_view": False,  # TODO: Detect materialized views in future
            "execution_count": execution_count,  # Total number of executions
            "days_in_period": days_in_period,  # Actual period of activity
            "last_execution_time": last_execution,  # Most recent execution
        }

        aggregated_queries.append(aggregated_entry)

        logger.debug(
            f"Pattern {pattern_hash[:8]}... - {execution_count} executions "
            f"({executions_per_day:.1f}/day), {bytes_per_execution / 1024**4:.2f} TB/exec"
        )

    logger.info(
        f"Aggregated {len(queries)} queries into {len(aggregated_queries)} unique patterns"
    )

    return aggregated_queries
