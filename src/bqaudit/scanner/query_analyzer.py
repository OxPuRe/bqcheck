"""Query pattern analysis for clustering recommendations.

This module extracts filtered columns from SQL queries to help identify
optimal clustering column candidates.
"""

import logging
import re
from collections import defaultdict
from typing import Dict, List

logger = logging.getLogger(__name__)


def extract_filtered_columns(query: str) -> List[str]:
    """
    Extract column names used in WHERE/HAVING clauses from a SQL query.

    Uses regex patterns to identify columns in filter conditions without
    requiring a full SQL parser. Handles common BigQuery patterns:
    - WHERE column = value
    - WHERE column IN (...)
    - WHERE column BETWEEN x AND y
    - WHERE column IS [NOT] NULL
    - WHERE column > / < / >= / <= value
    - AND/OR combinations

    Args:
        query: SQL query string

    Returns:
        List of column names found in filter clauses

    Example:
        >>> extract_filtered_columns("SELECT * FROM t WHERE user_id = 123 AND status IN ('active', 'pending')")
        ['user_id', 'status']
    """
    if not query:
        return []

    filtered_columns = []

    # Convert to lowercase for case-insensitive matching
    query_lower = query.lower()

    # Extract WHERE clause (everything after WHERE until GROUP BY/ORDER BY/LIMIT/;)
    # Match WHERE...GROUP|ORDER|HAVING|LIMIT|WINDOW|QUALIFY|;|end
    where_pattern = r'\bwhere\b\s+(.*?)(?:\b(?:group\s+by|order\s+by|having|limit|window|qualify)\b|;|$)'
    where_matches = re.findall(where_pattern, query_lower, re.IGNORECASE | re.DOTALL)

    # Also extract HAVING clause
    having_pattern = r'\bhaving\b\s+(.*?)(?:\b(?:order\s+by|limit|window|qualify)\b|;|$)'
    having_matches = re.findall(having_pattern, query_lower, re.IGNORECASE | re.DOTALL)

    all_conditions = ' '.join(where_matches + having_matches)

    if not all_conditions:
        return []

    # Pattern to match column names in filter conditions
    # Matches: column_name [operator] value
    # Common operators: =, !=, <>, >, <, >=, <=, IN, BETWEEN, IS, LIKE, REGEXP_CONTAINS
    # Column names: alphanumeric + underscore, optionally table-qualified (table.column)
    filter_patterns = [
        # column = value / column != value / column <> value
        r'\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s*(?:=|!=|<>|>|<|>=|<=)\s*',
        # column IN (...)
        r'\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s+in\s*\(',
        # column BETWEEN x AND y
        r'\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s+between\s+',
        # column IS [NOT] NULL
        r'\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s+is\s+(?:not\s+)?null\b',
        # column LIKE pattern
        r'\b([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s+(?:not\s+)?like\s+',
        # REGEXP_CONTAINS(column, pattern)
        r'regexp_contains\s*\(\s*([a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)?)\s*,',
    ]

    for pattern in filter_patterns:
        matches = re.findall(pattern, all_conditions, re.IGNORECASE)
        for match in matches:
            # Remove table prefix if present (table.column → column)
            column = match.split('.')[-1] if '.' in match else match
            # Skip SQL keywords that might be matched
            if column not in ('select', 'from', 'where', 'and', 'or', 'not', 'null',
                             'true', 'false', 'between', 'in', 'like', 'is', 'as'):
                filtered_columns.append(column)

    return filtered_columns


def aggregate_filtered_columns_by_table(
    queries: List[Dict[str, any]],
    table_key: str
) -> Dict[str, int]:
    """
    Aggregate filtered columns for a specific table from all queries.

    Counts how many times each column appears in WHERE clauses of queries
    that reference the given table.

    Args:
        queries: List of query metadata dicts with 'query' field
        table_key: Table identifier in "dataset.table" format

    Returns:
        Dict mapping column names to usage frequency

    Example:
        >>> queries = [
        ...     {"query": "SELECT * FROM dataset.users WHERE user_id = 1 AND status = 'active'"},
        ...     {"query": "SELECT * FROM dataset.users WHERE user_id = 2"}
        ... ]
        >>> aggregate_filtered_columns_by_table(queries, "dataset.users")
        {'user_id': 2, 'status': 1}
    """
    column_counts: Dict[str, int] = defaultdict(int)

    # Extract dataset and table from table_key
    if '.' not in table_key:
        return {}

    dataset, table = table_key.split('.', 1)

    for query_meta in queries:
        query = query_meta.get('query', '')
        if not query:
            continue

        # Check if this query references our table
        # Simple heuristic: look for dataset.table or just table in FROM/JOIN
        query_lower = query.lower()
        table_patterns = [
            rf'\bfrom\s+[`"]?{re.escape(dataset)}\.{re.escape(table)}[`"]?\b',
            rf'\bjoin\s+[`"]?{re.escape(dataset)}\.{re.escape(table)}[`"]?\b',
            rf'\bfrom\s+[`"]?{re.escape(table)}[`"]?\b',  # Without dataset prefix
            rf'\bjoin\s+[`"]?{re.escape(table)}[`"]?\b',
        ]

        references_table = any(re.search(pattern, query_lower) for pattern in table_patterns)

        if references_table:
            # Extract filtered columns from this query
            columns = extract_filtered_columns(query)
            for column in columns:
                column_counts[column] += 1

    return dict(column_counts)
