"""Pydantic models for BigQuery metadata structures."""

from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class TableMetadata(BaseModel):
    """Complete metadata for a BigQuery table.

    This model combines data from INFORMATION_SCHEMA.TABLES and TABLE_STORAGE.
    All fields use Python 3.8 compatible type hints.
    """

    # Core table identification
    table_catalog: str = Field(..., description="Project ID")
    table_schema: str = Field(..., description="Dataset ID")
    table_name: str = Field(..., description="Table name")
    table_type: str = Field(..., description="TABLE, VIEW, EXTERNAL, etc.")

    # Temporal metadata
    creation_time: str = Field(..., description="Table creation timestamp (ISO format)")

    # Storage metadata
    size_bytes: Optional[int] = Field(None, description="Total storage size in bytes")
    row_count: Optional[int] = Field(None, description="Total row count")

    # Partitioning metadata
    partition_expiration_days: Optional[int] = Field(
        None, description="Partition expiration in days"
    )
    time_partitioning_type: Optional[str] = Field(
        None, description="DAY, HOUR, MONTH, YEAR"
    )
    time_partitioning_field: Optional[str] = Field(
        None, description="Partitioning column name"
    )

    # Clustering metadata
    clustering_fields: Optional[List[str]] = Field(
        None, description="Clustering column names"
    )

    model_config = ConfigDict(
        frozen=False, extra="forbid"
    )  # Allow mutation, forbid extra fields


class QueryMetadata(BaseModel):
    """Metadata for a BigQuery job/query from INFORMATION_SCHEMA.JOBS.

    This model captures query execution metadata for identifying expensive queries
    and analyzing query patterns. All fields use Python 3.8 compatible type hints.
    """

    # Job identification
    job_id: str = Field(..., description="BigQuery job ID (project:location.job_id)")
    query: str = Field(..., description="SQL query text")

    # Execution metrics
    total_bytes_processed: int = Field(
        ..., description="Total bytes processed by the query"
    )
    creation_time: str = Field(..., description="Query creation timestamp (ISO format)")

    # Referenced tables (from BigQuery metadata)
    referenced_tables: Optional[List[str]] = Field(
        None, description="List of tables referenced in 'dataset.table' format"
    )

    # Optional metadata
    user_email: Optional[str] = Field(
        None, description="Email of user who ran the query"
    )
    job_type: str = Field(..., description="Job type (QUERY, LOAD, EXTRACT, COPY)")
    state: str = Field(..., description="Job state (DONE, RUNNING, PENDING)")

    model_config = ConfigDict(
        frozen=False, extra="forbid"
    )  # Allow mutation, forbid extra fields


class AccessPattern(BaseModel):
    """Table access pattern from INFORMATION_SCHEMA.TABLE_STORAGE_TIMELINE.

    This model captures the latest observable storage activity timestamp for tables.
    All fields use Python 3.8 compatible type hints.
    """

    # Table identification
    table_catalog: str = Field(..., description="Project ID")
    table_schema: str = Field(..., description="Dataset ID")
    table_name: str = Field(..., description="Table name")

    # Activity metadata
    last_access_time: str = Field(
        ..., description="Latest observed storage activity timestamp (ISO format)"
    )

    model_config = ConfigDict(
        frozen=False, extra="forbid"
    )  # Allow mutation, forbid extra fields
