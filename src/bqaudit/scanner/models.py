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
    table_name: str = Field(
        ..., description="Table name (will be anonymized in Story 2.4)"
    )
    table_type: str = Field(..., description="TABLE, VIEW, EXTERNAL, etc.")

    # Temporal metadata
    creation_time: str = Field(
        ..., description="Table creation timestamp (ISO format)"
    )

    # Storage metadata
    size_bytes: Optional[int] = Field(
        None, description="Total storage size in bytes"
    )
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
        frozen=False
    )  # Allow mutation during extraction if needed
