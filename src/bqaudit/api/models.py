"""Pydantic models for API requests and responses."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, ClassVar, Dict, List, Optional

from pydantic import BaseModel, Field, field_serializer, field_validator


class ActivationRequest(BaseModel):
    """Request payload for license activation."""

    master_key: str = Field(description="Master license key to activate")


class ActivationResponse(BaseModel):
    """Response payload for successful license activation."""

    token_pool_balance: int = Field(description="Number of scans in pool", ge=0)
    ephemeral_token: str = Field(description="First ephemeral scan token")
    server_url: str = Field(description="API server URL")
    activated_at: Optional[datetime] = Field(
        default=None, description="Activation timestamp"
    )

    @field_serializer("activated_at")
    def serialize_datetime(self, dt: Optional[datetime]) -> Optional[str]:
        """Serialize datetime to ISO8601 string."""
        return dt.isoformat() if dt else None


class TokenRenewalRequest(BaseModel):
    """Request payload for token renewal after successful scan."""

    master_key: str = Field(description="Master license key")


class TokenRenewalResponse(BaseModel):
    """Response payload for token renewal."""

    ephemeral_token: str = Field(description="New ephemeral scan token")
    token_pool_balance: int = Field(description="Updated token balance", ge=0)


# Audit Request/Response Models (Story 5.1)


class AuditMetadata(BaseModel):
    """
    Structured metadata for audit request (Story 5.3).

    Validates BigQuery metadata structure to prevent server-side errors.

    Note: Uses List[Dict[str, Any]] instead of typed Pydantic models for JSON serialization.
    Content validation is performed upstream via scanner.models (TableMetadata,
    QueryMetadata, AccessPattern) which are converted to dicts via model_dump()
    before being passed here (see executor.py:323-327). This ensures all required
    fields are present and correctly typed.

    Added max_items limits to prevent memory exhaustion
    attacks where malicious payloads contain millions of empty dicts.

    Added per-dict size validation to prevent memory
    exhaustion via large dicts (max_length limits list items but not dict size).
    """

    # Maximum serialized size per dict (1MB) to prevent DoS attacks
    MAX_DICT_SIZE_BYTES: ClassVar[int] = 1024 * 1024  # 1MB

    tables: List[Dict[str, Any]] = Field(
        description="List of table metadata dicts (validated upstream via TableMetadata.model_dump())",
        default_factory=list,
        max_length=10000,  # Prevent memory exhaustion attacks
    )
    queries: List[Dict[str, Any]] = Field(
        description="List of query metadata dicts (validated upstream via QueryMetadata.model_dump())",
        default_factory=list,
        max_length=10000,  # Prevent memory exhaustion attacks
    )
    access_patterns: List[Dict[str, Any]] = Field(
        description="List of access pattern dicts (validated upstream via AccessPattern.model_dump())",
        default_factory=list,
        max_length=10000,  # Prevent memory exhaustion attacks
    )

    @field_validator("tables", "queries", "access_patterns")
    @classmethod
    def validate_dict_sizes(cls, value: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Validate individual dict sizes to prevent memory exhaustion.

        max_length limits list items but NOT dict size.
        Attacker could send 10000 dicts × 2MB each = 20GB memory consumption.

        Args:
            value: List of dicts to validate

        Returns:
            Original value if valid

        Raises:
            ValueError: If any dict exceeds MAX_DICT_SIZE_BYTES (1MB)
        """
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                raise ValueError(f"Item {i} must be a dict, got {type(item).__name__}")

            # Check serialized size of each dict
            serialized = json.dumps(item)
            size_bytes = len(serialized.encode("utf-8"))

            if size_bytes > cls.MAX_DICT_SIZE_BYTES:
                raise ValueError(
                    f"Dict at index {i} exceeds maximum size: "
                    f"{size_bytes} bytes > {cls.MAX_DICT_SIZE_BYTES} bytes (1MB). "
                    "This may indicate a memory exhaustion attack or data corruption."
                )

        return value


class AuditRequest(BaseModel):
    """Request payload for audit execution."""

    project_id: str = Field(
        min_length=64,
        max_length=64,
        pattern="^[a-f0-9]{64}$",
        description="Anonymized GCP project ID (SHA-256 hash)",
    )
    metadata: AuditMetadata = Field(
        description="Anonymized BigQuery metadata (tables, queries, access_patterns)"
    )


class Recommendation(BaseModel):
    """Individual cost-saving recommendation."""

    type: str = Field(description="Recommendation category")
    priority: str = Field(description="Priority level (HIGH, MEDIUM, LOW)")
    title: str = Field(description="Brief recommendation title")
    description: str = Field(description="Detailed recommendation description")
    savings_eur: float = Field(ge=0, description="Estimated monthly savings in EUR")
    implementation_steps: List[str] = Field(description="Steps to implement")


class AuditSummary(BaseModel):
    """Summary statistics for audit results."""

    total_recommendations: int = Field(ge=0, description="Total recommendation count")
    total_potential_savings_eur: float = Field(
        ge=0, description="Total monthly savings in EUR"
    )
    high_priority_count: int = Field(ge=0, description="HIGH priority count")
    medium_priority_count: int = Field(ge=0, description="MEDIUM priority count")
    low_priority_count: int = Field(ge=0, description="LOW priority count")
    categories_breakdown: Dict[str, int] = Field(
        default_factory=dict, description="Count by category"
    )


class AuditResponse(BaseModel):
    """Response payload for audit execution."""

    recommendations: List[Recommendation] = Field(
        description="List of cost-saving recommendations"
    )
    summary: AuditSummary = Field(description="Audit summary statistics")
    audit_id: str = Field(description="Unique audit identifier")
    new_ephemeral_token: Optional[str] = Field(default=None, description="New ephemeral token for next scan")
