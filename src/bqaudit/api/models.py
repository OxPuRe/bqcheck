"""Pydantic models for API requests and responses."""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field, field_serializer


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


class AuditRequest(BaseModel):
    """Request payload for audit execution."""

    project_id: str = Field(
        min_length=64,
        max_length=64,
        pattern="^[a-f0-9]{64}$",
        description="Anonymized GCP project ID (SHA-256 hash)",
    )
    metadata: dict = Field(
        description="Anonymized BigQuery metadata (tables, queries, access_patterns)"
    )


class Recommendation(BaseModel):
    """Individual cost-saving recommendation."""

    type: str = Field(description="Recommendation category")
    priority: str = Field(description="Priority level (HIGH, MEDIUM, LOW)")
    title: str = Field(description="Brief recommendation title")
    description: str = Field(description="Detailed recommendation description")
    savings_eur: float = Field(ge=0, description="Estimated monthly savings in EUR")
    implementation_steps: list[str] = Field(description="Steps to implement")


class AuditSummary(BaseModel):
    """Summary statistics for audit results."""

    total_recommendations: int = Field(ge=0, description="Total recommendation count")
    total_potential_savings_eur: float = Field(
        ge=0, description="Total monthly savings in EUR"
    )
    high_priority_count: int = Field(ge=0, description="HIGH priority count")
    medium_priority_count: int = Field(ge=0, description="MEDIUM priority count")
    low_priority_count: int = Field(ge=0, description="LOW priority count")
    categories_breakdown: dict[str, int] = Field(
        default_factory=dict, description="Count by category"
    )


class AuditResponse(BaseModel):
    """Response payload for audit execution."""

    recommendations: list[Recommendation] = Field(
        description="List of cost-saving recommendations"
    )
    summary: AuditSummary = Field(description="Audit summary statistics")
    audit_id: str = Field(description="Unique audit identifier")
    new_ephemeral_token: str = Field(description="New ephemeral token for next scan")
