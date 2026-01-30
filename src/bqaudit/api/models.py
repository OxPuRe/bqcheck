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
