"""Data models for license management."""

from datetime import datetime
from typing import Union

from pydantic import BaseModel, Field, field_serializer, field_validator


class Credentials(BaseModel):
    """
    Stored credentials data model.

    Persisted to ~/.bqaudit/credentials.json with chmod 600.

    This model validates credentials data and ensures type safety.
    Accepts activated_at as either datetime object or ISO8601 string.
    """

    master_key: str = Field(description="Master license key (long-lived)")
    token_pool_balance: int = Field(description="Number of scans remaining", ge=0)
    ephemeral_token: str = Field(description="Current single-use scan token")
    server_url: str = Field(description="API server URL")
    activated_at: datetime = Field(description="ISO8601 timestamp of activation")

    @field_validator("activated_at", mode="before")
    @classmethod
    def parse_activated_at(cls, v: Union[datetime, str]) -> datetime:
        """Parse activated_at from ISO8601 string or datetime object."""
        if isinstance(v, str):
            return datetime.fromisoformat(v)
        return v

    @field_serializer("activated_at")
    def serialize_datetime(self, dt: datetime) -> str:
        """Serialize datetime to ISO8601 string with 'Z' suffix for UTC."""
        # Use 'Z' suffix instead of '+00:00' for consistency
        iso_str = dt.isoformat()
        return iso_str.replace('+00:00', 'Z')
