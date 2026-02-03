"""Data models for license management."""

from datetime import datetime
from typing import Any, Dict, List, Union

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
    encryption_key: str = Field(
        description="Base64-encoded AES-256 encryption key for identifier anonymization"
    )
    used_tokens: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Client-side tracking of used tokens (Story 3.4, AC8)",
    )

    @field_validator("activated_at", mode="before")
    @classmethod
    def parse_activated_at(cls, v: Union[datetime, str]) -> datetime:
        """Parse activated_at from ISO8601 string or datetime object."""
        if isinstance(v, str):
            # Replace 'Z' with '+00:00' for Python 3.8-3.10 compatibility
            # (fromisoformat only supports 'Z' suffix in Python 3.11+)
            v = v.replace("Z", "+00:00")
            return datetime.fromisoformat(v)
        return v

    @field_serializer("activated_at")
    def serialize_datetime(self, dt: datetime) -> str:
        """Serialize datetime to ISO8601 string with 'Z' suffix for UTC."""
        # Use 'Z' suffix instead of '+00:00' for consistency
        iso_str = dt.isoformat()
        return iso_str.replace("+00:00", "Z")

    def to_safe_dict(self) -> Dict[str, Any]:
        """
        Export credentials with sensitive fields masked for safe display/logging.

        This method should be used instead of model_dump() when displaying
        credentials to users or logging, to prevent accidental exposure of
        sensitive data like master_key and ephemeral_token.

        Returns:
            dict: Credentials with sensitive fields masked as ***REDACTED***

        Example:
            >>> creds = Credentials(master_key="secret", ...)
            >>> safe = creds.to_safe_dict()
            >>> safe["master_key"]
            '***REDACTED***'
        """
        data = self.model_dump(mode="json")
        # Mask sensitive fields
        data["master_key"] = "***REDACTED***"
        data["ephemeral_token"] = "***REDACTED***"
        data["encryption_key"] = "***REDACTED***"
        return data
