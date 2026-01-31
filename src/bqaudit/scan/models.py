"""Data models for scan functionality (Story 3.4)."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanResult(BaseModel):
    """
    Result of a BigQuery audit scan.

    Epic 3: Simulated scan results
    Epic 5: Real BigQuery audit with server integration
    """

    success: bool
    project_id: str = ""  # Optional for real scans
    simulated: bool = False
    audit_response: Optional[Any] = None  # Epic 5: Real audit response (AuditResponse)
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of audit findings (Epic 4: will contain Finding objects)",
    )
