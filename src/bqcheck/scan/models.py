"""Data models for scan functionality (Story 3.4)."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanResult(BaseModel):
    """
    Result of a BigQuery sanity check scan.

    Epic 3: Simulated scan results
    Epic 5: Real BigQuery sanity check with server integration
    """

    success: bool
    project_id: str = ""  # Optional for real scans
    simulated: bool = False
    check_response: Optional[Any] = None
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of check findings (Epic 4: will contain Finding objects)",
    )
