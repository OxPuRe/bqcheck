"""Data models for scan functionality (Story 3.4)."""

from typing import Any, Dict, List

from pydantic import BaseModel, Field


class ScanResult(BaseModel):
    """
    Result of a BigQuery audit scan.

    Epic 3: Simulated scan results
    Epic 4: Real BigQuery INFORMATION_SCHEMA scan results
    """

    success: bool
    project_id: str
    simulated: bool = False
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of audit findings (Epic 4: will contain Finding objects)",
    )
