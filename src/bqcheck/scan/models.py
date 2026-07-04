"""Data models for scan functionality."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ScanResult(BaseModel):
    """Result of a BigQuery sanity check scan."""

    success: bool
    project_id: str = ""  # Optional for real scans
    simulated: bool = False
    check_response: Optional[Any] = None
    report_notes: List[str] = Field(
        default_factory=list,
        description="Report notes about scan coverage or transport fallbacks",
    )
    findings: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of check findings",
    )
