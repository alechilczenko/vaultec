"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import List, Optional
from pydantic import BaseModel
from .asset import AssetRead
from .enums import SeverityEnum

class AssetFinding(BaseModel):
    asset_id: int
    status: Optional[str] = "open"
    evidence_type: str # "http", "terminal", "log"
    http_request: Optional[str] = None
    http_response: Optional[str] = None
    general_evidence: Optional[str] = None
    discovered_by: Optional[str] = None

class VulnerabilityCreate(BaseModel):
    title: str
    description: Optional[str] = None
    recommendation: Optional[str] = None
    severity: SeverityEnum
    tags: Optional[str] = None
    findings: List[AssetFinding]
    

class VulnerabilityInstance(BaseModel):
    id: int
    status: str
    evidence_type: Optional[str] = None
    http_request: Optional[str] = None
    http_response: Optional[str] = None
    general_evidence: Optional[str] = None
    discovered_by: Optional[str] = None
    asset: AssetRead
    class Config:
        from_attributes = True

class VulnerabilityInstanceUpdate(BaseModel):
    status: Optional[str] = None
    evidence_type: Optional[str] = None
    http_request: Optional[str] = None
    http_response: Optional[str] = None
    general_evidence: Optional[str] = None
    discovered_by: Optional[str] = None