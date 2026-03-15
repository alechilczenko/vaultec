"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import List, Optional
from pydantic import BaseModel
from .instance import VulnerabilityInstance
from .enums import SeverityEnum

class VulnerabilityDefinitionRead(BaseModel):
    title: str
    description: Optional[str] = None
    recommendation: Optional[str] = None
    tags: Optional[str] = None

    class Config:
        from_attributes = True

class VulnerabilityDefinitionUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[SeverityEnum] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    tags: Optional[str] = None

class VulnerabilityGrouped(BaseModel):
    id: int
    title: str
    severity: SeverityEnum
    description: Optional[str]
    recommendation: Optional[str]
    tags: Optional[str] = None
    instances: List[VulnerabilityInstance]

    class Config:
        from_attributes = True