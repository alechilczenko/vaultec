"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import List, Optional
from pydantic import BaseModel, field_validator
from .instance import VulnerabilityInstance
from .enums import SeverityEnum

class VulnerabilityDefinitionRead(BaseModel):
    title: str
    description: Optional[str] = None
    recommendation: Optional[str] = None
    tags: List[str] = []

    @field_validator("tags", mode="before")
    @classmethod
    def split_tags(cls, v):
        if isinstance(v, str):
            return [t.strip() for t in v.split(",") if t.strip()]
        return v or []
    
    class Config:
        from_attributes = True

class VulnerabilityDefinitionUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[SeverityEnum] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    tags: Optional[List[str]] = None

class VulnerabilityGrouped(BaseModel):
    id: int
    title: str
    severity: SeverityEnum
    description: Optional[str]
    recommendation: Optional[str]
    tags: List[str] = []
    instances: List[VulnerabilityInstance]

    class Config:
        from_attributes = True