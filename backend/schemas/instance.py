from typing import List, Optional
from pydantic import BaseModel
from .asset import AssetCreate, AssetRead, AssetUpdate
from .enums import SeverityEnum

class VulnerabilityCreate(BaseModel):
    title: str
    description: Optional[str] = None
    recommendation: Optional[str] = None
    severity: SeverityEnum
    status: Optional[str] = "open"
    assets: List[AssetCreate]

class VulnerabilityInstance(BaseModel):
    id: int
    status: str
    asset: AssetRead

    class Config:
        from_attributes = True

class VulnerabilityUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[SeverityEnum] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    status: Optional[str] = None
    asset: Optional[AssetUpdate] = None
