from pydantic import BaseModel
from typing import List, Optional
import enum

class SeverityEnum(str, enum.Enum):
    informative = "informative"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class UserRead(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True

class AssetRead(BaseModel):
    id: int
    name: str
    type: str

    class Config:
        from_attributes = True

class AssetCreate(BaseModel):
    name: str
    type: str

class VulnerabilityDefinitionRead(BaseModel):
    title: str
    description: Optional[str] = None
    recommendation: Optional[str] = None

    class Config:
        from_attributes = True

class VulnerabilityCreate(BaseModel):
    title: str
    description: Optional[str] = None
    recommendation: Optional[str] = None
    severity: SeverityEnum
    status: Optional[str] = "open"
    asset: AssetCreate

class VulnerabilityRead(BaseModel):
    id: int
    severity: SeverityEnum
    status: str
    definition: VulnerabilityDefinitionRead 
    asset: AssetRead

    class Config:
        from_attributes = True

class VulnerabilityInstance(BaseModel):
    id: int
    status: str
    asset: AssetRead

    class Config:
        from_attributes = True

class VulnerabilityGrouped(BaseModel):
    id: int
    title: str
    severity: SeverityEnum
    description: Optional[str]
    recommendation: Optional[str]
    instances: List[VulnerabilityInstance]

    class Config:
        from_attributes = True

class VulnerabilityUpdate(BaseModel):
    title: Optional[str] = None
    severity: Optional[SeverityEnum] = None
    description: Optional[str] = None
    recommendation: Optional[str] = None
    status: Optional[str] = None