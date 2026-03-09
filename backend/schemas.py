from pydantic import BaseModel, Field
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

class AssetUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = None

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
    asset: List[AssetCreate]

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
    asset: Optional[AssetUpdate] = None

class NoteCreate(BaseModel):
    # Field(...) means it is required
    # min_length=1 prevents empty strings
    # strip_whitespace=True prevents strings with only spaces
    title: str = Field(..., min_length=1, strip_whitespace=True)
    content: str = Field(..., min_length=1, strip_whitespace=True)

class NoteRead(BaseModel):
    id: int
    title: str
    content: str

    class Config:
        from_attributes = True

class NoteUpdate(BaseModel):
    # Optional[] allows the field to be missing in the request
    # Field(None, ...) sets the default to None if not provided
    title: Optional[str] = Field(None, min_length=1, strip_whitespace=True)
    content: Optional[str] = Field(None, min_length=1, strip_whitespace=True)

    class Config:
        from_attributes = True