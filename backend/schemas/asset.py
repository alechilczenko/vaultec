from typing import Optional
from pydantic import BaseModel

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