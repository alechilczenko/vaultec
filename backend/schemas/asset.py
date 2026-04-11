"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import Optional
from pydantic import BaseModel, ConfigDict, Field
from enum import Enum
from datetime import datetime
from .common import SafeIntID

class AssetType(str, Enum):
    IP = "IP"
    URL = "URL"
    HOST = "Host"

class AssetRead(BaseModel):
    id: SafeIntID
    name: str
    type: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class AssetListRead(BaseModel):
    assets: list[AssetRead]

class AssetCreate(BaseModel):
    name: str = Field(..., max_length=255, examples=["192.168.1.10", "https://api.example.com"])
    type: AssetType
    description: Optional[str] = Field(None, max_length=5000)

class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    type: Optional[AssetType] = None
    description: Optional[str] = Field(None, max_length=5000)

class AssetBulkImport(BaseModel):
    assets: list[AssetCreate] = Field(..., max_items=100)