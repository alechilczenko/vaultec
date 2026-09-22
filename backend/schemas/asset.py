"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import Optional, Any
from pydantic import BaseModel, ConfigDict, Field, model_validator
from enum import Enum
from datetime import datetime
from .common import SafeIntID, BaseSchema


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


class AssetCreate(BaseSchema):
    name: str = Field(..., min_length=1, max_length=255, json_schema_extra={"example": "192.168.1.10"})
    type: AssetType


class AssetUpdate(BaseSchema):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    type: Optional[AssetType] = Field(default=None)

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, data: Any) -> Any:
        if isinstance(data, dict):
            for field in ["name", "type"]:
                if field in data and data[field] is None:
                    raise ValueError(f"Field '{field}' cannot be null.")
        return data


class AssetBulkImport(BaseModel):
    assets: list[AssetCreate] = Field(..., max_length=100)