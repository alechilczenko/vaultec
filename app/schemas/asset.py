"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from typing import Optional, Any
from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator
from enum import Enum
from datetime import datetime
from .common import SafeIntID, BaseSchema
from .enums import SeverityEnum


class AssetType(str, Enum):
    IP = "IP"
    URL = "URL"
    HOST = "Host"


class AssetRead(BaseModel):
    id: SafeIntID
    name: str
    type: str
    notes: Optional[str] = None
    created_at: datetime
    findings_count: int = 0
    max_severity: Optional[SeverityEnum] = None

    model_config = ConfigDict(from_attributes=True)


class AssetListRead(BaseModel):
    assets: list[AssetRead]
    total: int = Field(..., ge=0)


class AssetExportWorkspace(BaseModel):
    """Assessment header for inventory export (no id/status)."""
    name: Optional[str] = None
    client_name: Optional[str] = None
    created_at: Optional[datetime] = None


class AssetExportRead(BaseModel):
    workspace: AssetExportWorkspace
    exported_at: datetime
    assets: list[AssetRead]
    total: int = Field(..., ge=0)


class AssetCreate(BaseSchema):
    name: str = Field(..., min_length=1, max_length=255, json_schema_extra={"example": "192.168.1.10"})
    type: AssetType
    notes: Optional[str] = Field(None, max_length=2000)

    @field_validator("notes", mode="before")
    @classmethod
    def empty_notes_as_none(cls, v: Any) -> Any:
        if v == "":
            return None
        return v


class AssetUpdate(BaseSchema):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    type: Optional[AssetType] = Field(default=None)
    notes: Optional[str] = Field(default=None, max_length=2000)

    @field_validator("notes", mode="before")
    @classmethod
    def empty_notes_as_none(cls, v: Any) -> Any:
        if v == "":
            return None
        return v

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
