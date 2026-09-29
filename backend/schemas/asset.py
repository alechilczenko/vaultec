"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import Optional, Any
from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator
from enum import Enum
from datetime import datetime
from .common import SafeIntID, BaseSchema
from .enums import SeverityEnum, FindingStatus


class AssetType(str, Enum):
    IP = "IP"
    URL = "URL"
    HOST = "Host"


class AssetScope(str, Enum):
    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"


class AssetRead(BaseModel):
    id: SafeIntID
    name: str
    type: str
    scope: AssetScope
    notes: Optional[str] = None
    created_at: datetime
    findings_count: int = 0

    model_config = ConfigDict(from_attributes=True)


class AssetListRead(BaseModel):
    assets: list[AssetRead]


class TopFindingRead(BaseModel):
    id: SafeIntID
    title: str
    severity: SeverityEnum
    status: FindingStatus
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AssetCreate(BaseSchema):
    name: str = Field(..., min_length=1, max_length=255, json_schema_extra={"example": "192.168.1.10"})
    type: AssetType
    scope: AssetScope = Field(
        default=AssetScope.IN_SCOPE,
        description="Whether this asset is in or out of pentest scope.",
    )
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
    scope: Optional[AssetScope] = Field(default=None)
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
            for field in ["name", "type", "scope"]:
                if field in data and data[field] is None:
                    raise ValueError(f"Field '{field}' cannot be null.")
        return data


class AssetBulkImport(BaseModel):
    assets: list[AssetCreate] = Field(..., max_length=100)
