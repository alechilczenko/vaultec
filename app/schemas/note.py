"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from typing import Optional, Any
import re
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from .common import SafeIntID


def sanitize_text(v: Any, strip: bool = False) -> Any:
    if isinstance(v, str):
        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', v):
            raise ValueError("Null bytes or control characters are not allowed")
        return v.strip() if strip else v
    return v


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=100)
    content: str = Field(..., min_length=1, max_length=5000)

    @field_validator("title", mode="before")
    @classmethod
    def sanitize_title(cls, v: Any) -> Any:
        return sanitize_text(v, strip=True)

    @field_validator("content", mode="before")
    @classmethod
    def sanitize_content(cls, v: Any) -> Any:
        return sanitize_text(v, strip=True)

class NoteRead(BaseModel):
    id: SafeIntID
    title: str
    content: str
    model_config = ConfigDict(from_attributes=True)

class NoteUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    title: Optional[str] = Field(default=None, min_length=1, max_length=100)
    content: Optional[str] = Field(default=None, min_length=1, max_length=5000)

    @model_validator(mode="before")
    @classmethod
    def reject_explicit_nulls(cls, data: Any) -> Any:
        """Prevents clients from sending explicit null values to bypass NOT NULL constraints."""
        if isinstance(data, dict):
            for field in ["title", "content"]:
                if field in data and data[field] is None:
                    raise ValueError(f"Field '{field}' cannot be null.")
        return data

    @field_validator("title", mode="before")
    @classmethod
    def sanitize_title(cls, v: Any) -> Any:
        return sanitize_text(v, strip=True)

    @field_validator("content", mode="before")
    @classmethod
    def sanitize_content(cls, v: Any) -> Any:
        return sanitize_text(v, strip=True)

class NoteListRead(BaseModel):
    notes: list[NoteRead]