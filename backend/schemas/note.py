"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import Optional, Any
import re
from pydantic import BaseModel, Field, ConfigDict, field_validator
from .common import SafeIntID


def sanitize_text(v: Any, strip: bool = False) -> Any:
    """Validates control characters and optionally applies whitespace stripping."""
    if isinstance(v, str):
        if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', v):
            raise ValueError("Null bytes or control characters are not allowed")
        return v.strip() if strip else v
    return v


class NoteCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=100)
    content: str = Field(default="", max_length=5000)

    @field_validator("title", mode="before")
    @classmethod
    def sanitize_title(cls, v: Any) -> Any:
        return sanitize_text(v, strip=True)

    @field_validator("content", mode="before")
    @classmethod
    def sanitize_content(cls, v: Any) -> Any:
        return sanitize_text(v, strip=False)

class NoteRead(BaseModel):
    id: SafeIntID
    title: str
    content: str
    model_config = ConfigDict(from_attributes=True)

class NoteUpdate(BaseModel):
    model_config = ConfigDict(from_attributes=True, extra="forbid")

    title: Optional[str] = Field(None, min_length=1, max_length=100)
    content: Optional[str] = Field(None, max_length=5000)

    @field_validator("title", mode="before")
    @classmethod
    def sanitize_title(cls, v: Any) -> Any:
        return sanitize_text(v, strip=True)

    @field_validator("content", mode="before")
    @classmethod
    def sanitize_content(cls, v: Any) -> Any:
        return sanitize_text(v, strip=False)

class NoteListRead(BaseModel):
    notes: list[NoteRead]