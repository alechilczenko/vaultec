"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from .common import SafeIntID

class NoteCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=100, strip_whitespace=True)
    content: str = Field(..., min_length=1, max_length=5000, strip_whitespace=True)

class NoteRead(BaseModel):
    id: SafeIntID
    title: str
    content: str
    model_config = ConfigDict(from_attributes=True)

class NoteUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=1, max_length=100, strip_whitespace=True)
    content: Optional[str] = Field(None, min_length=1, max_length=5000, strip_whitespace=True)
    model_config = ConfigDict(from_attributes=True)