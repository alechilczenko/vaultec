"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from pydantic import BaseModel, ConfigDict, Field
from typing import Optional
from datetime import datetime
from .common import BaseSchema

class WorkspaceSetup(BaseSchema):
    name: str = Field(..., min_length=3, max_length=100, example="pentest-2026")
    client_name: str = Field(..., min_length=2, max_length=100, example="Client Name")

class WorkspaceRead(BaseModel):
    id: int
    name: Optional[str] = None
    client_name: Optional[str] = None
    status: str = Field(..., json_schema_extra={"example": "active"})  # "active" | "empty"
    created_at: Optional[datetime] = None
    model_config = ConfigDict(from_attributes=True)