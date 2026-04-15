"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from pydantic import BaseModel, ConfigDict, Field
from typing import List
from datetime import datetime

class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=100, example="pentest-2026")
    client_name: str = Field(..., min_length=2, max_length=100, example="Client Name")

class ProjectRead(BaseModel):
    id: int
    name: str
    client_name: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class ProjectList(BaseModel):
    projects: List[ProjectRead]