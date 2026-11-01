"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from pydantic import BaseModel, ConfigDict, Field
from .common import SafeIntID

class UserRead(BaseModel):
    id: SafeIntID
    username: str = Field(..., max_length=50)
    model_config = ConfigDict(from_attributes=True)
