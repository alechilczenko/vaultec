"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from pydantic import BaseModel, ConfigDict
from .common import SafeIntID

class UserRead(BaseModel):
    id: SafeIntID
    username: str

    model_config = ConfigDict(from_attributes=True)
