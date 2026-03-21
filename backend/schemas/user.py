"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from pydantic import BaseModel, ConfigDict

class UserRead(BaseModel):
    id: int
    username: str

    model_config = ConfigDict(from_attributes=True)
