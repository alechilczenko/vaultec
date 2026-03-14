"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from pydantic import BaseModel

class UserRead(BaseModel):
    id: int
    username: str

    class Config:
        from_attributes = True
