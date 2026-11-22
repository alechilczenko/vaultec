"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from pydantic import BaseModel, Field
from .common import BaseSchema

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseSchema):
    username: str | None = Field(None, max_length=50)