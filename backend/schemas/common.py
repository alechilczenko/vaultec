"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import Annotated, Any
from pydantic import Field, BaseModel, ConfigDict, StringConstraints, field_validator
import re

MAX_ID_VALUE = 1_000_000

SafeIntID = Annotated[int, Field(ge=1, le=MAX_ID_VALUE)]

# This handles global string cleaning (stripping and min length)
class BaseSchema(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        str_min_length=1,
        extra="forbid"
    )
    @field_validator("*", mode="before")
    @classmethod
    def sanitize_strings(cls, v, info):
        if isinstance(v, str):
            if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', v):
                raise ValueError("Null bytes or control characters are not allowed")
            return v.strip()
        return v
    
    @field_validator("*", mode="before")
    @classmethod
    def prevent_nulls(cls, v: Any, info):
        field_info = cls.model_fields.get(info.field_name)
        
        if field_info and field_info.is_required() and v is None:
            raise ValueError(f"The field '{info.field_name}' cannot be null")
            
        return v
# Specific type for list items (like tags) to prevent [" ", "valid"]
CleanString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

# Finding / catalog tags — short labels (cwe-89, owasp-a03)
TagString = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=24)
]