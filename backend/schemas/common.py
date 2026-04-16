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
    def sanitize_strings(cls, v):
        if isinstance(v, str):
            if re.search(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', v):
                raise ValueError("Null bytes or control characters are not allowed")
            return v.strip()
    
    @field_validator("*", mode="before")
    @classmethod
    def prevent_nulls(cls, v: Any, info):
        # info.field_name gives us the name of the field being validated
        # We block explicit None (null) values from the JSON payload
        if v is None:
            raise ValueError(f"The field '{info.field_name}' cannot be null")
        return v
# Specific type for list items (like tags) to prevent [" ", "valid"]
CleanString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]