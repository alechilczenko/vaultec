"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import Annotated
from pydantic import Field, BaseModel, ConfigDict, StringConstraints

MAX_ID_VALUE = 1_000_000

SafeIntID = Annotated[int, Field(ge=1, le=MAX_ID_VALUE)]

# This handles global string cleaning (stripping and min length)
class BaseSchema(BaseModel):
    model_config = ConfigDict(
        str_strip_whitespace=True,
        str_min_length=1
    )

# Specific type for list items (like tags) to prevent [" ", "valid"]
CleanString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]