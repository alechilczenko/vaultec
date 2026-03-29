"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import Annotated
from pydantic import Field

MAX_ID_VALUE = 10_000

SafeIntID = Annotated[int, Field(ge=1, le=MAX_ID_VALUE)]