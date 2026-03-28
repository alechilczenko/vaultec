from typing import Annotated
from pydantic import Field

SQLITE_INT64_MAX = 9_223_372_036_854_775_807

SafeIntID = Annotated[int, Field(ge=1, le=SQLITE_INT64_MAX)]