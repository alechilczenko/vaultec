from pydantic import BaseModel, Field
from typing import Optional

class NoteCreate(BaseModel):
    # Field(...) means it is required
    # min_length=1 prevents empty strings
    # strip_whitespace=True prevents strings with only spaces
    title: str = Field(..., min_length=1, strip_whitespace=True)
    content: str = Field(..., min_length=1, strip_whitespace=True)

class NoteRead(BaseModel):
    id: int
    title: str
    content: str

    class Config:
        from_attributes = True

class NoteUpdate(BaseModel):
    # Optional[] allows the field to be missing in the request
    # Field(None, ...) sets the default to None if not provided
    title: Optional[str] = Field(None, min_length=1, strip_whitespace=True)
    content: Optional[str] = Field(None, min_length=1, strip_whitespace=True)

    class Config:
        from_attributes = True