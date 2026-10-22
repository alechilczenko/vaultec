"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import EvidenceType

MAX_EVIDENCE_ITEMS = 10
MAX_EVIDENCE_BYTES = 65536
MAX_EVIDENCE_LABEL = 80

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _reject_controls(value: str) -> str:
    if _CONTROL_CHARS.search(value):
        raise ValueError("Null bytes or control characters are not allowed")
    return value


class EvidenceItem(BaseModel):
    """One field inside a package. The package owns the type."""

    model_config = ConfigDict(extra="forbid")

    label: str = Field(default="", max_length=MAX_EVIDENCE_LABEL)
    content: str = Field(..., min_length=1)

    @field_validator("label", mode="before")
    @classmethod
    def clean_label(cls, value: Any) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            raise ValueError("Evidence label must be a string")
        return _reject_controls(value).strip()

    @field_validator("content", mode="before")
    @classmethod
    def clean_content(cls, value: Any) -> str:
        if not isinstance(value, str):
            raise ValueError("Evidence content must be a string")
        text = _reject_controls(value)
        if not text.strip():
            raise ValueError("Evidence content cannot be blank")
        return text


class EvidencePackage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: EvidenceType
    items: list[EvidenceItem] = Field(..., min_length=1, max_length=MAX_EVIDENCE_ITEMS)


class Evidence(BaseModel):
    """Typed packages attached to a finding. The finding itself has no evidence type."""

    model_config = ConfigDict(extra="forbid")

    packages: list[EvidencePackage] = Field(..., min_length=1, max_length=MAX_EVIDENCE_ITEMS)

    @model_validator(mode="after")
    def enforce_limits(self) -> "Evidence":
        total = sum(len(package.items) for package in self.packages)
        if total > MAX_EVIDENCE_ITEMS:
            raise ValueError(f"Evidence has too many items (max {MAX_EVIDENCE_ITEMS})")
        payload = json.dumps(self.model_dump(mode="json"))
        if len(payload) > MAX_EVIDENCE_BYTES:
            raise ValueError("Evidence data is too large")
        return self
