"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

import enum

class SeverityEnum(str, enum.Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    REMEDIATED = "remediated"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"

class EvidenceType(str, enum.Enum):
    HTTP = "http"       # Requests, responses, headers
    GENERAL = "general"  # Default for text or mixed data