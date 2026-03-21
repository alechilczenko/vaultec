"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

import enum

class SeverityEnum(str, enum.Enum):
    informative = "informative"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

class FindingStatus(str, enum.Enum):
    OPEN = "open"               
    IN_PROGRESS = "in_progress" 
    CONFIRMED = "confirmed"     
    REMEDIATED = "remediated"   
    VERIFIED = "verified"      
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"