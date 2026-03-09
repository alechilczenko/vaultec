import enum

class SeverityEnum(str, enum.Enum):
    informative = "informative"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
