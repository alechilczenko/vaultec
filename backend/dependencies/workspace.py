"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import workspace_service
import database.models as models

ACTIVE_ASSESSMENT_REQUIRED_DETAIL = (
    "Active assessment required. Call POST /workspace/setup first."
)


def require_active_workspace(db: Session = Depends(get_db)) -> models.Workspace:
    """
    Ensures the single workspace row is in status "active" (Operate mode).
    Used to block engagement-scoped routes while the workspace is empty (library mode).
    """
    workspace = workspace_service.get_active_workspace(db)
    if workspace.status != "active":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ACTIVE_ASSESSMENT_REQUIRED_DETAIL,
        )
    return workspace
