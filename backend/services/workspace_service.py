"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from loguru import logger
import database.models as models
import schemas


def get_active_workspace(db: Session) -> models.Workspace:
    """Creates the id=1 row as empty when it is missing."""
    workspace = db.query(models.Workspace).filter(models.Workspace.id == 1).first()
    if not workspace:
        workspace = models.Workspace(id=1, status="empty")
        db.add(workspace)
        db.commit()
        db.refresh(workspace)
    return workspace


ASSESSMENT_ALREADY_ACTIVE_DETAIL = (
    "Assessment already active. Reset the workspace before setting up a new one."
)


def setup_workspace(db: Session, workspace_data: schemas.WorkspaceSetup) -> models.Workspace:
    """409 when status is already active. Reset before setup."""
    workspace = get_active_workspace(db)

    if workspace.status == "active":
        logger.warning("Workspace setup blocked: assessment already active")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=ASSESSMENT_ALREADY_ACTIVE_DETAIL,
        )

    workspace.name = workspace_data.name
    workspace.client_name = workspace_data.client_name
    workspace.status = "active"

    try:
        db.commit()
        db.refresh(workspace)
        logger.info(f"Workspace initialized for client: '{workspace.client_name}' ({workspace.name})")
        return workspace
    except Exception:
        db.rollback()
        logger.exception("Failed to set up the assessment")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not set up the assessment."
        )