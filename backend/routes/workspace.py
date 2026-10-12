"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import workspace_service
import schemas

router = APIRouter(
    prefix="/workspace",
    tags=["Workspace"]
)

@router.get("", response_model=schemas.WorkspaceRead)
def get_workspace_status(db: Session = Depends(get_db)):
    """
    Retrieves the current active workspace status and audit metadata.
    """
    return workspace_service.get_active_workspace(db)


@router.post(
    "/setup",
    response_model=schemas.WorkspaceRead,
    status_code=status.HTTP_200_OK,
    responses={
        409: {
            "description": "Assessment already active; reset before setup.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Assessment already active. Reset the workspace before setting up a new one."
                    }
                }
            },
        }
    },
)
def setup_workspace(data: schemas.WorkspaceSetup, db: Session = Depends(get_db)):
    """
    Initializes the empty workspace as an active assessment (name + client).
    Returns 409 if an assessment is already active — call DELETE /admin/workspace/reset first.
    """
    return workspace_service.setup_workspace(db, data)