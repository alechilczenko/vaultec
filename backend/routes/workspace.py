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


@router.post("/setup", response_model=schemas.WorkspaceRead, status_code=status.HTTP_200_OK)
def setup_workspace(data: schemas.WorkspaceSetup, db: Session = Depends(get_db)):
    """
    Initializes or updates the client context for the active audit workspace.
    """
    return workspace_service.setup_workspace(db, data)