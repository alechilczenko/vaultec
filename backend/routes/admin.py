"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import admin_service
from schemas.common import SafeIntID

from dependencies.project import validate_project

router = APIRouter(prefix="/admin", tags=["Maintenance"])

@router.delete("/projects/{project_id}/findings", status_code=status.HTTP_204_NO_CONTENT)
def clear_project_findings(project_id: SafeIntID, db: Session = Depends(get_db), valid_project = Depends(validate_project)):
    """
    Removes all findings for a specific project while keeping assets.
    """
    admin_service.clear_project_findings(db, project_id)
    return None

@router.delete("/projects/{project_id}/assets", status_code=status.HTTP_204_NO_CONTENT)
def clear_project_assets(project_id: SafeIntID, db: Session = Depends(get_db), valid_project = Depends(validate_project)):
    """
    Removes all assets for a project (only if findings are cleared first).
    """
    admin_service.clear_project_assets(db, project_id)
    return None

@router.delete("/projects/{project_id}/notes", status_code=status.HTTP_204_NO_CONTENT)
def clear_project_notes(
    project_id: SafeIntID, 
    db: Session = Depends(get_db),
    valid_project = Depends(validate_project)
):
    """
    Deletes all notes for a specific project.
    Validates project existence before execution.
    """
    admin_service.clear_project_notes(db, project_id)
    return None

@router.delete("/projects/{project_id}/nuclear-reset", status_code=status.HTTP_204_NO_CONTENT)
def nuclear_reset(project_id: SafeIntID, db: Session = Depends(get_db), valid_project = Depends(validate_project)):
    """
    Wipes all findings, notes, and assets for a specific project.
    """
    admin_service.nuclear_project_reset(db, project_id)
    return None

@router.delete("/catalog", status_code=status.HTTP_204_NO_CONTENT)
def clear_global_catalog(db: Session = Depends(get_db)):
    """
    Wipes the global catalog. This operation is global and cross-project.
    """
    admin_service.clear_global_catalog(db)
    return None