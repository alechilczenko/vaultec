"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from database.db import get_db
from services import admin_service

router = APIRouter(prefix="/admin", tags=["Maintenance"])


@router.delete("/workspace/reset", status_code=status.HTTP_204_NO_CONTENT)
def reset_workspace(db: Session = Depends(get_db)):
    """Deletes findings, assets, and notes, then marks the workspace empty. Templates stay."""
    admin_service.reset_active_workspace(db)
    return None


@router.delete("/templates", status_code=status.HTTP_204_NO_CONTENT)
def clear_global_templates(db: Session = Depends(get_db)):
    """Deletes every template. Fails while any finding still references one."""
    admin_service.clear_global_templates(db)
    return None
