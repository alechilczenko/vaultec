"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import admin_service

router = APIRouter(prefix="/admin", tags=["Maintenance"])


@router.delete("/workspace/reset", status_code=status.HTTP_204_NO_CONTENT)
def reset_workspace(db: Session = Depends(get_db)):
    """
    Purges all active audit data (findings, assets, notes) and resets the 
    workspace context to empty. Preserves the global vulnerability catalog.
    """
    admin_service.reset_active_workspace(db)
    return None


@router.delete("/catalog", status_code=status.HTTP_204_NO_CONTENT)
def clear_global_catalog(db: Session = Depends(get_db)):
    """
    Wipes the global vulnerability catalog.
    Fails if the active workspace currently has findings referencing any catalog entry.
    """
    admin_service.clear_global_catalog(db)
    return None