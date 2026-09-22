"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from loguru import logger
import database.models as models

def reset_active_workspace(db: Session):
    """
    Clears all active audit data (findings, notes, assets) and resets 
    the workspace state to empty. Preserves the global catalog.
    """
    try:
        # 1. Clear active audit data
        db.query(models.Vulnerability).delete()
        db.query(models.Note).delete()
        db.query(models.Asset).delete()

        # 2. Reset workspace state
        workspace = db.query(models.Workspace).filter(models.Workspace.id == 1).first()
        if workspace:
            workspace.name = None
            workspace.client_name = None
            workspace.status = "empty"

        db.commit()
        logger.warning("Active workspace cleared and reset to empty state.")
    except Exception as e:
        db.rollback()
        logger.error(f"Critical error during workspace reset: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Critical error while resetting active workspace."
        )

def clear_global_catalog(db: Session):
    """
    Removes all definitions from the global catalog.
    This will fail if ANY project has a finding linked to a definition.
    """
    try:
        db.query(models.VulnerabilityDefinition).delete()
        db.commit()
        logger.warning("Global vulnerability catalog has been cleared.")
    except Exception as e:
        db.rollback()
        logger.error(f"Catalog clear failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Catalog is in use. Delete all findings across all projects first."
        )