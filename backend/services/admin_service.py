"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from loguru import logger
import database.models as models

TEMPLATES_IN_USE_DETAIL = (
    "Templates are in use. Reset the workspace or delete all findings first, then try again."
)

def reset_active_workspace(db: Session):
    """Findings, notes, and assets are deleted. Global templates stay."""
    try:
        db.query(models.Vulnerability).delete()
        db.query(models.Note).delete()
        db.query(models.Asset).delete()

        workspace = db.query(models.Workspace).filter(models.Workspace.id == 1).first()
        if workspace:
            workspace.name = None
            workspace.client_name = None
            workspace.status = "empty"

        db.commit()
        logger.warning("Active workspace cleared and reset to empty state.")
    except Exception:
        db.rollback()
        logger.exception("Failed to reset the workspace")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not reset the workspace."
        )

def clear_global_templates(db: Session):
    """400 when a finding still references a definition."""
    try:
        db.query(models.VulnerabilityDefinition).delete()
        db.commit()
        logger.warning("Template library cleared.")
    except IntegrityError:
        db.rollback()
        logger.warning("Templates clear blocked: definitions still referenced by findings")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=TEMPLATES_IN_USE_DETAIL,
        )
    except Exception:
        db.rollback()
        logger.exception("Failed to clear the template library")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not clear the template library.",
        )
