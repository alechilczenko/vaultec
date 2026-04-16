"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from loguru import logger
import database.models as models

def clear_project_findings(db: Session, project_id: int):
    """Deletes all findings for a specific project."""
    try:
        db.query(models.Vulnerability).filter(models.Vulnerability.project_id == project_id).delete()
        db.commit()
        logger.info(f"All findings cleared for project {project_id}")
    except Exception as e:
        db.rollback()
        logger.error(f"Error clearing findings for project {project_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Error clearing project findings.")

def clear_project_assets(db: Session, project_id: int):
    """Deletes all assets for a specific project. Checks for active findings first."""
    has_findings = db.query(models.Vulnerability).filter(models.Vulnerability.project_id == project_id).first()
    if has_findings:
        raise HTTPException(
            status_code=400, 
            detail="Cannot clear assets. There are findings still linked to them in this project.")
    try:
        db.query(models.Asset).filter(models.Asset.project_id == project_id).delete()
        db.commit()
        logger.info(f"All assets cleared for project {project_id}")
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Error clearing project assets.")

def clear_project_notes(db: Session, project_id: int):
    """
    Removes all notes linked to a specific project.
    """
    try:
        db.query(models.Note).filter(models.Note.project_id == project_id).delete()
        db.commit()
        logger.info(f"All notes cleared for Project {project_id}")
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to clear notes for Project {project_id}: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail="Internal Server Error: Could not clear project notes."
        )

def nuclear_project_reset(db: Session, project_id: int):
    """Nuclear option: Clears everything (Findings, Notes, Assets) for ONE project."""
    try:
        db.query(models.Vulnerability).filter(models.Vulnerability.project_id == project_id).delete()
        db.query(models.Note).filter(models.Note.project_id == project_id).delete()
        db.query(models.Asset).filter(models.Asset.project_id == project_id).delete()
        db.commit()
        logger.warning(f"Nuclear reset performed for project {project_id}")
    except Exception as e:
        db.rollback()
        logger.error(f"Nuclear reset failed for project {project_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Critical error during project reset.")

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