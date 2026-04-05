"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
from loguru import logger
import database.models as models

def clear_all_findings(db: Session):
    """
    Deletes all findings (vulnerabilities) from the database.
    """
    try:
        db.query(models.Vulnerability).delete()
        db.commit()
        logger.info("All findings have been cleared from the database")
    except Exception as e:
        db.rollback()
        logger.error(f"Could not clear findings: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear findings. Please check server logs")

def clear_all_assets(db: Session):
    """
    Deletes all assets. Requires no existing findings to maintain integrity.
    """
    # Check for dependent findings before attempting deletion
    if db.query(models.Vulnerability).count() > 0:
        logger.warning("Integrity check failed for asset deletion")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete assets. There are findings still linked to them.")
    try:
        db.query(models.Asset).delete()
        db.commit()
        logger.info("All assets have been cleared")
    except Exception as e:
        db.rollback()
        logger.info(f"Could not clear assets: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear assets due to an internal error.")

def clear_all_catalog(db: Session):
    """
    Deletes the entire vulnerability catalog. Requires no active findings.
    """
    # Check if catalog is being used
    if db.query(models.Vulnerability).count() > 0:
        logger.warning("Integrity check failed for catalog deletion")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot clear catalog. Definitions are referenced by existing findings.")
    try:
        db.query(models.VulnerabilityDefinition).delete()
        db.commit()
        logger.info("Catalog has been cleared")
    except Exception as e:
        db.rollback()
        logger.error(f"Could not clear catalog: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear catalog. Integrity constraints might be active.")

def clear_all_notes(db: Session):
    """
    Deletes all notes from the database.
    """
    try:
        db.query(models.Note).delete()
        db.commit()
        logger.info("All notes have been cleared")
    except Exception as e:
        db.rollback()
        logger.error(f"Could not clear notes: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear notes due to an internal error.")

def clear_everything(db: Session):
    """
    Nuclear option: Deletes all data across all tables in the correct order 
    to respect foreign key constraints.
    """
    try:
        db.query(models.Vulnerability).delete()
        db.query(models.Asset).delete()
        db.query(models.VulnerabilityDefinition).delete()
        db.query(models.Note).delete()
        db.commit()
        logger.info("Nuclear reset successful. All tables cleared")
    except Exception as e:
        db.rollback()
        logger.error(f"Could not perform nuclear reset: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to reset the database due to an internal error.")