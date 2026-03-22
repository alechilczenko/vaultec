"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from sqlalchemy import func
from fastapi import HTTPException, status
import database.models as models

def get_or_create_definition(db: Session, def_id: int = None, title: str = None, **kwargs):
    # Get definition by ID
    if def_id:
        existing_by_id = db.query(models.VulnerabilityDefinition).filter(models.VulnerabilityDefinition.id == def_id).first()
        if existing_by_id:
            return existing_by_id
    
    # If user selects title, filter
    if title:
        existing_by_title = db.query(models.VulnerabilityDefinition).filter(
            models.VulnerabilityDefinition.title.ilike(title.strip())
        ).first()
        if existing_by_title:
            return existing_by_title
    
    new_def = models.VulnerabilityDefinition(title=title, **kwargs)
    db.add(new_def)
    db.commit()
    db.refresh(new_def)
    return new_def

def get_or_create_finding(db: Session, def_id: int, asset_id: int, vulnerability_data: dict):
    """
    Checks if an open finding already exists for the given asset and definition.
    If it exists, raises a 400 error. Otherwise, creates a new one.
    """
    # 1. Look for an existing open finding
    existing_finding = db.query(models.Vulnerability).filter(
        models.Vulnerability.definition_id == def_id,
        models.Vulnerability.asset_id == asset_id
    ).first()

    if existing_finding:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Duplicate finding: Asset {asset_id} already has this vulnerability."
        )

    # 2. If no duplicate, create the new instance
    new_finding = models.Vulnerability(
        definition_id=def_id,
        asset_id=asset_id,
        **vulnerability_data
    )
    
    try:
        db.add(new_finding)
        db.commit()
        db.refresh(new_finding)
        return new_finding
    except Exception as e:
        db.rollback()
        print(f"ERROR: Database failure while creating finding. {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal database error during finding creation."
        )

def get_note_or_404(db: Session, note_id: int):
    """
    Fetch a note from the database or raise a 404 error if it doesn't exist.
    """
    # Perform the database query
    db_note = db.query(models.Note).filter(models.Note.id == note_id).first()
    
    if not db_note:
        # Stop execution and return the error to the client
        raise HTTPException(status_code=404, detail="Note not found")
    
    return db_note

def get_severity_stats(db: Session):
    # Query to group by severity and count occurrences
    stats = db.query(
        models.VulnerabilityDefinition.severity,
        func.count(models.VulnerabilityDefinition.id)
    ).group_by(models.VulnerabilityDefinition.severity).all()
    
    # Transform list of tuples into a clean dictionary
    return {severity: count for severity, count in stats}