"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from sqlalchemy import func
from fastapi import HTTPException
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