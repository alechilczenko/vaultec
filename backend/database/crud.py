"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import List
from sqlalchemy.orm import Session
from sqlalchemy import func
from fastapi import HTTPException
import database.models as models

def get_or_create_definition(db: Session, title: str, severity: str, description: str, recommendation: str, tags: List[str]):
    # Search if exists
    defn = db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.title == title
    ).first()
    
    tags_string = ",".join(tags) if tags else None

    if not defn:
        defn = models.VulnerabilityDefinition(
            title=title,
            severity=severity,
            description=description,
            recommendation=recommendation,
            tags=tags_string
        )
        db.add(defn)
        db.commit()
        db.refresh(defn)
    return defn

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

def format_vulnerability_grouped(defn):
    """
    Helper function to transform a database definition object 
    into a dictionary structure for the API response.
    """
    tags_list = [tag.strip() for tag in defn.tags.split(",")] if defn.tags else []

    return {
        "id": defn.id,
        "title": defn.title,
        "severity": defn.severity,
        "description": defn.description,
        "recommendation": defn.recommendation,
        "tags": tags_list,
        "instances": defn.instances
    }

def get_severity_stats(db: Session):
    # Query to group by severity and count occurrences
    stats = db.query(
        models.VulnerabilityDefinition.severity,
        func.count(models.VulnerabilityDefinition.id)
    ).group_by(models.VulnerabilityDefinition.severity).all()
    
    # Transform list of tuples into a clean dictionary
    return {severity: count for severity, count in stats}