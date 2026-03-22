"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
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