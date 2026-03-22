"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException
import database.models as models
import schemas

def get_all_definitions(db: Session):
    return db.query(models.VulnerabilityDefinition).all()

def get_definition_by_id(db: Session, def_id: int):
    return db.query(models.VulnerabilityDefinition).filter(models.VulnerabilityDefinition.id == def_id).first()

def search_definitions(db: Session, query: str):
    return db.query(models.VulnerabilityDefinition).filter(models.VulnerabilityDefinition.title.ilike(f"%{query}%")).limit(10).all()

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

def update_definition(db: Session, db_obj: models.VulnerabilityDefinition, update_data: dict):
    # Validates uniqueness of title to prevent IntegrityError
    if "title" in update_data:
        new_title = update_data["title"].strip()
        existing = db.query(models.VulnerabilityDefinition).filter(
            models.VulnerabilityDefinition.title.ilike(new_title),
            models.VulnerabilityDefinition.id != db_obj.id
        ).first()
        
        if existing:
            raise HTTPException(
                status_code=400, 
                detail=f"A definition with title '{new_title}' already exists."
            )
        update_data["title"] = new_title
    # Process tags
    if "tags" in update_data and isinstance(update_data["tags"], list):
        update_data["tags"] = ",".join(update_data["tags"])

    for key, value in update_data.items():
        setattr(db_obj, key, value)
    try:
        db.commit()
        db.refresh(db_obj)
        return db_obj
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Internal database error during update.")

def import_definitions(db: Session, data: schemas.CatalogImport):
    # Handles bulk import and updates for definitions
    created_count = 0
    updated_count = 0

    for item in data.definitions:
        clean_title = item.title.strip()
        existing = db.query(models.VulnerabilityDefinition).filter(models.VulnerabilityDefinition.title.ilike(clean_title)).first()
        tag_str = ",".join(item.tags) if item.tags else ""

        if existing:
            existing.title = clean_title
            existing.severity = item.severity
            existing.description = item.description
            existing.recommendation = item.recommendation
            existing.tags = tag_str
            updated_count += 1
        else:
            new_defn = models.VulnerabilityDefinition(
                title=clean_title,
                severity=item.severity,
                description=item.description,
                recommendation=item.recommendation,
                tags=tag_str
            )
            db.add(new_defn)
            created_count += 1
        db.flush()
    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error during import: {str(e)}")

    return {
        "status": "success",
        "details": {
            "created": created_count,
            "updated": updated_count,
            "total_processed": len(data.definitions)
        }
    }

def delete_definition(db: Session, db_obj: models.VulnerabilityDefinition):
    db.delete(db_obj)
    db.commit()