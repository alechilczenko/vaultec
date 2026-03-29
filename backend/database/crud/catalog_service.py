"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from fastapi import HTTPException
import database.models as models
import schemas

def pop_and_serialize_tags(kwargs: dict) -> str:
    tags = kwargs.pop("tags", [])
    if not tags:
        return ""
    if isinstance(tags, list):
        return ",".join(tags)
    return str(tags)

def get_all_definitions(db: Session):
    return db.query(models.VulnerabilityDefinition).all()

def get_definition_by_id(db: Session, def_id: int):
    return db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.id == def_id
    ).first()

def get_definition_or_404(db: Session, def_id: int):
    definition = get_definition_by_id(db, def_id)
    if not definition:
        raise HTTPException(
            status_code=404,
            detail=f"Catalog Error: Vulnerability definition with ID {def_id} not found."
        )
    return definition

def get_definition_by_title(db: Session, title: str):
    return db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.title.ilike(title.strip())
    ).first()

def save_definition(db: Session, new_def: models.VulnerabilityDefinition):
    db.add(new_def)
    try:
        db.commit()
        db.refresh(new_def)
        return new_def
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500, 
            detail=f"Database Error: Could not persist data. {str(e)}"
        )
    
def search_definitions(db: Session, query: str):
    return db.query(models.VulnerabilityDefinition).filter(models.VulnerabilityDefinition.title.ilike(f"%{query}%")).limit(10).all()

def create_definition_strict(db: Session, data: schemas.VulnerabilityCreate):
    existing = get_definition_by_title(db, data.title)
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Catalog Error: A definition with the title '{data.title.strip()}' already exists in the database.")
    
    tag_str = pop_and_serialize_tags({"tags": data.tags})
    
    new_def = models.VulnerabilityDefinition(
        title=data.title.strip(),
        severity=data.severity,
        description=data.description,
        recommendation=data.recommendation,
        tags=tag_str
    )
    return save_definition(db, new_def)

def get_or_create_definition(db: Session, def_id: int = None, title: str = None, **kwargs):
    if def_id:
        existing_by_id = get_definition_by_id(db, def_id)
        if existing_by_id:
            return existing_by_id    
    if title:
        existing_by_title = get_definition_by_title(db, title)
        if existing_by_title:
            return existing_by_title
    
    tag_str = pop_and_serialize_tags(kwargs)

    clean_title = title.strip() if title else title
    new_def = models.VulnerabilityDefinition(title=clean_title, tags=tag_str, **kwargs)
    return save_definition(db, new_def)

def update_definition(db: Session, def_id: int, update_data: dict):

    db_obj = get_definition_or_404(db, def_id)

    # Validates uniqueness of title to prevent IntegrityError
    if "title" in update_data:
        clean_title = update_data["title"].strip()
        existing = get_definition_by_title(db, clean_title)
        
        if existing and existing.id != db_obj.id:
            raise HTTPException(
                status_code=400, 
                detail=f"Catalog Conflict: The title '{clean_title}' is already in use by definition ID {existing.id}."
            )
        update_data["title"] = clean_title
    # Process tags
    if "tags" in update_data:
        update_data["tags"] = pop_and_serialize_tags(update_data)

    for key, value in update_data.items():
        setattr(db_obj, key, value)
    
    return save_definition(db, db_obj)

def import_definitions(db: Session, data: schemas.CatalogImport):
    # Handles bulk import and updates for definitions
    created_count = 0
    updated_count = 0

    for item in data.definitions:
        clean_title = item.title.strip()
        existing = get_definition_by_title(db, clean_title)
        tag_str = pop_and_serialize_tags({"tags": item.tags})

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

def delete_definition(db: Session, def_id: int):
    """
    Deletes a vulnerability definition and handles dependency conflicts.
    """
    db_obj = get_definition_or_404(db, def_id)
    title = db_obj.title
    try:
        db.delete(db_obj)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=(
                f"Catalog Dependency Error: Cannot delete '{title}'. "
                "There are active findings using this definition. "
                "Remove those findings first."
            )
        )
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Database Error: An unexpected error occurred while deleting the definition."
        )