"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from fastapi import HTTPException
from loguru import logger
import database.models as models
import schemas


def get_template_stats(db: Session):
    severity_order = ["critical", "high", "medium", "low", "info"]

    severity_rows = db.query(
        models.VulnerabilityDefinition.severity,
        func.count(models.VulnerabilityDefinition.id)
    ).group_by(
        models.VulnerabilityDefinition.severity
    ).all()

    category_rows = db.query(
        models.VulnerabilityDefinition.category,
        func.count(models.VulnerabilityDefinition.id)
    ).group_by(
        models.VulnerabilityDefinition.category
    ).all()

    severity_map = {severity: count for severity, count in severity_rows}

    return {
        "by_severity": {sev: severity_map.get(sev, 0) for sev in severity_order},
        "by_category": {category: count for category, count in category_rows},
    }


def get_all_definitions(db: Session, skip: int = 0, limit: int = 100):
    """Returns (templates, total). total ignores skip and limit."""
    total = db.query(func.count(models.VulnerabilityDefinition.id)).scalar() or 0
    templates = (
        db.query(models.VulnerabilityDefinition).offset(skip).limit(limit).all()
    )
    return templates, total

def get_definition_by_id(db: Session, def_id: int):
    return db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.id == def_id
    ).first()

def get_definition_or_404(db: Session, def_id: int):
    definition = get_definition_by_id(db, def_id)
    if not definition:
        raise HTTPException(
            status_code=404,
            detail=f"Template {def_id} was not found."
        )
    return definition

def get_definition_by_title(db: Session, title: str):
    return db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.title.ilike(title.strip())
    ).first()

def save_definition(db: Session, new_def: models.VulnerabilityDefinition):

    def_title = new_def.title
    db.add(new_def)
    try:
        db.commit()
        db.refresh(new_def)
        logger.info(f"New definition saved to templates: '{def_title}'")
        return new_def
    except Exception:
        db.rollback()
        logger.exception(f"Failed to save definition: '{def_title}'")
        raise HTTPException(
            status_code=500,
            detail="Could not save this template.",
        )
    
def search_definitions(db: Session, query: str):
    """Returns (templates, total). Rows cap at 10. total does not."""
    pattern = f"%{query}%"
    filtered = db.query(models.VulnerabilityDefinition).filter(
        or_(
            models.VulnerabilityDefinition.title.ilike(pattern),
            models.VulnerabilityDefinition.category.ilike(pattern),
        )
    )
    total = filtered.count()
    return filtered.limit(10).all(), total

def create_definition_strict(db: Session, data: schemas.TemplateEntryCreate):

    title = data.title.strip()
    existing = get_definition_by_title(db, data.title)
    
    if existing:
        logger.warning(f"Definition creation blocked: '{title}' already exists in templates")
        raise HTTPException(
            status_code=400,
            detail=f"A template titled '{title}' already exists.",
        )

    new_def = models.VulnerabilityDefinition(
        title=data.title.strip(),
        severity=data.severity,
        category=data.category or "General",
        description=data.description,
        recommendation=data.recommendation,
        tags=data.tags
    )
    return save_definition(db, new_def)

def get_or_create_definition(db: Session, title: str, **kwargs):

    clean_title = title.strip()
    existing = get_definition_by_title(db, clean_title)
    if existing:
        return existing

    if kwargs.get("category") is None:
        kwargs.pop("category", None)

    new_def = models.VulnerabilityDefinition(title=clean_title, **kwargs)
    return save_definition(db, new_def)

def update_definition(db: Session, def_id: int, update_data: dict):

    db_obj = get_definition_or_404(db, def_id)

    if "title" in update_data:
        clean_title = update_data["title"].strip()
        existing = get_definition_by_title(db, clean_title)
        
        if existing and existing.id != db_obj.id:
            logger.warning(f"Template update blocked: Title '{clean_title}' already exists (ID: {existing.id})")
            raise HTTPException(
                status_code=400, 
                detail=f"A template titled '{clean_title}' already exists."
            )
        update_data["title"] = clean_title

    for key, value in update_data.items():
        setattr(db_obj, key, value)
    
    return save_definition(db, db_obj)

def import_definitions(db: Session, data: schemas.TemplatesImport):
    """Existing titles are updated in place. New titles are inserted."""
    created_titles = []
    updated_titles = []

    for item in data.templates:
        clean_title = item.title.strip()
        existing = get_definition_by_title(db, clean_title)

        if existing:
            existing.title = clean_title
            existing.severity = item.severity
            existing.description = item.description
            existing.recommendation = item.recommendation
            existing.tags = item.tags
            if item.category is not None:
                existing.category = item.category
            updated_titles.append(clean_title)
        else:
            new_defn = models.VulnerabilityDefinition(
                title=clean_title,
                severity=item.severity,
                category=item.category or "General",
                description=item.description,
                recommendation=item.recommendation,
                tags=item.tags
            )
            db.add(new_defn)
            created_titles.append(clean_title)
        db.flush()
    try:
        db.commit()
        logger.info(f"Templates bulk import finished: {len(created_titles)} created, {len(updated_titles)} updated")
    except Exception:
        db.rollback()
        logger.exception("Failed to import templates")
        raise HTTPException(status_code=500, detail="Could not import these templates.")

    return {
        "message": "Templates import completed successfully.",
        "summary": {
            "created": len(created_titles),
            "updated": len(updated_titles),
            "total": len(data.templates)
        },
        "details": {
            "new_templates": created_titles,
            "updated_templates": updated_titles
        }
    }

def delete_definition(db: Session, def_id: int):
    db_obj = get_definition_or_404(db, def_id)
    title = db_obj.title
    try:
        db.delete(db_obj)
        db.commit()
        logger.info(f"Definition: '{title}' (ID: {def_id}) deleted from templates")
    except IntegrityError:
        db.rollback()
        logger.warning(f"Deletion blocked: Definition '{title}' is in use by active findings")
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete '{title}' until its findings are removed."
        )
    except Exception:
        db.rollback()
        logger.exception(f"Failed to delete template '{title}'")
        raise HTTPException(
            status_code=500,
            detail="Could not delete this template."
        )
