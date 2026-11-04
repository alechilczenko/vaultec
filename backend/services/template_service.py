"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from datetime import datetime, timezone
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy import or_, func
from fastapi import HTTPException
from loguru import logger
import database.models as models
import schemas
from utils.slug import slugify


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


def list_definitions_for_export(db: Session) -> list[models.VulnerabilityDefinition]:
    """All library templates, ordered by title (no pagination)."""
    return (
        db.query(models.VulnerabilityDefinition)
        .order_by(models.VulnerabilityDefinition.title.asc())
        .all()
    )


def build_templates_export(db: Session) -> dict:
    """Library export envelope: all definitions (no workspace header)."""
    templates = list_definitions_for_export(db)
    return {
        "exported_at": datetime.now(timezone.utc),
        "templates": templates,
        "total": len(templates),
    }


def export_download_filename(payload: dict) -> str:
    """Build Content-Disposition filename: templates-{YYYY-MM-DD}.json."""
    exported_at = payload.get("exported_at") or datetime.now(timezone.utc)
    if isinstance(exported_at, str):
        day = exported_at[:10]
    else:
        day = exported_at.strftime("%Y-%m-%d")
    return f"templates-{day}.json"


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

def get_definition_by_slug(db: Session, slug: str):
    clean_slug = slugify(slug)
    if not clean_slug:
        return None
    return db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.slug == clean_slug
    ).first()

def save_definition(db: Session, new_def: models.VulnerabilityDefinition):

    def_title = new_def.title
    db.add(new_def)
    try:
        db.commit()
        db.refresh(new_def)
        logger.info(f"New definition saved to templates: '{def_title}'")
        return new_def
    except IntegrityError:
        db.rollback()
        logger.warning(f"Definition save blocked by unique constraint: '{def_title}'")
        raise HTTPException(
            status_code=400,
            detail=f"A template with slug '{new_def.slug}' already exists.",
        )
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
            models.VulnerabilityDefinition.slug.ilike(pattern),
            models.VulnerabilityDefinition.category.ilike(pattern),
        )
    )
    total = filtered.count()
    return filtered.limit(10).all(), total

def create_definition_strict(db: Session, data: schemas.TemplateEntryCreate):

    existing = get_definition_by_slug(db, data.slug)
    
    if existing:
        logger.warning(f"Definition creation blocked: slug '{data.slug}' already exists")
        raise HTTPException(
            status_code=400,
            detail=f"A template with slug '{data.slug}' already exists.",
        )

    new_def = models.VulnerabilityDefinition(
        title=data.title,
        slug=data.slug,
        severity=data.severity,
        category=data.category or "General",
        description=data.description,
        recommendation=data.recommendation,
        tags=data.tags
    )
    return save_definition(db, new_def)

def get_or_create_definition(db: Session, title: str, slug: str | None = None, **kwargs):

    clean_slug = slugify(slug) if slug else slugify(title)
    if not clean_slug:
        raise HTTPException(
            status_code=400,
            detail="Could not derive a valid slug from title.",
        )

    existing = get_definition_by_slug(db, clean_slug)
    if existing:
        return existing

    if kwargs.get("category") is None:
        kwargs.pop("category", None)

    new_def = models.VulnerabilityDefinition(
        title=title,
        slug=clean_slug,
        **kwargs,
    )
    return save_definition(db, new_def)

def update_definition(db: Session, def_id: int, update_data: dict):

    db_obj = get_definition_or_404(db, def_id)
    # Slug is immutable — never accept it on PATCH (schema also forbids it).
    update_data.pop("slug", None)

    for key, value in update_data.items():
        setattr(db_obj, key, value)

    return save_definition(db, db_obj)

def import_definitions(db: Session, data: schemas.TemplatesImport):
    """Existing slugs are updated in place. New slugs are inserted."""
    created_slugs = []
    updated_slugs = []

    for item in data.templates:
        existing = get_definition_by_slug(db, item.slug)

        if existing:
            existing.title = item.title
            existing.severity = item.severity
            existing.description = item.description
            existing.recommendation = item.recommendation
            existing.tags = item.tags
            if item.category is not None:
                existing.category = item.category
            updated_slugs.append(existing.slug)
        else:
            new_defn = models.VulnerabilityDefinition(
                title=item.title,
                slug=item.slug,
                severity=item.severity,
                category=item.category or "General",
                description=item.description,
                recommendation=item.recommendation,
                tags=item.tags
            )
            db.add(new_defn)
            created_slugs.append(item.slug)
        db.flush()
    try:
        db.commit()
        logger.info(
            f"Templates bulk import finished: "
            f"{len(created_slugs)} created, {len(updated_slugs)} updated"
        )
    except Exception:
        db.rollback()
        logger.exception("Failed to import templates")
        raise HTTPException(status_code=500, detail="Could not import these templates.")

    return {
        "message": "Templates import completed successfully.",
        "summary": {
            "created": len(created_slugs),
            "updated": len(updated_slugs),
            "total": len(data.templates)
        },
        "details": {
            "new_templates": created_slugs,
            "updated_templates": updated_slugs
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
