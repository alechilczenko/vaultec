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


def save_definition(db: Session, new_def: models.VulnerabilityDefinition):

    def_title = new_def.title
    db.add(new_def)
    try:
        db.commit()
        db.refresh(new_def)
        logger.info(f"New definition saved to templates: '{def_title}'")
        return new_def
    except IntegrityError as exc:
        db.rollback()
        logger.warning(
            f"Definition save blocked by integrity conflict: '{def_title}' ({exc.orig})"
        )
        raise HTTPException(
            status_code=400,
            detail="Could not save this template (conflict).",
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
            models.VulnerabilityDefinition.category.ilike(pattern),
        )
    )
    total = filtered.count()
    return filtered.limit(10).all(), total


def create_definition(db: Session, data: schemas.TemplateEntryCreate):
    """Always inserts a new library template. Titles may duplicate."""
    new_def = models.VulnerabilityDefinition(
        title=data.title,
        severity=data.severity,
        category=data.category or "General",
        description=data.description,
        recommendation=data.recommendation,
        tags=data.tags
    )
    return save_definition(db, new_def)


# Back-compat alias used by routes / older call sites
create_definition_strict = create_definition


def create_definition_from_fields(
    db: Session,
    *,
    title: str,
    severity,
    category=None,
    description=None,
    recommendation=None,
    tags=None,
):
    """Insert a new definition from inline finding-create fields."""
    new_def = models.VulnerabilityDefinition(
        title=title,
        severity=severity,
        category=category or "General",
        description=description,
        recommendation=recommendation,
        tags=tags or [],
    )
    return save_definition(db, new_def)


def update_definition(db: Session, def_id: int, update_data: dict):

    db_obj = get_definition_or_404(db, def_id)

    for key, value in update_data.items():
        setattr(db_obj, key, value)

    return save_definition(db, db_obj)


def import_definitions(db: Session, data: schemas.TemplatesImport):
    """Existing ids are updated in place. Rows without a matching id are inserted."""
    created_ids = []
    updated_ids = []

    for item in data.templates:
        existing = get_definition_by_id(db, item.id) if item.id is not None else None

        if existing:
            existing.title = item.title
            existing.severity = item.severity
            existing.description = item.description
            existing.recommendation = item.recommendation
            existing.tags = item.tags
            if item.category is not None:
                existing.category = item.category
            updated_ids.append(existing.id)
        else:
            new_defn = models.VulnerabilityDefinition(
                title=item.title,
                severity=item.severity,
                category=item.category or "General",
                description=item.description,
                recommendation=item.recommendation,
                tags=item.tags
            )
            db.add(new_defn)
            db.flush()
            created_ids.append(new_defn.id)
            continue
        db.flush()
    try:
        db.commit()
        logger.info(
            f"Templates bulk import finished: "
            f"{len(created_ids)} created, {len(updated_ids)} updated"
        )
    except Exception:
        db.rollback()
        logger.exception("Failed to import templates")
        raise HTTPException(status_code=500, detail="Could not import these templates.")

    return {
        "message": "Templates import completed successfully.",
        "summary": {
            "created": len(created_ids),
            "updated": len(updated_ids),
            "total": len(data.templates)
        },
        "details": {
            "new_templates": created_ids,
            "updated_templates": updated_ids
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
