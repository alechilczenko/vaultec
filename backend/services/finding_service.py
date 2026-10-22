"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status
import database.models as models
import schemas
from schemas.enums import FindingStatus
from services import template_service, asset_service
from loguru import logger


def _prepare_finding_read(db: Session, finding: models.Vulnerability) -> models.Vulnerability:
    """Ensures nested asset carries findings_count and max_severity for AssetRead."""
    if finding.asset is not None:
        asset_service.attach_finding_summary(db, finding.asset)
    return finding


def _duplicate_finding_detail(asset_name: str, definition_title: str) -> str:
    return (
        f"Duplicate Finding: The asset '{asset_name}' already has an active record "
        f"for '{definition_title}'. Duplicate prevented."
    )


def _raise_duplicate_finding(asset_name: str, definition_title: str) -> None:
    logger.warning(
        f"Duplicate finding blocked: '{definition_title}' already present on '{asset_name}'"
    )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=_duplicate_finding_detail(asset_name, definition_title),
    )


def update_finding(db: Session, db_obj: models.Vulnerability, update_data: dict):
    finding_id = db_obj.id
    finding_title = db_obj.definition.title if db_obj.definition else "Unknown Title"

    try:
        for key, value in update_data.items():
            setattr(db_obj, key, value)
        
        db.commit()
        db.refresh(db_obj)
        logger.info(f"Finding updated: '{finding_title}' (ID: {finding_id})")
        return _prepare_finding_read(db, db_obj)
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update finding: '{finding_title}' (ID: {finding_id}): {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Update Error: Could not update finding ID {finding_id}. Check if the data format is correct."
        )

def delete_finding(db: Session, db_obj: models.Vulnerability):
    finding_id = db_obj.id
    vuln_title = db_obj.definition.title if db_obj.definition else "Unknown Title"
    asset_name = db_obj.asset.name if db_obj.asset else "Unknown Asset"

    try:
        db.delete(db_obj)
        db.commit()
        logger.info(f"Finding deleted: '{vuln_title}' on Asset '{asset_name}' (ID: {finding_id})")
        return True 
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to delete finding '{vuln_title}' (ID: {finding_id}): {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Database Error: Could not delete finding ID {finding_id}. Transaction rolled back."
        )
    
def get_finding_stats(db: Session):
    severity_order = ["critical", "high", "medium", "low", "info"]
    status_order = [s.value for s in FindingStatus]

    severity_rows = db.query(
        models.VulnerabilityDefinition.severity,
        func.count(models.Vulnerability.id)
    ).join(
        models.Vulnerability,
        models.Vulnerability.definition_id == models.VulnerabilityDefinition.id
    ).group_by(
        models.VulnerabilityDefinition.severity
    ).all()

    status_rows = db.query(
        models.Vulnerability.status,
        func.count(models.Vulnerability.id)
    ).group_by(
        models.Vulnerability.status
    ).all()

    severity_map = {severity: count for severity, count in severity_rows}
    status_map = {status: count for status, count in status_rows}

    return {
        "by_severity": {sev: severity_map.get(sev, 0) for sev in severity_order},
        "by_status": {st: status_map.get(st, 0) for st in status_order},
    }

def get_finding_by_id(db: Session, finding_id: int):
    finding = db.query(models.Vulnerability).filter(
        models.Vulnerability.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=404,
            detail=f"Finding Error: Vulnerability instance with ID {finding_id} not found."
        )
    return _prepare_finding_read(db, finding)

def get_or_create_finding(db: Session, defn: models.VulnerabilityDefinition, asset: models.Asset, vulnerability_data: dict):
    """400 if any finding already exists for that pair, including closed ones.
    Concurrent inserts collide on uq_vulnerability_definition_asset.
    """
    existing_finding = db.query(models.Vulnerability).filter(
        models.Vulnerability.definition_id == defn.id,
        models.Vulnerability.asset_id == asset.id
    ).first()

    if existing_finding:
        _raise_duplicate_finding(asset.name, defn.title)

    new_finding = models.Vulnerability(
        definition_id=defn.id,
        asset_id=asset.id,
        **vulnerability_data
    )
    try:
        db.add(new_finding)
        db.commit()
        db.refresh(new_finding)
        logger.info(f"New finding created: '{defn.title}' on '{asset.name}'")
        return _prepare_finding_read(db, new_finding)

    except IntegrityError:
        db.rollback()
        _raise_duplicate_finding(asset.name, defn.title)

    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist finding for Asset '{asset.name}': {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database Error: Failed to persist the new finding. Transaction rolled back."
        )

def process_vulnerability_entry(db: Session, vuln_data: schemas.VulnerabilityCreate):
    """Shared by POST /findings/create and POST /findings/import."""
    target_asset = asset_service.get_asset_by_name_silent(db, vuln_data.asset_name)

    if not target_asset:
        logger.error(f"Asset lookup failed: '{vuln_data.asset_name}' not found.")
        raise HTTPException(
            status_code=404, 
            detail=f"Asset '{vuln_data.asset_name}' not found. Please register it first."
        )

    def_data = vuln_data.model_dump(exclude={
        "asset_name", "status", "evidence", "discovered_by", "notes"
    })

    v_title = def_data.pop("title")

    target_defn = template_service.get_or_create_definition(db, title=v_title, **def_data)

    finding_info = {
        "status": vuln_data.status,
        "evidence": None if vuln_data.evidence is None else vuln_data.evidence.model_dump(mode="json"),
        "discovered_by": vuln_data.discovered_by,
        "notes": vuln_data.notes,
    }
    return get_or_create_finding(db, target_defn, target_asset, finding_info)

def get_vulnerabilities_joined(db: Session, skip: int = 0, limit: int = 100, search_query: str = None):
    """Returns (rows, total). total uses the same filters and ignores skip and limit."""
    base = (
        db.query(models.Vulnerability.id)
        .join(models.Asset, models.Vulnerability.asset_id == models.Asset.id)
        .join(
            models.VulnerabilityDefinition,
            models.Vulnerability.definition_id == models.VulnerabilityDefinition.id,
        )
    )
    if search_query:
        base = base.filter(
            or_(
                models.VulnerabilityDefinition.title.ilike(f"%{search_query}%"),
                models.Asset.name.ilike(f"%{search_query}%"),
            )
        )
    total = base.count()

    query = db.query(
        models.Vulnerability.created_at,
        models.Asset.name.label("asset_name"),
        models.VulnerabilityDefinition.title,
        models.VulnerabilityDefinition.severity,
        models.Vulnerability.status,
        models.Vulnerability.id.label("instance_id"),
    ).join(models.Asset, models.Vulnerability.asset_id == models.Asset.id).join(
        models.VulnerabilityDefinition,
        models.Vulnerability.definition_id == models.VulnerabilityDefinition.id,
    )
    if search_query:
        query = query.filter(
            or_(
                models.VulnerabilityDefinition.title.ilike(f"%{search_query}%"),
                models.Asset.name.ilike(f"%{search_query}%"),
            )
        )
    return query.offset(skip).limit(limit).all(), total


def bulk_process_vulnerabilities(db: Session, import_data: schemas.VulnerabilityBulkImport):
    """A failed row is recorded and the rest of the batch continues."""
    processed_count = 0
    errors = []

    for vuln in import_data.vulnerabilities:
        try:
            process_vulnerability_entry(db, vuln)
            processed_count += 1
        
        except HTTPException as he:
            db.rollback()
            errors.append({
                "title": vuln.title,
                "asset": vuln.asset_name,
                "reason": he.detail,
                "status_code": he.status_code
            })
            continue

        except Exception as e:
            db.rollback()
            logger.error(f"Unexpected error in bulk process for {vuln.asset_name} | {vuln.title}: {str(e)}")
            errors.append({
                "asset": vuln.asset_name,
                "title": vuln.title,
                "reason": "Internal Server Error: Unexpected exception occurred",
                "status_code": 500
            })
            continue

    logger.info(f"Bulk process finished: {processed_count} imported, {len(errors)} failed")
    
    return {
        "message": "Bulk processing completed.",
        "summary": {
            "imported": processed_count,
            "failed": len(errors),
            "total": len(import_data.vulnerabilities)
        },
        "details": {
            "errors": errors
        }
    }