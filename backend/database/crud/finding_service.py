"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func, or_
from fastapi import HTTPException, status
import database.models as models
import schemas
from database.crud import catalog_service, asset_service
from loguru import logger

def update_finding(db: Session, db_obj: models.Vulnerability, update_data: dict):
    """
    Applies updates to a finding instance with robust error handling.
    """
    finding_id = db_obj.id
    finding_title = db_obj.definition.title if db_obj.definition else "Unknown Title"

    try:
        for key, value in update_data.items():
            setattr(db_obj, key, value)
        
        db.commit()
        db.refresh(db_obj)
        logger.info(f"Finding updated: '{finding_title}' (ID: {finding_id})")
        return db_obj
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to update finding: '{finding_title}' (ID: {finding_id}): {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Update Error: Could not update finding ID {finding_id}. Check if the data format is correct."
        )

def delete_finding(db: Session, db_obj: models.Vulnerability):
    """
    Deletes a specific finding instance with error handling.
    """
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
        print(e)
        raise HTTPException(
            status_code=500,
            detail=f"Database Error: Could not delete finding ID {finding_id}. Transaction rolled back."
        )
    
def get_severity_stats(db: Session):
    priority_order = ["critical", "high", "medium", "low", "informative"]

    # Query instances (Vulnerability) joined with their Definitions
    stats = db.query(
        models.VulnerabilityDefinition.severity,
        func.count(models.Vulnerability.id)
    ).join(
        models.Vulnerability, 
        models.Vulnerability.definition_id == models.VulnerabilityDefinition.id
    ).filter(
        models.Vulnerability.status == "open" # Only count active findings
    ).group_by(
        models.VulnerabilityDefinition.severity
    ).all()

    stats_map = {severity: count for severity, count in stats}
    ordered_stats = {sev: stats_map.get(sev, 0) for sev in priority_order}

    return ordered_stats

def get_finding_by_id(db: Session, finding_id: int):

    finding = db.query(models.Vulnerability).filter(models.Vulnerability.id == finding_id).first()
    if not finding:
        raise HTTPException(
            status_code=404,
            detail=f"Finding Error: Vulnerability instance with ID {finding_id} not found."
        )
    return finding

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

        asset_name = existing_finding.asset.name if existing_finding.asset else f"ID {asset_id}"
        vuln_title = existing_finding.definition.title if existing_finding.definition else f"Def ID {def_id}"

        logger.warning(f"Duplicate finding blocked: '{vuln_title}' already active on '{asset_name}'")

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Duplicate Finding: The asset '{asset_name}' already has an active record "
                f"for '{vuln_title}'. Duplicate prevented.")
    
    # 2. If no duplicate, create the new instance
    new_finding = models.Vulnerability(
        definition_id=def_id,
        asset_id=asset_id,
        **vulnerability_data)
    try:
        db.add(new_finding)
        db.commit()
        db.refresh(new_finding)
        logger.info(f"New finding created: {vuln_title}")
        return new_finding
    
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to persist finding for Asset {asset_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database Error: Failed to persist the new finding. Transaction rolled back.")

def process_vulnerability_entry(db: Session, vuln_data: schemas.VulnerabilityCreate):
    """
    Orchestrates the creation of a definition and its associated finding.
    Logic shared between single and bulk imports.
    """
    asset_service.check_asset_exists(db, vuln_data.asset_id)

    # 1. Prepare Definition Data
    def_data = vuln_data.model_dump(exclude={
        "asset_id", "status", "evidence_type", "http_request", 
        "http_response", "general_evidence", "discovered_by", "notes"
    })
 
    v_id = def_data.pop("definition_id", None)
    v_title = def_data.pop("title")

    # 2. Get/Create Definition
    defn = catalog_service.get_or_create_definition(db, def_id=v_id, title=v_title, **def_data)

    # 3. Prepare Finding Data
    finding_info = {
        "status": vuln_data.status,
        "evidence_type": vuln_data.evidence_type,
        "http_request": vuln_data.http_request,
        "http_response": vuln_data.http_response,
        "general_evidence": vuln_data.general_evidence,
        "discovered_by": vuln_data.discovered_by,
        "notes": vuln_data.notes,
    }
    # 4. Create Finding
    return get_or_create_finding(db, defn.id, vuln_data.asset_id, finding_info)

def get_vulnerabilities_joined(db: Session, skip: int = 0, limit: int = 100, search_query: str = None):
    query = db.query(
        models.Vulnerability.created_at,
        models.Asset.name.label("asset_name"),
        models.VulnerabilityDefinition.title,
        models.VulnerabilityDefinition.severity,
        models.Vulnerability.status,
        models.Vulnerability.id.label("instance_id")
    ).join(models.Vulnerability, models.Asset.id == models.Vulnerability.asset_id)\
     .join(models.VulnerabilityDefinition, models.Vulnerability.definition_id == models.VulnerabilityDefinition.id)
    
    if search_query:
        query = query.filter(
            or_(
                models.VulnerabilityDefinition.title.ilike(f"%{search_query}%"),
                models.Asset.name.ilike(f"%{search_query}%")
            )
        )
    return query.offset(skip).limit(limit).all()
    

def bulk_process_vulnerabilities(db: Session, vulnerabilities: schemas.VulnerabilityBulkImport):

    processed_count = 0
    errors = []

    asset_ids = {v.asset_id for v in vulnerabilities}
    asset_map = {
        row.id: row.name 
        for row in db.query(models.Asset.id, models.Asset.name).filter(models.Asset.id.in_(asset_ids)).all()
    }

    for vuln in vulnerabilities:
        
        asset_label = asset_map.get(vuln.asset_id, f"Asset ID {vuln.asset_id}")
        vuln_label = vuln.title if hasattr(vuln, 'title') else f"Def ID {vuln.definition_id}"
        context = f"{asset_label} | {vuln_label}"

        try:
            process_vulnerability_entry(db, vuln)
            processed_count += 1
        
        except HTTPException as he:
        
            db.rollback()
            errors.append(f"{context}: {he.detail}")
            continue

        except Exception as e:
            db.rollback()
            logger.error(f"Unexpected error in bulk process for {context}: {str(e)}")
            errors.append(f"{context}: Unexpected error")
            continue

    logger.info(f"Bulk process finished: {processed_count} imported, {len(errors)} failed")
    
    return {
        "message": "Bulk processing completed.",
        "summary": {
            "imported": processed_count,
            "failed": len(errors),
            "total": len(vulnerabilities)
        },
        "details": {
            "errors": errors
        }
    }