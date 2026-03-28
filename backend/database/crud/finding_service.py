"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy import func
from fastapi import HTTPException, status
import database.models as models
import schemas
from database.crud import catalog_service, asset_service

def update_finding(db: Session, db_obj: models.Vulnerability, update_data: dict):
    """
    Applies updates to a finding instance with robust error handling.
    """
    finding_id = db_obj.id
    try:
        for key, value in update_data.items():
            setattr(db_obj, key, value)
        
        db.commit()
        db.refresh(db_obj)
        return db_obj
    except Exception as e:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=f"Update Error: Could not update finding ID {finding_id}. Check if the data format is correct."
        )

def delete_finding(db: Session, db_obj: models.Vulnerability):
    """
    Deletes a specific finding instance with error handling.
    """
    finding_id = db_obj.id
    try:
        db.delete(db_obj)
        db.commit()
        return True 
    except Exception as e:
        db.rollback()
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
        return new_finding
    
    except Exception as e:
        db.rollback()
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

    if "tags" in def_data and isinstance(def_data["tags"], list):
        def_data["tags"] = ",".join(def_data["tags"])
    
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

def get_vulnerabilities_joined(db: Session):
    return db.query(
        models.Vulnerability.created_at,
        models.Asset.name.label("asset_name"),
        models.VulnerabilityDefinition.title,
        models.VulnerabilityDefinition.severity,
        models.Vulnerability.status,
        models.Vulnerability.id.label("instance_id")
    ).join(models.Vulnerability, models.Asset.id == models.Vulnerability.asset_id)\
     .join(models.VulnerabilityDefinition, models.Vulnerability.definition_id == models.VulnerabilityDefinition.id).all()

def bulk_process_vulnerabilities(db: Session, vulnerabilities: schemas.VulnerabilityBulkImport):
    created_count = 0
    total = len(vulnerabilities)
    for vuln in vulnerabilities:
        try:
            process_vulnerability_entry(db, vuln)
            created_count += 1
        except (HTTPException, SQLAlchemyError) as e:
            # Rollback only for expected business logic or DB operational errors
            db.rollback()
            continue
    return {
        "imported": created_count, 
        "skipped": total - created_count, 
        "total": total }