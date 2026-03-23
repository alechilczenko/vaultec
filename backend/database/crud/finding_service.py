"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from sqlalchemy import func
from fastapi import HTTPException, status
import database.models as models
import schemas
from database.crud import catalog_service, asset_service

def update_finding(db: Session, db_obj: models.Vulnerability, update_data: dict):
    # Applies updates to the finding instance and commits
    for key, value in update_data.items():
        setattr(db_obj, key, value)
    db.commit()
    db.refresh(db_obj)
    return db_obj

def delete_finding(db: Session, db_obj: models.Vulnerability):
    # Deletes the finding instance from the database
    db.delete(db_obj)
    db.commit()

def get_severity_stats(db: Session):
    # Query to group by severity and count occurrences
    stats = db.query(
        models.VulnerabilityDefinition.severity,
        func.count(models.VulnerabilityDefinition.id)
    ).group_by(models.VulnerabilityDefinition.severity).all()
    # Transform list of tuples into a clean dictionary
    return {severity: count for severity, count in stats}

def get_finding_by_id(db: Session, finding_id: int):
    return db.query(models.Vulnerability).filter(models.Vulnerability.id == finding_id).first()

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
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Duplicate finding: Asset {asset_id} already has this vulnerability.")
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
        print(f"ERROR: Database failure while creating finding. {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal database error during finding creation.")

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

def bulk_process_vulnerabilities(db: Session, vulnerabilities: list[schemas.VulnerabilityCreate]):
    created_count = 0
    total = len(vulnerabilities)
    for vuln in vulnerabilities:
        try:
            process_vulnerability_entry(db, vuln)
            created_count += 1
        except Exception as e:
            db.rollback()
            continue
    return {
        "imported": created_count, 
        "skipped": total - created_count, 
        "total": total }