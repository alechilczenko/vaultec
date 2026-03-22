"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from database.db import get_db
from database.crud import get_or_create_definition, get_severity_stats, get_or_create_finding
import database.models as models
import schemas

router = APIRouter(
    prefix="/findings",
    tags=["Findings (Instances)"]
)

@router.get("/by-asset", response_model=List[schemas.VulnerabilityByAsset])
def get_vulnerabilities_by_asset(db: Session = Depends(get_db)):
    results = db.query(
        models.Vulnerability.created_at,
        models.Asset.name.label("asset_name"),
        models.VulnerabilityDefinition.title,
        models.VulnerabilityDefinition.severity,
        models.Vulnerability.status,
        models.Vulnerability.id.label("instance_id")
    ).join(models.Vulnerability, models.Asset.id == models.Vulnerability.asset_id)\
     .join(models.VulnerabilityDefinition, models.Vulnerability.definition_id == models.VulnerabilityDefinition.id)\
     .all()

    return results

@router.get("/{id}", response_model=schemas.VulnerabilityFullRead)
def get_finding_detail(id: int, db: Session = Depends(get_db)):
    finding = db.query(models.Vulnerability).filter(models.Vulnerability.id == id).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    return finding

@router.get("/stats")
def get_vulnerability_stats(db: Session = Depends(get_db)):
    return get_severity_stats(db)


@router.post("/create", response_model=schemas.VulnerabilityFullRead)
def create_vulnerabilities(vulnerability: schemas.VulnerabilityCreate, db: Session = Depends(get_db)):
    """
    Creates or retrieves a vulnerability definition and assigns it to multiple assets.
    """
    # 1. Prepare Definition Data (The Catalog part)
    # Extract all fields except 'findings' as they don't belong to the Definition table.
    def_data = vulnerability.model_dump(exclude={
    "asset_id", 
    "status", 
    "evidence_type", 
    "http_request", 
    "http_response", 
    "general_evidence", 
    "discovered_by", 
    "notes"
    })

    if "tags" in def_data and isinstance(def_data["tags"], list):
        def_data["tags"] = ",".join(def_data["tags"])
    
    # Extract keys used for the lookup logic
    v_id = def_data.pop("definition_id", None)
    v_title = def_data.pop("title")

    # **def_data passes severity, description, etc., automatically to the DB model.
    defn = get_or_create_definition(db, def_id=v_id, title=v_title, **def_data)

    # Validate if asset exists
    db_asset = db.query(models.Asset).filter(models.Asset.id == vulnerability.asset_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail=f"Asset with ID: {vulnerability.asset_id} not found")

    finding_info = {
        "status": vulnerability.status,
        "evidence_type": vulnerability.evidence_type,
        "http_request": vulnerability.http_request,
        "http_response": vulnerability.http_response,
        "general_evidence": vulnerability.general_evidence,
        "discovered_by": vulnerability.discovered_by,
        "notes": vulnerability.notes,
    }

    return get_or_create_finding(db, defn.id, vulnerability.asset_id, finding_info)

@router.patch("/{id}", response_model=schemas.VulnerabilityInstanceUpdate)
def update_vulnerability_instance(instance_id: int, data: schemas.VulnerabilityInstanceUpdate, db: Session = Depends(get_db)):
    db_v = db.query(models.Vulnerability).filter(models.Vulnerability.id == instance_id).first()
    if not db_v:
        raise HTTPException(status_code=404, detail="Instance not found")

    update_data = data.model_dump(exclude_unset=True)
    
    for key, value in update_data.items():
        setattr(db_v, key, value)
        
    db.commit()
    db.refresh(db_v)
    return db_v

@router.post("/import")
def bulk_create_vulnerabilities(vulnerabilities: list[schemas.VulnerabilityCreate], db: Session = Depends(get_db)):
    created_count = 0
    total = len(vulnerabilities)

    for vuln in vulnerabilities:
        try:
            
            def_data = vuln.model_dump(exclude={
                "asset_id", "status", "evidence_type", "http_request", 
                "http_response", "general_evidence", "discovered_by", "notes"
            })
            
            if "tags" in def_data and isinstance(def_data["tags"], list):
                def_data["tags"] = ",".join(def_data["tags"])
            
            v_id = def_data.pop("definition_id", None)
            v_title = def_data.pop("title")
            
            defn = get_or_create_definition(db, def_id=v_id, title=v_title, **def_data)

            finding_info = {
                "status": vuln.status,
                "evidence_type": vuln.evidence_type,
                "http_request": vuln.http_request,
                "http_response": vuln.http_response,
                "general_evidence": vuln.general_evidence,
                "discovered_by": vuln.discovered_by,
                "notes": vuln.notes
            }

            get_or_create_finding(db, defn.id, vuln.asset_id, finding_info)
            created_count += 1

        except Exception:
            continue

    return {
        "imported": created_count,
        "skipped": total - created_count,
        "total": total
    }

@router.delete("/{id}", status_code=204)
def delete_vulnerability_instance(instance_id: int, db: Session = Depends(get_db)):

    db_v = db.query(models.Vulnerability).filter(models.Vulnerability.id == instance_id).first()
    if not db_v:
        raise HTTPException(status_code=404, detail="Instance not found")

    db.delete(db_v)
    db.commit()
    return None