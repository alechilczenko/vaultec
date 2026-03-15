"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from database.db import get_db
from database.crud import get_or_create_definition, format_vulnerability_grouped, get_severity_stats
import database.models as models
import schemas

router = APIRouter(
    prefix="/vulnerability",
    tags=["Vulnerabilities"]
)

@router.get("/stats")
def get_vulnerability_stats(db: Session = Depends(get_db)):
    return get_severity_stats(db)

@router.get("/list", response_model=List[schemas.VulnerabilityGrouped])
def get_vulnerabilities_grouped(db: Session = Depends(get_db)):

    definitions = db.query(models.VulnerabilityDefinition).all()
    
    return [format_vulnerability_grouped(defn) for defn in definitions]

@router.get("/search", response_model=List[schemas.VulnerabilityGrouped])
def search_vulnerabilities_by_title(title: str, db: Session = Depends(get_db)):

    definitions = db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.title.ilike(f"%{title}%")
    ).all()

    return [format_vulnerability_grouped(defn) for defn in definitions]

@router.post("", response_model=schemas.VulnerabilityGrouped)
def create_vulnerabilities(vulnerability: schemas.VulnerabilityCreate, db: Session = Depends(get_db)):

    defn = get_or_create_definition(
        db, 
        vulnerability.title,
        vulnerability.severity,
        vulnerability.description, 
        vulnerability.recommendation,
        vulnerability.tags
    )
   
    for finding in vulnerability.findings:

        # Validate if asset exists
        db_asset = db.query(models.Asset).filter(models.Asset.id == finding.asset_id).first()
        if not db_asset:
            raise HTTPException(status_code=404, detail=f"Asset with ID: {finding.asset_id} not found")

        # Set instance
        db_v = models.Vulnerability(
            definition_id=defn.id,
            asset_id=db_asset.id,
            status=finding.status,
            evidence_type=finding.evidence_type,
            http_request=finding.http_request,
            http_response=finding.http_response,
            general_evidence=finding.general_evidence,
            discovered_by=finding.discovered_by
        )
        db.add(db_v)

    db.commit()
    db.refresh(defn)
        
    return defn

@router.patch("/instances/{instance_id}", response_model=schemas.VulnerabilityInstance)
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

@router.patch("/definitions/{definition_id}", response_model=schemas.VulnerabilityDefinitionRead)
def update_vulnerability_definition(definition_id: int, data: schemas.VulnerabilityDefinitionUpdate, db: Session = Depends(get_db)):
    defn = db.query(models.VulnerabilityDefinition).filter(models.VulnerabilityDefinition.id == definition_id).first()
    if not defn:
        raise HTTPException(status_code=404, detail="Definition not found")

    update_data = data.model_dump(exclude_unset=True)
    
    if "tags" in update_data and isinstance(update_data["tags"], list):
        update_data["tags"] = ",".join(update_data["tags"])

    for key, value in update_data.items():
        setattr(defn, key, value)

    db.commit()
    db.refresh(defn)
    return defn

@router.delete("/instance/{instance_id}", status_code=204)
def delete_vulnerability_instance(instance_id: int, db: Session = Depends(get_db)):

    db_v = db.query(models.Vulnerability).filter(models.Vulnerability.id == instance_id).first()
    
    if not db_v:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    db.delete(db_v)
    db.commit()
    return None

@router.delete("/definition/{def_id}", status_code=204)
def delete_vulnerability_group(def_id: int, db: Session = Depends(get_db)):
    db_def = db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.id == def_id
    ).first()
    
    if not db_def:
        raise HTTPException(status_code=404, detail="Group not found")
    
    db.delete(db_def)
    db.commit()
    return None