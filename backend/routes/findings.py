"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from database.db import get_db
from database.crud import finding_service, asset_service
import database.models as models
import schemas

router = APIRouter(
    prefix="/findings",
    tags=["Findings (Instances)"])

@router.get("/stats")
def get_vulnerability_stats(db: Session = Depends(get_db)):
    return finding_service.get_severity_stats(db)

@router.get("/by-asset", response_model=List[schemas.VulnerabilityByAsset])
def get_vulnerabilities_by_asset(db: Session = Depends(get_db)):
    return finding_service.get_vulnerabilities_joined(db)

@router.get("/{id}", response_model=schemas.VulnerabilityFullRead)
def get_finding_detail(id: int, db: Session = Depends(get_db)):
    finding = finding_service.get_finding_by_id(db, id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.post("/create", response_model=schemas.VulnerabilityFullRead)
def create_vulnerabilities(vulnerability: schemas.VulnerabilityCreate, db: Session = Depends(get_db)):
    asset_service.check_asset_exists(db, vulnerability.asset_id)
    return finding_service.process_vulnerability_entry(db, vulnerability)

@router.patch("/{id}", response_model=schemas.VulnerabilityInstanceUpdate)
def update_vulnerability_instance(id: int, data: schemas.VulnerabilityInstanceUpdate, db: Session = Depends(get_db)):
    db_v = finding_service.get_finding_by_id(db, id)
    if not db_v:
        raise HTTPException(status_code=404, detail="Instance not found")
    update_data = data.model_dump(exclude_unset=True)
    return finding_service.update_finding(db, db_v, update_data)

@router.post("/import")
def bulk_create_vulnerabilities(vulnerabilities: list[schemas.VulnerabilityCreate], db: Session = Depends(get_db)):
    return finding_service.bulk_process_vulnerabilities(db, vulnerabilities)

@router.delete("/{id}", status_code=204)
def delete_vulnerability_instance(id: int, db: Session = Depends(get_db)):
    db_v = finding_service.get_finding_by_id(db, id)
    if not db_v:
        raise HTTPException(status_code=404, detail="Instance not found")
    finding_service.delete_finding(db, db_v)
    return None