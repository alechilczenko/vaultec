"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from database.db import get_db
from database.crud import get_severity_stats, get_vulnerabilities_joined, get_finding_by_id, process_vulnerability_entry
import database.models as models
import schemas

router = APIRouter(
    prefix="/findings",
    tags=["Findings (Instances)"]
)

@router.get("/stats")
def get_vulnerability_stats(db: Session = Depends(get_db)):
    return get_severity_stats(db)

@router.get("/by-asset", response_model=List[schemas.VulnerabilityByAsset])
def get_vulnerabilities_by_asset(db: Session = Depends(get_db)):
    return get_vulnerabilities_joined(db)

@router.get("/{id}", response_model=schemas.VulnerabilityFullRead)
def get_finding_detail(id: int, db: Session = Depends(get_db)):
    finding = get_finding_by_id(db, id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding

@router.post("/create", response_model=schemas.VulnerabilityFullRead)
def create_vulnerabilities(vulnerability: schemas.VulnerabilityCreate, db: Session = Depends(get_db)):
    db_asset = db.query(models.Asset).filter(models.Asset.id == vulnerability.asset_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail=f"Asset with ID: {vulnerability.asset_id} not found")
    return process_vulnerability_entry(db, vulnerability)

@router.patch("/{id}", response_model=schemas.VulnerabilityInstanceUpdate)
def update_vulnerability_instance(id: int, data: schemas.VulnerabilityInstanceUpdate, db: Session = Depends(get_db)):
    db_v = get_finding_by_id(db, id)
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
            process_vulnerability_entry(db, vuln)
            created_count += 1
        except Exception:
            continue
    return {"imported": created_count, "skipped": total - created_count, "total": total}

@router.delete("/{id}", status_code=204)
def delete_vulnerability_instance(id: int, db: Session = Depends(get_db)):
    db_v = get_finding_by_id(db, id)
    if not db_v:
        raise HTTPException(status_code=404, detail="Instance not found")
    db.delete(db_v)
    db.commit()
    return None