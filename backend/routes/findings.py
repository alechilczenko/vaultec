"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Annotated, Optional
from database.db import get_db
from database.crud import finding_service, asset_service
import schemas
from schemas.common import SafeIntID

router = APIRouter(
    prefix="/findings",
    tags=["Findings (Instances)"])

@router.get("/stats")
def get_vulnerability_stats(db: Session = Depends(get_db)):
    return finding_service.get_severity_stats(db)

@router.get("/by-asset", response_model=schemas.VulnerabilityJoinedRead)
def get_vulnerabilities_by_asset(skip: Annotated[int, Query(ge=0, description="Records to skip")] = 0, limit: Annotated[int, Query(ge=1, le=100, description="Records per page")] = 50, q: Annotated[Optional[str], Query(min_length=1, max_length=100)] = None, db: Session = Depends(get_db)):
    return {"findings": finding_service.get_vulnerabilities_joined(db, skip, limit, q)}

@router.get("/{id}", response_model=schemas.VulnerabilityFullRead)
def get_finding_detail(id: SafeIntID, db: Session = Depends(get_db)):
    return finding_service.get_finding_by_id(db, id)

@router.post("/create", response_model=schemas.VulnerabilityFullRead)
def create_vulnerabilities(vulnerability: schemas.VulnerabilityCreate, db: Session = Depends(get_db)):
    asset_service.get_asset_by_name(db, vulnerability.asset_name)
    return finding_service.process_vulnerability_entry(db, vulnerability)

@router.post("/import")
def bulk_create_vulnerabilities(data: schemas.VulnerabilityBulkImport, db: Session = Depends(get_db)):
    return finding_service.bulk_process_vulnerabilities(db, data)

@router.patch("/{id}", response_model=schemas.VulnerabilityFullRead)
def update_vulnerability_instance(id: SafeIntID, data: schemas.VulnerabilityInstanceUpdate, db: Session = Depends(get_db)):
    db_v = finding_service.get_finding_by_id(db, id)
    update_data = data.model_dump(exclude_unset=True)
    return finding_service.update_finding(db, db_v, update_data)

@router.delete("/{id}", status_code=204)
def delete_vulnerability_instance(id: SafeIntID, db: Session = Depends(get_db)):
    db_v = finding_service.get_finding_by_id(db, id)
    finding_service.delete_finding(db, db_v)
    return None