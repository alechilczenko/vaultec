"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Annotated, Optional
from database.db import get_db
from database.crud import finding_service
import schemas
from schemas.common import SafeIntID
from dependencies.project import validate_project
from dependencies.clean_query import get_clean_query

router = APIRouter(
    prefix="/projects/{project_id}/findings",
    tags=["Findings (Instances)"],
    dependencies=[Depends(validate_project)])

@router.get("/stats")
def get_vulnerability_stats(project_id: SafeIntID, db: Session = Depends(get_db)):
    return finding_service.get_severity_stats(db, project_id)

@router.get("/by-asset", response_model=schemas.VulnerabilityJoinedRead)
def get_vulnerabilities_by_asset(
    project_id: SafeIntID, 
    skip: Annotated[int, Query(ge=0, le=10000, description="Records to skip")] = 0, 
    limit: Annotated[int, Query(ge=1, le=100, description="Records per page")] = 50, 
    q: Annotated[Optional[str], Depends(get_clean_query)] = None, 
    db: Session = Depends(get_db)):
    return {"findings": finding_service.get_vulnerabilities_joined(db, project_id, skip, limit, q)}

@router.get("/{id}", response_model=schemas.VulnerabilityFullRead)
def get_finding_detail(project_id: SafeIntID, id: SafeIntID, db: Session = Depends(get_db)):
    return finding_service.get_finding_by_id(db, id, project_id)

@router.post("/create", response_model=schemas.VulnerabilityFullRead)
def create_vulnerabilities(project_id: SafeIntID, vulnerability: schemas.VulnerabilityCreate, db: Session = Depends(get_db)):
    return finding_service.process_vulnerability_entry(db, vulnerability, project_id)

@router.post("/import")
def bulk_create_vulnerabilities(project_id: SafeIntID, data: schemas.VulnerabilityBulkImport, db: Session = Depends(get_db)):
    return finding_service.bulk_process_vulnerabilities(db, data, project_id)

@router.patch("/{id}", response_model=schemas.VulnerabilityFullRead)
def update_vulnerability_instance(project_id: SafeIntID, id: SafeIntID, data: schemas.VulnerabilityInstanceUpdate, db: Session = Depends(get_db)):
    db_v = finding_service.get_finding_by_id(db, id, project_id)
    update_data = data.model_dump(exclude_unset=True)
    return finding_service.update_finding(db, db_v, update_data)

@router.delete("/{id}", status_code=204)
def delete_vulnerability_instance(project_id: SafeIntID, id: SafeIntID, db: Session = Depends(get_db)):
    db_v = finding_service.get_finding_by_id(db, id, project_id)
    finding_service.delete_finding(db, db_v)
    return None