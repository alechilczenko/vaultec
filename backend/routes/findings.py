"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from typing import Annotated, Optional
from database.db import get_db
from database.crud import finding_service
import schemas
from schemas.common import SafeIntID
from dependencies.clean_query import get_clean_query

router = APIRouter(
    prefix="/findings",
    tags=["Findings (Instances)"],
    responses={
        409: {
            "description": "Workspace is empty (library mode); active assessment required.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Active assessment required. Call POST /workspace/setup first."
                    }
                }
            },
        }
    },
)


@router.get("", response_model=schemas.VulnerabilityJoinedRead)
def list_findings(
    skip: Annotated[int, Query(ge=0, le=10000, description="Records to skip")] = 0,
    limit: Annotated[int, Query(ge=1, le=100, description="Records per page")] = 50,
    q: Annotated[Optional[str], Depends(get_clean_query)] = None,
    db: Session = Depends(get_db),
):
    """
    Lists findings in the active workspace, joined with asset and definition data.
    """
    findings, total = finding_service.get_vulnerabilities_joined(db, skip, limit, q)
    return {"findings": findings, "total": total}


@router.get("/stats")
def get_vulnerability_stats(db: Session = Depends(get_db)):
    """
    Retrieves severity and status metrics for all findings in the active workspace.
    """
    return finding_service.get_finding_stats(db)


@router.post("/create", response_model=schemas.VulnerabilityFullRead, status_code=status.HTTP_201_CREATED)
def create_vulnerabilities(vulnerability: schemas.VulnerabilityCreate, db: Session = Depends(get_db)):
    """
    Creates or registers a new finding in the active workspace.
    """
    return finding_service.process_vulnerability_entry(db, vulnerability)


@router.post("/import")
def bulk_create_vulnerabilities(data: schemas.VulnerabilityBulkImport, db: Session = Depends(get_db)):
    """
    Bulk imports multiple findings into the active workspace.
    """
    return finding_service.bulk_process_vulnerabilities(db, data)


@router.get("/{id}", response_model=schemas.VulnerabilityFullRead)
def get_finding_detail(id: SafeIntID, db: Session = Depends(get_db)):
    """
    Retrieves details for a single finding instance.
    """
    return finding_service.get_finding_by_id(db, id)


@router.patch("/{id}", response_model=schemas.VulnerabilityFullRead)
def update_vulnerability_instance(
    id: SafeIntID, 
    data: schemas.VulnerabilityInstanceUpdate, 
    db: Session = Depends(get_db)
):
    """
    Updates an existing finding in the active workspace.
    """
    db_v = finding_service.get_finding_by_id(db, id)
    update_data = data.model_dump(exclude_unset=True)
    return finding_service.update_finding(db, db_v, update_data)


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vulnerability_instance(id: SafeIntID, db: Session = Depends(get_db)):
    """
    Deletes a finding instance from the active workspace.
    """
    db_v = finding_service.get_finding_by_id(db, id)
    finding_service.delete_finding(db, db_v)
    return None