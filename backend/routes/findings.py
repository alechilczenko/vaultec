"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from typing import Annotated, Optional
from database.db import get_db
from services import finding_service
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
    findings, total = finding_service.get_vulnerabilities_joined(db, skip, limit, q)
    return {"findings": findings, "total": total}


@router.get("/stats")
def get_vulnerability_stats(db: Session = Depends(get_db)):
    return finding_service.get_finding_stats(db)


@router.get("/export", response_model=schemas.FindingExportRead)
def export_findings(db: Session = Depends(get_db)):
    """Report JSON: workspace header + findings grouped by definition."""
    payload = finding_service.build_findings_export(db)
    body = schemas.FindingExportRead.model_validate(payload).model_dump(mode="json")
    filename = finding_service.export_download_filename(payload)
    return JSONResponse(
        content=body,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/create", response_model=schemas.VulnerabilityFullRead, status_code=status.HTTP_201_CREATED)
def create_vulnerabilities(vulnerability: schemas.VulnerabilityCreate, db: Session = Depends(get_db)):
    return finding_service.process_vulnerability_entry(db, vulnerability)


@router.post(
    "/import",
    response_model=schemas.VulnerabilityBulkImportRead,
    responses={
        400: {
            "description": (
                "Import cancelled (all-or-nothing). No findings or inline templates "
                "were written. Typical causes: missing asset, missing template id, "
                "or duplicate (definition, asset) pair."
            ),
            "content": {
                "application/json": {
                    "example": {
                        "detail": (
                            "Import cancelled. Row 2: asset 'missing.example' not found. "
                            "Please register it first."
                        )
                    }
                }
            },
        }
    },
)
def bulk_create_vulnerabilities(
    data: schemas.VulnerabilityBulkImport, db: Session = Depends(get_db)
):
    return finding_service.bulk_process_vulnerabilities(db, data)


@router.get("/{id}", response_model=schemas.VulnerabilityFullRead)
def get_finding_detail(id: SafeIntID, db: Session = Depends(get_db)):
    return finding_service.get_finding_by_id(db, id)


@router.patch("/{id}", response_model=schemas.VulnerabilityFullRead)
def update_vulnerability_instance(
    id: SafeIntID, 
    data: schemas.VulnerabilityInstanceUpdate, 
    db: Session = Depends(get_db)
):
    db_v = finding_service.get_finding_by_id(db, id)
    update_data = data.model_dump(exclude_unset=True, mode="json")
    return finding_service.update_finding(db, db_v, update_data)


@router.post("/{id}/relink", response_model=schemas.VulnerabilityFullRead)
def relink_vulnerability_instance(
    id: SafeIntID,
    data: schemas.VulnerabilityRelink,
    db: Session = Depends(get_db),
):
    return finding_service.relink_finding(db, id, data.definition_id)


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_vulnerability_instance(id: SafeIntID, db: Session = Depends(get_db)):
    db_v = finding_service.get_finding_by_id(db, id)
    finding_service.delete_finding(db, db_v)
    return None