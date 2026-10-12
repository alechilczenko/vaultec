"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import template_service
import schemas
from schemas.common import SafeIntID
from dependencies.clean_query import get_clean_query

router = APIRouter(
    prefix="/templates",
    tags=["Templates (Vulnerability Definitions)"]
)

@router.get("", response_model=schemas.TemplatesRead)
def get_vulnerability_templates(db: Session = Depends(get_db), skip: int = Query(0, ge=0, le=10000), limit: int = Query(100, ge=1, le=500)):
    templates, total = template_service.get_all_definitions(db, skip=skip, limit=limit)
    return {"templates": templates, "total": total}

@router.get("/stats")
def get_template_stats(db: Session = Depends(get_db)):
    """
    Retrieves severity and category metrics for all template definitions.
    """
    return template_service.get_template_stats(db)

@router.get("/search", response_model=schemas.TemplatesRead)
def search_templates(q: str = Depends(get_clean_query), db: Session = Depends(get_db)):
    templates, total = template_service.search_definitions(db, q)
    return {"templates": templates, "total": total}

@router.post("/create", response_model=schemas.VulnerabilityDefinitionRead, status_code=201)
def create_vulnerability_definition(data: schemas.TemplateEntryCreate, db: Session = Depends(get_db)):
    return template_service.create_definition_strict(db, data)

@router.post("/import", status_code=201)
def import_templates(data: schemas.TemplatesImport, db: Session = Depends(get_db)):
    return template_service.import_definitions(db, data)

@router.get("/{id}", response_model=schemas.VulnerabilityDefinitionRead)
def get_template_entry(id: SafeIntID, db: Session = Depends(get_db)):
    return template_service.get_definition_or_404(db, id)

@router.patch("/{id}", response_model=schemas.VulnerabilityDefinitionRead)
def update_vulnerability_definition(id: SafeIntID, data: schemas.VulnerabilityDefinitionUpdate, db: Session = Depends(get_db)):
    return template_service.update_definition(db, id, data.model_dump(exclude_unset=True))

@router.delete("/{id}", status_code=204)
def delete_vulnerability_definition(id: SafeIntID, db: Session = Depends(get_db)):
    template_service.delete_definition(db, id)
    return None
