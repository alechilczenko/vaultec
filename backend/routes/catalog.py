"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import catalog_service
import schemas
from schemas.common import SafeIntID
from dependencies.clean_query import get_clean_query

router = APIRouter(
    prefix="/catalog",
    tags=["Catalog (Vulnerability Definitions)"]
)

@router.get("/", response_model=schemas.CatalogRead)
def get_vulnerability_catalog(db: Session = Depends(get_db), skip: int = Query(0, ge=0, le=10000), limit: int = Query(100, ge=1, le=500)):
    return {"definitions": catalog_service.get_all_definitions(db, skip=skip, limit=limit)}

@router.get("/stats")
def get_catalog_stats(db: Session = Depends(get_db)):
    """
    Retrieves severity and category metrics for all catalog definitions.
    """
    return catalog_service.get_catalog_stats(db)

@router.get("/search", response_model=schemas.CatalogRead)
def search_definitions(q: str = Depends(get_clean_query), db: Session = Depends(get_db)):
    return {"definitions": catalog_service.search_definitions(db,q)}

@router.post("/create", response_model=schemas.VulnerabilityDefinitionRead, status_code=201)
def create_vulnerability_definition(data: schemas.CatalogEntryCreate, db: Session = Depends(get_db)):
    return catalog_service.create_definition_strict(db, data)

@router.post("/import", status_code=201)
def import_catalog_definitions(data: schemas.CatalogImport, db: Session = Depends(get_db)):
    return catalog_service.import_definitions(db, data)

@router.get("/{id}", response_model=schemas.VulnerabilityDefinitionRead)
def get_catalog_entry(id: SafeIntID, db: Session = Depends(get_db)):
    return catalog_service.get_definition_or_404(db, id)

@router.patch("/{id}", response_model=schemas.VulnerabilityDefinitionRead)
def update_vulnerability_definition(id: SafeIntID, data: schemas.VulnerabilityDefinitionUpdate, db: Session = Depends(get_db)):
    return catalog_service.update_definition(db, id, data.model_dump(exclude_unset=True))

@router.delete("/{id}", status_code=204)
def delete_vulnerability_definition(id: SafeIntID, db: Session = Depends(get_db)):
    catalog_service.delete_definition(db, id)
    return None