"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from database.db import get_db
from database.crud import catalog_service
import schemas
from schemas.common import SafeIntID

router = APIRouter(
    prefix="/catalog",
    tags=["Catalog (Vulnerability Definitions)"]
)

@router.get("/", response_model=list[schemas.VulnerabilityDefinitionRead])
def get_vulnerability_catalog(db: Session = Depends(get_db)):
    return catalog_service.get_all_definitions(db)

@router.get("/search", response_model=List[schemas.VulnerabilityDefinitionRead])
def search_definitions(q: str, db: Session = Depends(get_db)):
    return catalog_service.search_definitions(db,q)

@router.get("/{id}", response_model=schemas.VulnerabilityDefinitionRead)
def get_catalog_entry(id: SafeIntID, db: Session = Depends(get_db)):
    return catalog_service.get_definition_by_id(db, id)

@router.patch("/{id}", response_model=schemas.VulnerabilityDefinitionRead)
def update_vulnerability_definition(id: SafeIntID, data: schemas.VulnerabilityDefinitionUpdate, db: Session = Depends(get_db)):
    defn = catalog_service.get_definition_by_id(db, id)
    update_data = data.model_dump(exclude_unset=True)
    return catalog_service.update_definition(db, defn, update_data)

@router.post("/import", status_code=201)
def import_catalog_definitions(data: schemas.CatalogImport, db: Session = Depends(get_db)):
    return catalog_service.import_definitions(db, data)

@router.delete("/{id}", status_code=204)
def delete_vulnerability_definition(id: SafeIntID, db: Session = Depends(get_db)):
    defn = catalog_service.get_definition_by_id(db, id)
    catalog_service.delete_definition(db, defn)
    return None