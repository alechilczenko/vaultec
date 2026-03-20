"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from database.db import get_db
import database.models as models
import schemas

router = APIRouter(
    prefix="/catalog",
    tags=["Catalog (Vulnerability Definitions)"]
)

@router.get("/search", response_model=List[schemas.VulnerabilityDefinitionRead])
def search_definitions(q: str, db: Session = Depends(get_db)):

    results = db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.title.ilike(f"%{q}%")
    ).limit(10).all()
    return results

@router.patch("/{id}", response_model=schemas.VulnerabilityDefinitionRead)
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

@router.delete("/{id}", status_code=204)
def delete_vulnerability_definition(def_id: int, db: Session = Depends(get_db)):
    db_def = db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.id == def_id
    ).first()
    
    if not db_def:
        raise HTTPException(status_code=404, detail="Definition not found")
    
    db.delete(db_def)
    db.commit()
    return None