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

@router.get("/", response_model=list[schemas.VulnerabilityDefinitionRead])
def get_vulnerability_catalog(db: Session = Depends(get_db)):
    catalog = db.query(models.VulnerabilityDefinition).all()
    return catalog

@router.get("/{id}", response_model=schemas.VulnerabilityDefinitionRead)
def get_catalog_entry(id: int, db: Session = Depends(get_db)):
    defn = db.query(models.VulnerabilityDefinition).filter(models.VulnerabilityDefinition.id == id).first()
    
    if not defn:
        raise HTTPException(status_code=404, detail="Definition not found")
    
    return defn

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

@router.post("/import", status_code=201)
def import_catalog_definitions(data: schemas.CatalogImport, db: Session = Depends(get_db)):
    created_count = 0
    updated_count = 0

    for item in data.definitions:
        existing = db.query(models.VulnerabilityDefinition).filter(
            models.VulnerabilityDefinition.title == item.title
        ).first()

        tag_str = ",".join(item.tags) if item.tags else ""

        if existing:
            existing.severity = item.severity
            existing.description = item.description
            existing.recommendation = item.recommendation
            existing.tags = tag_str
            updated_count += 1
        else:
            new_defn = models.VulnerabilityDefinition(
                title=item.title,
                severity=item.severity,
                description=item.description,
                recommendation=item.recommendation,
                tags=tag_str
            )
            db.add(new_defn)
            created_count += 1

    try:
        db.commit()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

    return {
        "status": "success",
        "details": {
            "created": created_count,
            "updated": updated_count,
            "total_processed": len(data.definitions)
        }
    }

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