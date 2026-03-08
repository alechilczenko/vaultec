from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from db import get_db
from crud import get_or_create_definition, format_vulnerability_grouped
import models, schemas

router = APIRouter(
    prefix="/vulnerability",
    tags=["Vulnerabilities"]
)

@router.get("/list", response_model=List[schemas.VulnerabilityGrouped])
def get_vulnerabilities_grouped(db: Session = Depends(get_db)):

    definitions = db.query(models.VulnerabilityDefinition).all()
    
    return [format_vulnerability_grouped(defn) for defn in definitions]

@router.get("/search", response_model=List[schemas.VulnerabilityGrouped])
def search_vulnerabilities_by_title(title: str, db: Session = Depends(get_db)):

    definitions = db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.title.ilike(f"%{title}%")
    ).all()

    return [format_vulnerability_grouped(defn) for defn in definitions]

@router.post("", response_model=schemas.VulnerabilityRead)
def create_vulnerability(vulnerability: schemas.VulnerabilityCreate, db: Session = Depends(get_db)):

    defn = get_or_create_definition(
        db, 
        vulnerability.title,
        vulnerability.severity,
        vulnerability.description, 
        vulnerability.recommendation
    )
    db_asset = db.query(models.Asset).filter(models.Asset.name == vulnerability.asset.name).first()

    if not db_asset:
        db_asset = models.Asset(
            name=vulnerability.asset.name,
            type=vulnerability.asset.type
        )
        db.add(db_asset)
        db.commit()
        db.refresh(db_asset)

    db_vulnerability = models.Vulnerability(
        definition_id=defn.id,
        severity=vulnerability.severity,
        status=vulnerability.status,
        asset_id=db_asset.id
    )
    
    db.add(db_vulnerability)
    db.commit()
    db.refresh(db_vulnerability)
    
    return db_vulnerability


@router.patch("/{v_id}", response_model=schemas.VulnerabilityRead)
def update_vulnerability(v_id: int, data: schemas.VulnerabilityUpdate, db: Session = Depends(get_db)):
    # Find the instance of vulnerability
    db_v = db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).first()
    if not db_v:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    # Update Status (this is individual to this instance)
    if data.status is not None:
        db_v.status = data.status

    # Update the Definition (this affects all assets with this title)
    # If a title, description, recommendation, or severity rating is submitted

    if any([data.title, data.severity, data.description, data.recommendation]):
        defn = db_v.definition
        if data.title: defn.title = data.title
        if data.severity: defn.severity = data.severity
        if data.description: defn.description = data.description
        if data.recommendation: defn.recommendation = data.recommendation
        
        db.add(defn)

    db.commit()
    db.refresh(db_v)
    return db_v

@router.delete("/instance/{v_id}", status_code=204)
def delete_vulnerability_instance(v_id: int, db: Session = Depends(get_db)):

    db_v = db.query(models.Vulnerability).filter(models.Vulnerability.id == v_id).first()
    
    if not db_v:
        raise HTTPException(status_code=404, detail="Instance not found")
    
    db.delete(db_v)
    db.commit()
    return None

@router.delete("/definition/{def_id}", status_code=204)
def delete_vulnerability_group(def_id: int, db: Session = Depends(get_db)):
    db_def = db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.id == def_id
    ).first()
    
    if not db_def:
        raise HTTPException(status_code=404, detail="Group not found")
    
    db.delete(db_def)
    db.commit()
    return None