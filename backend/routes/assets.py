"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.db import get_db
import database.models as models
import schemas.asset as schemas
from typing import List

router = APIRouter(
    prefix="/assets",
    tags=["Assets"]
)
@router.get("", response_model=List[schemas.AssetRead])
def list_assets(db: Session = Depends(get_db)):
    return db.query(models.Asset).all()

@router.post("", response_model=schemas.AssetRead)
def create_asset(asset: schemas.AssetCreate, db: Session = Depends(get_db)):

    db_asset = db.query(models.Asset).filter(models.Asset.name == asset.name).first()
    if db_asset:
        raise HTTPException(status_code=400, detail="Asset already exists")
    
    new_asset = models.Asset(name=asset.name, type=asset.type)
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)
    return new_asset

@router.patch("/{id}", response_model=schemas.AssetRead)
def update_asset(asset_id: int, asset_data: schemas.AssetUpdate, db: Session = Depends(get_db)):

    db_asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    
    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    update_dict = asset_data.model_dump(exclude_unset=True)

    if "name" in update_dict:
        existing = db.query(models.Asset).filter(
            models.Asset.name == update_dict["name"], 
            models.Asset.id != asset_id
        ).first()
        if existing:
            raise HTTPException(status_code=400, detail="Asset with this name already exists")

    for key, value in update_dict.items():
        setattr(db_asset, key, value)

    db.commit()
    db.refresh(db_asset)
    return db_asset

@router.post("/import", response_model=dict)
def import_assets(assets: List[schemas.AssetCreate], db: Session = Depends(get_db)):
    added_count = 0
    skipped_count = 0
    
    existing_names = {a.name for a in db.query(models.Asset.name).all()}
    
    new_assets_objs = []
    for asset_data in assets:
        if asset_data.name not in existing_names:
            new_assets_objs.append(models.Asset(
                name=asset_data.name,
                type=asset_data.type,
                description=asset_data.description
            ))
            existing_names.add(asset_data.name)
            added_count += 1
        else:
            skipped_count += 1
            
    if new_assets_objs:
        db.add_all(new_assets_objs)
        db.commit()
        
    return {
        "message": "Import completed",
        "added": added_count,
        "skipped": skipped_count
    }

@router.delete("/{id}", status_code=204)
def delete_asset(asset_id: int, db: Session = Depends(get_db)):
    db_asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    db.delete(db_asset)
    db.commit()
    return None

