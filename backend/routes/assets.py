"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from database.db import get_db
from typing import List
from database.crud import asset_service
import schemas.asset as schemas

router = APIRouter(
    prefix="/assets",
    tags=["Assets"]
)
@router.get("", response_model=List[schemas.AssetRead])
def list_assets(db: Session = Depends(get_db)):
    return asset_service.get_all_assets(db)

@router.post("", response_model=schemas.AssetRead)
def create_asset(asset: schemas.AssetCreate, db: Session = Depends(get_db)):
    return asset_service.create_asset(db,asset)

@router.patch("/{id}", response_model=schemas.AssetRead)
def update_asset(id: int, asset_data: schemas.AssetUpdate, db: Session = Depends(get_db)):
    db_asset = asset_service.check_asset_exists(db, id)
    update_dict = asset_data.model_dump(exclude_unset=True)
    return asset_service.update_asset(db, db_asset, update_dict)

@router.post("/import", response_model=dict)
def import_assets(assets: List[schemas.AssetCreate], db: Session = Depends(get_db)):
    return asset_service.import_assets(db, assets)

@router.delete("/{id}", status_code=204)
def delete_asset(id: int, db: Session = Depends(get_db)):
    db_asset = asset_service.check_asset_exists(db, id)
    asset_service.delete_asset(db, db_asset)
    return None

