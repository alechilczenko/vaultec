"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from database.db import get_db
from typing import List
from database.crud import asset_service
import schemas.asset as schemas
from schemas.common import SafeIntID
from dependencies.project import validate_project

router = APIRouter(
    prefix="/projects/{project_id}/assets",
    tags=["Assets"],
    dependencies=[Depends(validate_project)]
)
@router.get("", response_model=schemas.AssetListRead)
def list_assets(project_id: SafeIntID, db: Session = Depends(get_db), skip: int = Query(0, ge=0, le=10000), limit: int = Query(100, ge=1, le=500)):
    return {"assets": asset_service.get_all_assets(db, project_id, skip=skip, limit=limit)}

@router.post("/create", response_model=schemas.AssetRead)
def create_asset(project_id: SafeIntID, asset: schemas.AssetCreate, db: Session = Depends(get_db)):
    return asset_service.create_asset(db,asset,project_id)

@router.post("/import", response_model=dict)
def import_assets(project_id: SafeIntID, assets: schemas.AssetBulkImport, db: Session = Depends(get_db)):
    return asset_service.import_assets(db, assets, project_id)

@router.patch("/{id}", response_model=schemas.AssetRead)
def update_asset(project_id: SafeIntID, id: SafeIntID, asset_data: schemas.AssetUpdate, db: Session = Depends(get_db)):
    db_asset = asset_service.get_asset_by_id(db, id, project_id)
    update_dict = asset_data.model_dump(exclude_unset=True)
    return asset_service.update_asset(db, db_asset, update_dict)

@router.delete("/{id}", status_code=204)
def delete_asset(project_id: SafeIntID, id: SafeIntID, db: Session = Depends(get_db)):
    db_asset = asset_service.get_asset_by_id(db, id, project_id)
    asset_service.delete_asset(db, db_asset)
    return None

