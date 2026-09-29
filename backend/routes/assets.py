"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import asset_service
import schemas.asset as schemas
from schemas.common import SafeIntID

router = APIRouter(
    prefix="/assets",
    tags=["Assets"]
)


@router.get("", response_model=schemas.AssetListRead)
def list_assets(
    db: Session = Depends(get_db), 
    skip: int = Query(0, ge=0, le=10000), 
    limit: int = Query(100, ge=1, le=500)
):
    """
    Retrieves all assets registered in the active workspace.
    """
    return {"assets": asset_service.get_all_assets(db, skip=skip, limit=limit)}


@router.get("/stats")
def get_finding_asset_stats(db: Session = Depends(get_db)):
    """
    Retrieves asset type counts for assets with active vulnerabilities.
    """
    return asset_service.get_asset_type_stats(db)


@router.post("/create", response_model=schemas.AssetRead, status_code=status.HTTP_201_CREATED)
def create_asset(asset: schemas.AssetCreate, db: Session = Depends(get_db)):
    """
    Registers a new asset in the active workspace.
    """
    return asset_service.create_asset(db, asset)


@router.post("/import", response_model=dict)
def import_assets(assets: schemas.AssetBulkImport, db: Session = Depends(get_db)):
    """
    Bulk imports assets into the active workspace.
    """
    return asset_service.import_assets(db, assets)


@router.get("/{id}", response_model=schemas.AssetRead)
def get_asset(id: SafeIntID, db: Session = Depends(get_db)):
    """
    Retrieves a single asset by ID in the active workspace.
    """
    return asset_service.get_asset_by_id(db, id)


@router.get("/{id}/top-finding", response_model=Optional[schemas.TopFindingRead])
def get_asset_top_finding(id: SafeIntID, db: Session = Depends(get_db)):
    """
    Retrieves the highest-severity finding for an asset, or null if none exist.
    """
    return asset_service.get_top_finding_for_asset(db, id)


@router.patch("/{id}", response_model=schemas.AssetRead)
def update_asset(id: SafeIntID, asset_data: schemas.AssetUpdate, db: Session = Depends(get_db)):
    """
    Updates an asset's details in the active workspace.
    """
    db_asset = asset_service.get_asset_by_id(db, id)
    update_dict = asset_data.model_dump(exclude_unset=True)
    return asset_service.update_asset(db, db_asset, update_dict)


@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(id: SafeIntID, db: Session = Depends(get_db)):
    """
    Deletes an asset from the active workspace.
    """
    db_asset = asset_service.get_asset_by_id(db, id)
    asset_service.delete_asset(db, db_asset)
    return None