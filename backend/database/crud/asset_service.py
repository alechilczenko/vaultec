"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from fastapi import HTTPException
from typing import List
import database.models as models
import schemas

def check_asset_exists(db: Session, asset_id: int):
    """
    Validates if an asset exists in the database.
    Raises 404 if not found.
    """
    db_asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()
    if not db_asset:
        raise HTTPException(status_code=404, detail=f"Reference Error: Asset with ID {asset_id} does not exist. Cannot link finding.")
    return db_asset

def get_all_assets(db: Session):
    """
    Retrieves all assets.
    """
    return db.query(models.Asset).all()

def create_asset(db: Session, asset: schemas.AssetCreate):
    """
    Creates a new asset after verifying the name is unique.
    """
    db_asset = db.query(models.Asset).filter(models.Asset.name == asset.name).first()
    if db_asset:
        raise HTTPException(status_code=400, detail=f"Conflict: Asset with name '{asset.name}' is already registered.")
    
    new_asset = models.Asset(name=asset.name, type=asset.type, description=asset.description)
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)
    return new_asset

def update_asset(db: Session, db_asset: models.Asset, update_data: dict):
    """
    Updates an asset, ensuring the new name does not conflict with existing ones.
    """
    if "name" in update_data:
        new_name = update_data["name"]
        existing = db.query(models.Asset).filter(models.Asset.name == update_data["name"], models.Asset.id != db_asset.id).first()
        if existing:
            raise HTTPException(status_code=400, detail=f"Update Conflict: The name '{new_name}' is already assigned to another asset (ID: {existing.id}).")

    for key, value in update_data.items():
        setattr(db_asset, key, value)

    db.commit()
    db.refresh(db_asset)
    return db_asset

def import_assets(db: Session, assets: List[schemas.AssetCreate]):
    """
    Bulk imports assets, skipping those with existing names.
    """
    added_count = 0
    skipped_count = 0
    
    existing_names = {a.name for a in db.query(models.Asset.name).all()}
    
    new_assets_objs = []
    for asset_data in assets:
        if asset_data.name not in existing_names:
            new_assets_objs.append(models.Asset(name=asset_data.name,type=asset_data.type,description=asset_data.description))
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

def delete_asset(db: Session, db_asset: models.Asset):
    """
    Deletes an asset and handles potential integrity conflicts.
    """
    asset_name = db_asset.name
    try:
        db.delete(db_asset)
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=f"Dependency Error: Cannot delete '{asset_name}'. It has associated findings that must be removed first."
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Internal Server Error: An unexpected error occurred while deleting the asset."
        )