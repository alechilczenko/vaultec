"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from fastapi import HTTPException
from loguru import logger
import database.models as models
import schemas

def get_asset_by_id(db: Session, asset_id: int, project_id: int):
    """
    Retrieves an asset by its internal ID.
    Raises a 404 error if the ID does not exist in the database.
    """
    db_asset = db.query(models.Asset).filter(
        models.Asset.id == asset_id, 
        models.Asset.project_id == project_id
    ).first()

    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset not found in this project.")
    return db_asset

def get_asset_by_name(db: Session, name: str, project_id: int):
    """
    Retrieves an asset by its unique name. 
    Raises a 404 error if the asset is not registered in the inventory.
    """
    db_asset = db.query(models.Asset).filter(
        models.Asset.name == name, 
        models.Asset.project_id == project_id
    ).first()
    
    if not db_asset:
        logger.error(f"Asset lookup failed: '{name}' not found in this project.")
        raise HTTPException(
            status_code=404, 
            detail=f"Asset '{name}' not found. Please register the asset before importing findings.")
    return db_asset

def get_all_assets(db: Session, project_id: int, skip: int = 0, limit: int = 100):
    """
    Retrieves all assets.
    """
    return db.query(models.Asset).filter(models.Asset.project_id == project_id).offset(skip).limit(limit).all()

def create_asset(db: Session, asset: schemas.AssetCreate, project_id: int):
    """
    Creates a new asset after verifying the name is unique.
    """
    existing = get_asset_by_name(db, asset.name, project_id)
    if existing:
        logger.warning(f"Asset creation blocked: Name '{asset.name}' already exists in this project")
        raise HTTPException(status_code=400, detail=f"Asset '{asset.name}' already exists in this project.")
    
    new_asset = models.Asset(name=asset.name, type=asset.type, description=asset.description)
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)
    logger.info(f"Asset created: {asset.name} (ID: {new_asset.id})")
    return new_asset

def update_asset(db: Session, db_asset: models.Asset, update_data: dict):
    """
    Updates an asset, ensuring the new name does not conflict with existing ones.
    """
    original_name = db_asset.name

    if "name" in update_data:
        # Check if another asset in the same project already uses the new name
        new_name = update_data["name"]
        existing_conflict = db.query(models.Asset).filter(
            models.Asset.name == new_name,
            models.Asset.project_id == db_asset.project_id,
            models.Asset.id != db_asset.id
        ).first()

        if existing_conflict:
            logger.warning(f"Update failed: Name '{new_name}' already exists in Project ID {db_asset.project_id}")
            raise HTTPException(
                status_code=400, 
                detail=f"The name '{new_name}' is already assigned to another asset in this project."
            )
    for key, value in update_data.items():
        setattr(db_asset, key, value)

    db.commit()
    db.refresh(db_asset)
    logger.info(f"Asset '{original_name}' (ID: {db_asset.id}) updated to '{db_asset.name}'")
    return db_asset

def import_assets(db: Session, assets: schemas.AssetBulkImport, project_id: int):
    """
    Bulk imports assets, skipping those with existing names.
    """
    added_names = []
    skipped_names = []
    
    existing_names = {row[0] for row in db.query(models.Asset.name).filter(models.Asset.project_id == project_id).all()}
    
    new_assets_objs = []
    for asset_data in assets.assets:
        if asset_data.name not in existing_names:
            new_assets_objs.append(models.Asset(name=asset_data.name,type=asset_data.type,description=asset_data.description,project_id=project_id))
            existing_names.add(asset_data.name)
            added_names.append(asset_data.name)
        else:
            skipped_names.append(asset_data.name)
            
    if new_assets_objs:
        try:
            db.add_all(new_assets_objs)
            db.commit()
            logger.info(f"Bulk import successful for Project ID {project_id}: {len(added_names)} assets added")
        except Exception as e:
            db.rollback()
            logger.error(f"Bulk asset import failed for Project ID {project_id}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    return {
        "message": "Import completed",
        "project_id": project_id,
        "summary": {
            "added_count": len(added_names),
            "skipped_count": len(skipped_names)
        },
        "details": {
            "added_assets": added_names,
            "ignored_duplicates": skipped_names
        }
    }

def delete_asset(db: Session, db_asset: models.Asset):
    """
    Deletes an asset and handles potential integrity conflicts.
    """
    asset_name = db_asset.name
    try:
        db.delete(db_asset)
        db.commit()
        logger.info(f"Asset '{asset_name}' deleted successfully")
    except IntegrityError:
        db.rollback()
        logger.warning(f"Deletion blocked: Asset '{asset_name}' has associated findings")
        raise HTTPException(
            status_code=400,
            detail=f"Dependency Error: Cannot delete '{asset_name}'. It has associated findings that must be removed first."
        )
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error deleting asset '{asset_name}': {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Internal Server Error: An unexpected error occurred while deleting the asset."
        )