"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy import case, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from fastapi import HTTPException
from loguru import logger
import database.models as models
import schemas
_SEVERITY_RANK = case(
    (models.VulnerabilityDefinition.severity == "critical", 5),
    (models.VulnerabilityDefinition.severity == "high", 4),
    (models.VulnerabilityDefinition.severity == "medium", 3),
    (models.VulnerabilityDefinition.severity == "low", 2),
    (models.VulnerabilityDefinition.severity == "informative", 1),
    else_=0,
)


def attach_findings_count(db: Session, asset: models.Asset) -> models.Asset:
    """Attaches total findings count (all statuses) onto the asset instance."""
    count = (
        db.query(func.count(models.Vulnerability.id))
        .filter(models.Vulnerability.asset_id == asset.id)
        .scalar()
    ) or 0
    asset.findings_count = count
    return asset


def get_asset_by_id(db: Session, asset_id: int):
    """
    Retrieves an asset by its internal ID in the active workspace.
    Raises a 404 error if the ID does not exist in the database.
    """
    db_asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()

    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset not found in active workspace.")
    return attach_findings_count(db, db_asset)


def get_top_finding_for_asset(db: Session, asset_id: int):
    """
    Returns the highest-severity finding for an asset, or None if it has none.
    Raises 404 if the asset does not exist.
    """
    exists = db.query(models.Asset.id).filter(models.Asset.id == asset_id).first()
    if not exists:
        raise HTTPException(status_code=404, detail="Asset not found in active workspace.")

    row = (
        db.query(
            models.Vulnerability.id,
            models.Vulnerability.status,
            models.Vulnerability.created_at,
            models.VulnerabilityDefinition.title,
            models.VulnerabilityDefinition.severity,
        )
        .join(
            models.VulnerabilityDefinition,
            models.Vulnerability.definition_id == models.VulnerabilityDefinition.id,
        )
        .filter(models.Vulnerability.asset_id == asset_id)
        .order_by(_SEVERITY_RANK.desc(), models.Vulnerability.created_at.desc())
        .first()
    )

    if not row:
        return None

    return schemas.TopFindingRead(
        id=row.id,
        title=row.title,
        severity=row.severity,
        status=row.status,
        created_at=row.created_at,
    )


def get_asset_by_name_silent(db: Session, name: str):
    """Retrieves an asset by its name without throwing exceptions if not found."""
    return db.query(models.Asset).filter(models.Asset.name == name).first()


def get_all_assets(db: Session, skip: int = 0, limit: int = 100):
    """Retrieves all assets in the active workspace with findings counts and pagination."""
    findings_count = func.count(models.Vulnerability.id).label("findings_count")
    rows = (
        db.query(models.Asset, findings_count)
        .outerjoin(
            models.Vulnerability,
            models.Vulnerability.asset_id == models.Asset.id,
        )
        .group_by(models.Asset.id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    assets = []
    for asset, count in rows:
        asset.findings_count = count
        assets.append(asset)
    return assets

def get_asset_stats(db: Session):
    """
    Calculates type counts for all assets in the active workspace.
    """
    type_keys = {"URL": "urls", "IP": "ips", "Host": "hosts"}

    type_rows = db.query(
        models.Asset.type,
        func.count(models.Asset.id)
    ).group_by(
        models.Asset.type
    ).all()

    type_map = {asset_type: count for asset_type, count in type_rows}

    return {
        "by_type": {key: type_map.get(db_type, 0) for db_type, key in type_keys.items()},
    }

def create_asset(db: Session, asset: schemas.AssetCreate):
    """Creates a new asset after verifying the name is unique within the active workspace."""
    existing = get_asset_by_name_silent(db, asset.name)
    if existing:
        raise HTTPException(
            status_code=400, 
            detail=f"Asset '{asset.name}' already exists in active workspace."
        )
    
    new_asset = models.Asset(
        name=asset.name,
        type=asset.type.value,
        notes=asset.notes,
    )
    db.add(new_asset)
    db.commit()
    db.refresh(new_asset)
    new_asset.findings_count = 0
    logger.info(f"Asset created: {asset.name} (ID: {new_asset.id})")
    return new_asset


def update_asset(db: Session, db_asset: models.Asset, update_data: dict):
    """Updates an asset, ensuring the new name does not conflict with existing ones."""
    original_name = db_asset.name

    if "name" in update_data:
        new_name = update_data["name"]
        existing_conflict = db.query(models.Asset).filter(
            models.Asset.name == new_name,
            models.Asset.id != db_asset.id
        ).first()

        if existing_conflict:
            logger.warning(f"Update failed: Name '{new_name}' already exists in active workspace")
            raise HTTPException(
                status_code=400, 
                detail=f"The name '{new_name}' is already assigned to another asset in this workspace."
            )

    for key, value in update_data.items():
        setattr(db_asset, key, value)

    db.commit()
    db.refresh(db_asset)
    logger.info(f"Asset '{original_name}' (ID: {db_asset.id}) updated to '{db_asset.name}'")
    return attach_findings_count(db, db_asset)


def import_assets(db: Session, assets: schemas.AssetBulkImport):
    """Bulk imports assets into the active workspace, skipping existing names."""
    added_names = []
    skipped_names = []
    
    existing_names = {row[0] for row in db.query(models.Asset.name).all()}
    
    new_assets_objs = []
    for asset_data in assets.assets:
        if asset_data.name not in existing_names:
            new_assets_objs.append(
                models.Asset(
                    name=asset_data.name,
                    type=asset_data.type.value,
                    notes=asset_data.notes,
                )
            )
            existing_names.add(asset_data.name)
            added_names.append(asset_data.name)
        else:
            skipped_names.append(asset_data.name)
            
    if new_assets_objs:
        try:
            db.add_all(new_assets_objs)
            db.commit()
            logger.info(f"Bulk import successful: {len(added_names)} assets added")
        except Exception as e:
            db.rollback()
            logger.error(f"Bulk asset import failed: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

    return {
        "message": "Import completed",
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
    """Deletes an asset and handles potential integrity conflicts."""
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