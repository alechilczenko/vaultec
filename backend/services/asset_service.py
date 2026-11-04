"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
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
    (models.VulnerabilityDefinition.severity == "info", 1),
    else_=0,
)

_RANK_TO_SEVERITY = {
    5: "critical",
    4: "high",
    3: "medium",
    2: "low",
    1: "info",
}


def severity_from_rank(rank) -> str | None:
    """None when the rank is unset."""
    if rank is None:
        return None
    return _RANK_TO_SEVERITY.get(int(rank))


def _finding_summary_query(db: Session):
    return db.query(
        func.count(models.Vulnerability.id),
        func.max(_SEVERITY_RANK),
    ).outerjoin(
        models.VulnerabilityDefinition,
        models.Vulnerability.definition_id == models.VulnerabilityDefinition.id,
    )


def attach_finding_summary(db: Session, asset: models.Asset) -> models.Asset:
    """Attaches findings_count and max_severity for AssetRead serialization."""
    count, rank = (
        _finding_summary_query(db)
        .filter(models.Vulnerability.asset_id == asset.id)
        .one()
    )
    asset.findings_count = count or 0
    asset.max_severity = severity_from_rank(rank)
    return asset


def get_asset_by_id(db: Session, asset_id: int):
    db_asset = db.query(models.Asset).filter(models.Asset.id == asset_id).first()

    if not db_asset:
        raise HTTPException(status_code=404, detail="Asset not found in active workspace.")
    return attach_finding_summary(db, db_asset)


def get_asset_by_name_silent(db: Session, name: str):
    return db.query(models.Asset).filter(models.Asset.name == name).first()


def get_all_assets(db: Session, skip: int = 0, limit: int = 100):
    """Returns (assets, total). total ignores skip and limit."""
    total = db.query(func.count(models.Asset.id)).scalar() or 0
    findings_count = func.count(models.Vulnerability.id).label("findings_count")
    max_rank = func.max(_SEVERITY_RANK).label("max_rank")
    rows = (
        db.query(models.Asset, findings_count, max_rank)
        .outerjoin(
            models.Vulnerability,
            models.Vulnerability.asset_id == models.Asset.id,
        )
        .outerjoin(
            models.VulnerabilityDefinition,
            models.Vulnerability.definition_id == models.VulnerabilityDefinition.id,
        )
        .group_by(models.Asset.id)
        .offset(skip)
        .limit(limit)
        .all()
    )
    assets = []
    for asset, count, rank in rows:
        asset.findings_count = count
        asset.max_severity = severity_from_rank(rank)
        assets.append(asset)
    return assets, total

def get_asset_stats(db: Session):
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
    new_asset.max_severity = None
    logger.info(f"Asset created: {asset.name} (ID: {new_asset.id})")
    return new_asset


def update_asset(db: Session, db_asset: models.Asset, update_data: dict):
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
    return attach_finding_summary(db, db_asset)


def import_assets(db: Session, assets: schemas.AssetBulkImport):
    """Skips names that are already registered."""
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
            logger.info(f"Imported {len(added_names)} assets")
        except Exception:
            db.rollback()
            logger.exception("Bulk asset import failed")
            raise HTTPException(status_code=500, detail="Could not import these assets.")

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
    asset_name = db_asset.name
    try:
        db.delete(db_asset)
        db.commit()
        logger.info(f"Asset '{asset_name}' deleted")
    except IntegrityError:
        db.rollback()
        logger.warning(f"Deletion blocked: Asset '{asset_name}' has associated findings")
        raise HTTPException(
            status_code=400,
            detail=f"Cannot delete '{asset_name}' until its findings are removed."
        )
    except Exception:
        db.rollback()
        logger.exception(f"Failed to delete asset '{asset_name}'")
        raise HTTPException(
            status_code=500,
            detail="Could not delete this asset."
        )