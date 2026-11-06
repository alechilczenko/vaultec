"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from collections import OrderedDict
from datetime import datetime, timezone
from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func, or_
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status
import database.models as models
import schemas
from schemas.enums import FindingStatus
from services import template_service, asset_service, workspace_service
from utils.slug import slugify
from loguru import logger

_EXPORT_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _prepare_finding_read(db: Session, finding: models.Vulnerability) -> models.Vulnerability:
    """Ensures nested asset carries findings_count and max_severity for AssetRead."""
    if finding.asset is not None:
        asset_service.attach_finding_summary(db, finding.asset)
    return finding


def _duplicate_finding_detail(asset_name: str, definition_title: str) -> str:
    return f"{asset_name} already has a finding for '{definition_title}'."


def _raise_duplicate_finding(asset_name: str, definition_title: str) -> None:
    logger.warning(
        f"Duplicate finding blocked: '{definition_title}' already present on '{asset_name}'"
    )
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=_duplicate_finding_detail(asset_name, definition_title),
    )


def update_finding(db: Session, db_obj: models.Vulnerability, update_data: dict):
    finding_id = db_obj.id
    finding_title = db_obj.definition.title if db_obj.definition else "Unknown Title"

    try:
        for key, value in update_data.items():
            setattr(db_obj, key, value)
        
        db.commit()
        db.refresh(db_obj)
        logger.info(f"Finding updated: '{finding_title}' (ID: {finding_id})")
        return _prepare_finding_read(db, db_obj)
    except Exception:
        db.rollback()
        logger.exception(f"Failed to update finding '{finding_title}' (ID: {finding_id})")
        raise HTTPException(
            status_code=500,
            detail="Could not update this finding."
        )


def relink_finding(db: Session, finding_id: int, definition_id: int):
    """Re-point a finding at another template. Instance fields stay untouched."""
    finding = get_finding_by_id(db, finding_id)
    new_defn = template_service.get_definition_or_404(db, definition_id)

    if finding.definition_id == new_defn.id:
        return finding

    asset_name = finding.asset.name if finding.asset else "Unknown Asset"
    conflict = db.query(models.Vulnerability).filter(
        models.Vulnerability.definition_id == new_defn.id,
        models.Vulnerability.asset_id == finding.asset_id,
        models.Vulnerability.id != finding.id,
    ).first()
    if conflict:
        _raise_duplicate_finding(asset_name, new_defn.title)

    old_title = finding.definition.title if finding.definition else "Unknown Title"
    finding.definition_id = new_defn.id
    try:
        db.commit()
        db.refresh(finding)
        logger.info(
            f"Finding relinked: '{old_title}' → '{new_defn.title}' "
            f"on '{asset_name}' (ID: {finding_id})"
        )
        return _prepare_finding_read(db, finding)
    except IntegrityError:
        db.rollback()
        _raise_duplicate_finding(asset_name, new_defn.title)
    except Exception:
        db.rollback()
        logger.exception(
            f"Failed to relink finding (ID: {finding_id}) to definition {definition_id}"
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not relink this finding.",
        )

def delete_finding(db: Session, db_obj: models.Vulnerability):
    finding_id = db_obj.id
    vuln_title = db_obj.definition.title if db_obj.definition else "Unknown Title"
    asset_name = db_obj.asset.name if db_obj.asset else "Unknown Asset"

    try:
        db.delete(db_obj)
        db.commit()
        logger.info(f"Finding deleted: '{vuln_title}' on Asset '{asset_name}' (ID: {finding_id})")
        return True 
    except Exception:
        db.rollback()
        logger.exception(f"Failed to delete finding '{vuln_title}' (ID: {finding_id})")
        raise HTTPException(
            status_code=500,
            detail="Could not delete this finding."
        )
    
def get_finding_stats(db: Session):
    severity_order = ["critical", "high", "medium", "low", "info"]
    status_order = [s.value for s in FindingStatus]

    severity_rows = db.query(
        models.VulnerabilityDefinition.severity,
        func.count(models.Vulnerability.id)
    ).join(
        models.Vulnerability,
        models.Vulnerability.definition_id == models.VulnerabilityDefinition.id
    ).group_by(
        models.VulnerabilityDefinition.severity
    ).all()

    status_rows = db.query(
        models.Vulnerability.status,
        func.count(models.Vulnerability.id)
    ).group_by(
        models.Vulnerability.status
    ).all()

    severity_map = {severity: count for severity, count in severity_rows}
    status_map = {status: count for status, count in status_rows}

    return {
        "by_severity": {sev: severity_map.get(sev, 0) for sev in severity_order},
        "by_status": {st: status_map.get(st, 0) for st in status_order},
    }

def get_finding_by_id(db: Session, finding_id: int):
    finding = db.query(models.Vulnerability).filter(
        models.Vulnerability.id == finding_id
    ).first()

    if not finding:
        raise HTTPException(
            status_code=404,
            detail=f"Finding {finding_id} was not found."
        )
    return _prepare_finding_read(db, finding)

def get_or_create_finding(db: Session, defn: models.VulnerabilityDefinition, asset: models.Asset, vulnerability_data: dict):
    """400 if any finding already exists for that pair, including closed ones.
    Concurrent inserts collide on uq_vulnerability_definition_asset.
    """
    existing_finding = db.query(models.Vulnerability).filter(
        models.Vulnerability.definition_id == defn.id,
        models.Vulnerability.asset_id == asset.id
    ).first()

    if existing_finding:
        _raise_duplicate_finding(asset.name, defn.title)

    new_finding = models.Vulnerability(
        definition_id=defn.id,
        asset_id=asset.id,
        **vulnerability_data
    )
    try:
        db.add(new_finding)
        db.commit()
        db.refresh(new_finding)
        logger.info(f"New finding created: '{defn.title}' on '{asset.name}'")
        return _prepare_finding_read(db, new_finding)

    except IntegrityError:
        db.rollback()
        _raise_duplicate_finding(asset.name, defn.title)

    except Exception:
        db.rollback()
        logger.exception(f"Failed to save finding for asset '{asset.name}'")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Could not save this finding."
        )

def _resolve_definition_for_write(
    db: Session,
    *,
    definition_id: int | None,
    title: str | None,
    severity,
    category=None,
    description=None,
    recommendation=None,
    tags=None,
) -> models.VulnerabilityDefinition:
    """Link an existing template by id, or always insert a new one from fields."""
    if definition_id is not None:
        return template_service.get_definition_or_404(db, definition_id)

    return template_service.create_definition_from_fields(
        db,
        title=title,
        severity=severity,
        category=category,
        description=description,
        recommendation=recommendation,
        tags=tags,
    )


def _process_finding_write(
    db: Session,
    *,
    definition_id: int | None,
    title: str | None,
    severity,
    category,
    description,
    recommendation,
    tags,
    asset_name: str,
    status,
    evidence,
    discovered_by,
    notes,
):
    """Shared write path for POST /findings/create."""
    target_asset = asset_service.get_asset_by_name_silent(db, asset_name)

    if not target_asset:
        logger.error(f"Asset lookup failed: '{asset_name}' not found.")
        raise HTTPException(
            status_code=404,
            detail=f"Asset '{asset_name}' not found. Please register it first."
        )

    target_defn = _resolve_definition_for_write(
        db,
        definition_id=definition_id,
        title=title,
        severity=severity,
        category=category,
        description=description,
        recommendation=recommendation,
        tags=tags,
    )

    finding_info = {
        "status": status,
        "evidence": None if evidence is None else evidence.model_dump(mode="json"),
        "discovered_by": discovered_by,
        "notes": notes,
    }
    return get_or_create_finding(db, target_defn, target_asset, finding_info)


def process_vulnerability_entry(db: Session, vuln_data: schemas.VulnerabilityCreate):
    """POST /findings/create — resolve template by id or create one inline."""
    return _process_finding_write(
        db,
        definition_id=vuln_data.definition_id,
        title=vuln_data.title,
        severity=vuln_data.severity,
        category=vuln_data.category,
        description=vuln_data.description,
        recommendation=vuln_data.recommendation,
        tags=vuln_data.tags,
        asset_name=vuln_data.asset_name,
        status=vuln_data.status,
        evidence=vuln_data.evidence,
        discovered_by=vuln_data.discovered_by,
        notes=vuln_data.notes,
    )


def group_findings_for_export(rows: list[models.Vulnerability]) -> list[dict]:
    """Collapse instances into definition → assets[] for report export.

    Definition text (description, recommendation, …) appears once; instance
    fields (status, evidence, discovered_by, notes) stay per asset.
    """
    groups: OrderedDict[int, dict] = OrderedDict()
    for row in rows:
        defn = row.definition
        asset = row.asset
        group = groups.get(defn.id)
        if group is None:
            group = {
                "id": defn.id,
                "title": defn.title,
                "severity": defn.severity,
                "category": defn.category,
                "description": defn.description,
                "recommendation": defn.recommendation,
                "tags": list(defn.tags or []),
                "assets": [],
            }
            groups[defn.id] = group

        group["assets"].append({
            "finding_id": row.id,
            "asset_id": asset.id,
            "asset_name": asset.name,
            "asset_type": asset.type,
            "status": row.status,
            "evidence": row.evidence,
            "discovered_by": row.discovered_by,
            "notes": row.notes,
            "created_at": row.created_at,
        })

    items = list(groups.values())
    items.sort(
        key=lambda g: (
            _EXPORT_SEVERITY_RANK.get(str(g["severity"]), 99),
            (g["title"] or "").lower(),
        )
    )
    for g in items:
        g["assets"].sort(key=lambda a: (a["asset_name"] or "").lower())
    return items


def export_findings_grouped(db: Session) -> list[dict]:
    """All findings in the active assessment, grouped by definition for reports."""
    rows = (
        db.query(models.Vulnerability)
        .options(
            joinedload(models.Vulnerability.definition),
            joinedload(models.Vulnerability.asset),
        )
        .all()
    )
    return group_findings_for_export(rows)


def build_findings_export(db: Session) -> dict:
    """Full report envelope: workspace header + grouped findings."""
    ws = workspace_service.get_active_workspace(db)
    findings = export_findings_grouped(db)
    return {
        "workspace": {
            "name": ws.name,
            "client_name": ws.client_name,
            "created_at": ws.created_at,
        },
        "exported_at": datetime.now(timezone.utc),
        "findings": findings,
        "total": len(findings),
    }


def export_download_filename(payload: dict) -> str:
    """Build Content-Disposition filename: {client}-findings-{YYYY-MM-DD}.json."""
    workspace = payload.get("workspace") or {}
    client = slugify(workspace.get("client_name") or "") or "assessment"
    exported_at = payload.get("exported_at") or datetime.now(timezone.utc)
    if isinstance(exported_at, str):
        day = exported_at[:10]
    else:
        day = exported_at.strftime("%Y-%m-%d")
    return f"{client}-findings-{day}.json"


def get_vulnerabilities_joined(db: Session, skip: int = 0, limit: int = 100, search_query: str = None):
    """Returns (rows, total). total uses the same filters and ignores skip and limit."""
    base = (
        db.query(models.Vulnerability.id)
        .join(models.Asset, models.Vulnerability.asset_id == models.Asset.id)
        .join(
            models.VulnerabilityDefinition,
            models.Vulnerability.definition_id == models.VulnerabilityDefinition.id,
        )
    )
    if search_query:
        base = base.filter(
            or_(
                models.VulnerabilityDefinition.title.ilike(f"%{search_query}%"),
                models.Asset.name.ilike(f"%{search_query}%"),
            )
        )
    total = base.count()

    query = db.query(
        models.Vulnerability.created_at,
        models.Asset.name.label("asset_name"),
        models.VulnerabilityDefinition.title,
        models.VulnerabilityDefinition.severity,
        models.VulnerabilityDefinition.category,
        models.Vulnerability.status,
        models.Vulnerability.discovered_by,
        models.Vulnerability.id.label("instance_id"),
        models.Vulnerability.definition_id,
    ).join(models.Asset, models.Vulnerability.asset_id == models.Asset.id).join(
        models.VulnerabilityDefinition,
        models.Vulnerability.definition_id == models.VulnerabilityDefinition.id,
    )
    if search_query:
        query = query.filter(
            or_(
                models.VulnerabilityDefinition.title.ilike(f"%{search_query}%"),
                models.Asset.name.ilike(f"%{search_query}%"),
            )
        )
    return query.offset(skip).limit(limit).all(), total


def bulk_process_vulnerabilities(db: Session, import_data: schemas.VulnerabilityBulkImport):
    """All-or-nothing import. Any invalid row cancels the entire batch (no partial writes)."""
    rows = list(import_data.vulnerabilities)
    total = len(rows)
    if total == 0:
        return {
            "message": "Import completed.",
            "summary": {"imported": 0, "failed": 0, "total": 0},
            "details": {"errors": []},
        }

    errors: list[str] = []
    prepared: list[dict] = []
    seen_pairs: set[tuple[int, int]] = set()

    for index, vuln in enumerate(rows):
        row = f"Row {index + 1}"
        asset = asset_service.get_asset_by_name_silent(db, vuln.asset_name)
        if not asset:
            errors.append(
                f"{row}: asset '{vuln.asset_name}' not found. Please register it first."
            )
            continue

        if vuln.definition_id is not None:
            defn = template_service.get_definition_by_id(db, vuln.definition_id)
            if not defn:
                errors.append(f"{row}: template {vuln.definition_id} was not found.")
                continue

            pair = (defn.id, asset.id)
            if pair in seen_pairs:
                errors.append(
                    f"{row}: {_duplicate_finding_detail(asset.name, defn.title)} "
                    "(duplicate in import file)."
                )
                continue
            existing = (
                db.query(models.Vulnerability)
                .filter(
                    models.Vulnerability.definition_id == defn.id,
                    models.Vulnerability.asset_id == asset.id,
                )
                .first()
            )
            if existing:
                errors.append(f"{row}: {_duplicate_finding_detail(asset.name, defn.title)}")
                continue

            seen_pairs.add(pair)
            prepared.append({
                "asset": asset,
                "defn": defn,
                "inline": None,
                "status": vuln.status,
                "evidence": (
                    None
                    if vuln.evidence is None
                    else vuln.evidence.model_dump(mode="json")
                ),
                "discovered_by": vuln.discovered_by,
                "notes": vuln.notes,
            })
            continue

        prepared.append({
            "asset": asset,
            "defn": None,
            "inline": {
                "title": vuln.title,
                "severity": vuln.severity,
                "category": vuln.category,
                "description": vuln.description,
                "recommendation": vuln.recommendation,
                "tags": list(vuln.tags or []),
            },
            "status": vuln.status,
            "evidence": (
                None
                if vuln.evidence is None
                else vuln.evidence.model_dump(mode="json")
            ),
            "discovered_by": vuln.discovered_by,
            "notes": vuln.notes,
        })

    if errors:
        preview = "; ".join(errors[:8])
        extra = f" (+{len(errors) - 8} more)" if len(errors) > 8 else ""
        logger.warning(
            f"Findings import cancelled before write: {len(errors)} issue(s) in {total} row(s)"
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Import cancelled. {preview}{extra}",
        )

    try:
        for item in prepared:
            defn = item["defn"]
            if defn is None:
                fields = item["inline"]
                defn = models.VulnerabilityDefinition(
                    title=fields["title"],
                    severity=fields["severity"],
                    category=fields["category"] or "General",
                    description=fields["description"],
                    recommendation=fields["recommendation"],
                    tags=fields["tags"],
                )
                db.add(defn)
                db.flush()

            db.add(
                models.Vulnerability(
                    definition_id=defn.id,
                    asset_id=item["asset"].id,
                    status=item["status"],
                    evidence=item["evidence"],
                    discovered_by=item["discovered_by"],
                    notes=item["notes"],
                )
            )
            db.flush()

        db.commit()
    except IntegrityError:
        db.rollback()
        logger.warning("Findings import cancelled by integrity conflict")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Import cancelled. A finding conflict was detected.",
        )
    except Exception:
        db.rollback()
        logger.exception("Findings import cancelled by unexpected error")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Import cancelled. Could not import findings.",
        )

    logger.info(f"Findings import completed: {len(prepared)} imported (all-or-nothing)")
    return {
        "message": "Import completed.",
        "summary": {
            "imported": len(prepared),
            "failed": 0,
            "total": total,
        },
        "details": {"errors": []},
    }