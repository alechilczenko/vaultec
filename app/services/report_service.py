"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

from fastapi import HTTPException, status
from jinja2 import Environment, FileSystemLoader, select_autoescape
from sqlalchemy.orm import Session

import schemas
from services import finding_service
from utils.slug import slugify

_UI_ROOT = Path(__file__).resolve().parent.parent / "ui"
_TEMPLATE_DIR = _UI_ROOT / "pages" / "reports"
_BRAND_MARK_PATH = _UI_ROOT / "static" / "img" / "favicon-64.png"
_BRAND_NAME = "Vaultec"


@lru_cache(maxsize=4)
def _brand_mark_data_uri(mtime_ns: int) -> str:
    """Embed the app favicon so headless Chrome can render the cover mark offline."""
    data = _BRAND_MARK_PATH.read_bytes()
    encoded = base64.standard_b64encode(data).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def brand_mark_data_uri() -> str:
    """Return the current favicon data URI (cache key = file mtime)."""
    mtime_ns = _BRAND_MARK_PATH.stat().st_mtime_ns if _BRAND_MARK_PATH.is_file() else 0
    return _brand_mark_data_uri(mtime_ns)

_STATUS_LABELS = {
    "open": "Open",
    "remediated": "Remediated",
    "risk_accepted": "Risk Accepted",
    "false_positive": "False Positive",
}

_CHROME_CANDIDATES = (
    "CHROME_PATH",
    "GOOGLE_CHROME_BIN",
)


def _chrome_binaries() -> list[str]:
    found: list[str] = []
    for env_key in _CHROME_CANDIDATES:
        value = (os.environ.get(env_key) or "").strip()
        if value:
            found.append(value)
    for name in (
        "google-chrome-stable",
        "google-chrome",
        "chromium",
        "chromium-browser",
        "chrome",
    ):
        path = shutil.which(name)
        if path:
            found.append(path)
    # De-dupe preserving order
    seen: set[str] = set()
    ordered: list[str] = []
    for item in found:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def resolve_chrome_path() -> Optional[str]:
    for path in _chrome_binaries():
        if path and Path(path).is_file() and os.access(path, os.X_OK):
            return path
    return None


def _jinja_env() -> Environment:
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
    )


def format_report_date(value: Any) -> str:
    """Human date like '16 March 2026'."""
    dt = _as_datetime(value)
    if not dt:
        return ""
    return f"{dt.day} {dt.strftime('%B %Y')}"


def format_asset_datetime(value: Any) -> str:
    """Compact local-ish stamp: '2026-03-12 14:22'."""
    dt = _as_datetime(value)
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M")


def _as_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def status_label(value: Any) -> str:
    key = str(value or "open").lower().strip().replace(" ", "_")
    return _STATUS_LABELS.get(key, key.replace("_", " ").title() or "Open")


def severity_label(value: Any) -> str:
    return str(value or "").strip().upper() or "INFO"


def tags_line(category: Any, tags: Any) -> str:
    parts: list[str] = []
    cat = (str(category).strip() if category else "") or ""
    if cat:
        parts.append(cat)
    tag_list = [str(t).strip() for t in (tags or []) if str(t).strip()]
    if tag_list:
        parts.append(", ".join(tag_list))
    return " · ".join(parts)


def evidence_blocks(evidence: Any) -> list[dict]:
    """Flatten Evidence JSON into printable {heading, content} blocks."""
    if not evidence:
        return []
    if hasattr(evidence, "model_dump"):
        evidence = evidence.model_dump(mode="json")
    packages = evidence.get("packages") if isinstance(evidence, dict) else None
    if not isinstance(packages, list):
        return []

    blocks: list[dict] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        pkg_type = str(package.get("type") or "general").lower()
        items = package.get("items") or []
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            content = str(item.get("content") or "").rstrip()
            if not content:
                continue
            label = str(item.get("label") or "").strip()
            if pkg_type == "http":
                heading = f"HTTP · {label}" if label else "HTTP"
            else:
                heading = label or "Evidence"
            blocks.append({"heading": heading, "content": content})
    return blocks


def prepare_report_context(payload: dict) -> dict:
    """Normalize FindingExportRead dump for the Jinja report template."""
    workspace = payload.get("workspace") or {}
    exported_at = payload.get("exported_at")
    findings_in = payload.get("findings") or []

    client_name = (workspace.get("client_name") or "").strip() or "Client"
    assessment_name = (workspace.get("name") or "").strip() or "Assessment"
    report_date = format_report_date(exported_at) or format_report_date(
        datetime.now(timezone.utc)
    )
    footer_meta = f"{client_name} · {assessment_name} · {report_date}"

    findings: list[dict] = []
    for index, raw in enumerate(findings_in, start=1):
        assets_out: list[dict] = []
        for asset in raw.get("assets") or []:
            discovered = (asset.get("discovered_by") or "").strip() or "Unassigned"
            assets_out.append(
                {
                    "asset_name": asset.get("asset_name") or "—",
                    "asset_type": asset.get("asset_type") or "Asset",
                    "status": status_label(asset.get("status")),
                    "status_key": str(asset.get("status") or "open").lower(),
                    "discovered_by": discovered,
                    "created_at": format_asset_datetime(asset.get("created_at")),
                    "evidence_blocks": evidence_blocks(asset.get("evidence")),
                }
            )
        findings.append(
            {
                "index": index,
                "title": raw.get("title") or "Untitled finding",
                "severity": severity_label(raw.get("severity")),
                "severity_key": str(raw.get("severity") or "info").lower(),
                "meta_line": tags_line(raw.get("category"), raw.get("tags")),
                "description": (raw.get("description") or "").strip(),
                "recommendation": (raw.get("recommendation") or "").strip(),
                "assets": assets_out,
            }
        )

    return {
        "brand_name": _BRAND_NAME,
        "brand_mark_src": brand_mark_data_uri(),
        "assessment_name": assessment_name,
        "client_name": client_name,
        "report_date": report_date,
        "footer_meta": footer_meta,
        "findings": findings,
        "total": int(payload.get("total") or len(findings)),
    }


def render_findings_report_html(payload: dict) -> str:
    ctx = prepare_report_context(payload)
    template = _jinja_env().get_template("findings_report.html")
    return template.render(**ctx)


def html_to_pdf(html: str, *, chrome_path: Optional[str] = None) -> bytes:
    """Render HTML to PDF bytes via headless Chrome/Chromium."""
    binary = chrome_path or resolve_chrome_path()
    if not binary:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "PDF renderer unavailable. Install Google Chrome or Chromium, "
                "or set CHROME_PATH."
            ),
        )

    with tempfile.TemporaryDirectory(prefix="vmp-report-") as tmp:
        tmp_path = Path(tmp)
        html_path = tmp_path / "report.html"
        pdf_path = tmp_path / "report.pdf"
        user_data = tmp_path / "chrome-profile"
        user_data.mkdir()
        html_path.write_text(html, encoding="utf-8")

        cmd = [
            binary,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--no-pdf-header-footer",
            f"--user-data-dir={user_data}",
            f"--print-to-pdf={pdf_path}",
            html_path.resolve().as_uri(),
        ]
        try:
            completed = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="PDF renderer timed out.",
            ) from exc
        except OSError as exc:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="PDF renderer failed to start.",
            ) from exc

        if completed.returncode != 0 or not pdf_path.is_file():
            stderr = (completed.stderr or completed.stdout or "").strip()
            detail = "PDF renderer failed."
            if stderr:
                detail = f"PDF renderer failed: {stderr[:400]}"
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=detail,
            )
        return pdf_path.read_bytes()


def export_pdf_filename(payload: dict) -> str:
    workspace = payload.get("workspace") or {}
    client = slugify(workspace.get("client_name") or "") or "assessment"
    exported_at = payload.get("exported_at") or datetime.now(timezone.utc)
    if isinstance(exported_at, str):
        day = exported_at[:10]
    else:
        day = exported_at.strftime("%Y-%m-%d")
    return f"{client}-findings-{day}.pdf"


def build_findings_report_pdf(db: Session) -> tuple[bytes, str]:
    """Build PDF bytes + download filename from the active assessment export."""
    payload = finding_service.build_findings_export(db)
    body = schemas.FindingExportRead.model_validate(payload).model_dump(mode="json")
    html = render_findings_report_html(body)
    pdf = html_to_pdf(html)
    return pdf, export_pdf_filename(body)
