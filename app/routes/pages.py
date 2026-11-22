"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates

UI = Path(__file__).resolve().parent.parent / "ui"
templates = Jinja2Templates(directory=UI / "pages")
router = APIRouter(include_in_schema=False)


@router.get("/")
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html")


# HTML shell only — does not register GET /workspace (JSON API owns that).
@router.get("/workspace/templates")
def templates_page(request: Request):
    return templates.TemplateResponse(request, "workspace/templates.html")


@router.get("/workspace/assets")
def assets_page(request: Request):
    return templates.TemplateResponse(request, "workspace/assets.html")


@router.get("/workspace/findings")
def findings_page(request: Request):
    return templates.TemplateResponse(request, "workspace/findings.html")
