"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from config.logger_config import setup_app_logging

setup_app_logging()

from pathlib import Path
from fastapi import Depends, FastAPI
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from database.db import engine
from database.models import Base
from auth.setup import setup_admin_user
from auth.utils import get_current_user
from dependencies.workspace import require_active_workspace
from routes import admin, assets, auth, findings, notes, pages, templates, workspace
from loguru import logger
from inspect import cleandoc
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Uvicorn's reloader calls dictConfig again before startup.
    setup_app_logging()
    Base.metadata.create_all(bind=engine)
    try:
        setup_admin_user()
    except SystemExit:
        logger.info("Application stopped: environment validation failed")
        os._exit(1) 
    yield

app = FastAPI(
    lifespan=lifespan,
    title="Vaultec",
    description=cleandoc("""
        ## Vaultec
        Open-source workspace API for active security assessments: assets, vulnerability templates, and findings.

        ### Features:
        * **Workspace**: Manage active audit context.
        * **Assets**: Manage infrastructure inventory.
        * **Templates**: Centralized vulnerability definitions.
        * **Findings**: Track and remediate security issues.
    """),
    version="1.0.0",
    contact={
        "name": "Alejandro Chilczenko",
        "url": "https://github.com/alechilczenko",
    },
    openapi_tags=[
        {
            "name": "Authentication",
            "description": "Login and session verification. Only POST /auth/token is public.",
        },
        {
            "name": "Workspace",
            "description": "Single assessment context (id=1). Usable while the workspace is empty.",
        },
        {
            "name": "Templates (Vulnerability Definitions)",
            "description": "Global reusable vulnerability definitions. Survives a workspace reset.",
        },
        {
            "name": "Assets",
            "description": "Engagement inventory. Requires an active assessment.",
        },
        {
            "name": "Findings (Instances)",
            "description": "Finding instances on assets (status, evidence, notes). Requires an active assessment.",
        },
        {
            "name": "Notes",
            "description": "Free-form engagement notes. Requires an active assessment.",
        },
        {
            "name": "Maintenance",
            "description": "Irreversible reset of the workspace or the global template library.",
        },
    ],
)

# Authentication routes (unprotected)
app.include_router(auth.router)

# Protected routes (auth only, usable in library mode when workspace is empty)
app.include_router(workspace.router, dependencies=[Depends(get_current_user)])
app.include_router(templates.router, dependencies=[Depends(get_current_user)])

# Engagement-scoped routes require an active assessment (workspace status == "active")
_engagement_deps = [Depends(get_current_user), Depends(require_active_workspace)]
app.include_router(assets.router, dependencies=_engagement_deps)
app.include_router(findings.router, dependencies=_engagement_deps)
app.include_router(notes.router, dependencies=_engagement_deps)

# Destructive maintenance (auth only; not engagement-gated)
app.include_router(admin.router, dependencies=[Depends(get_current_user)])

# HTML pages (Jinja2 + Alpine). Mount static after JSON routers so /static is not shadowed.
app.include_router(pages.router)
app.mount(
    "/static",
    StaticFiles(directory=Path(__file__).parent / "ui" / "static"),
    name="static",
)

