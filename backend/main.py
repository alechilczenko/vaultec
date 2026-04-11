"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from database.db import engine
from database.models import Base
from auth.setup import setup_admin_user
from auth.utils import get_current_user
from config.logger_config import setup_app_logging
from routes import catalog, findings, notes, auth, assets, admin
from loguru import logger
import os

# Initialize logging BEFORE creating the FastAPI app
setup_app_logging()

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    try:
        # Launch admin config
        setup_admin_user()
    except SystemExit:
        logger.info("Application stopped: environment validation failed")
        os._exit(1) 
    yield

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],)

app.include_router(auth.router) # Only unprotected endpoint

app.include_router(catalog.router,dependencies=[Depends(get_current_user)])
app.include_router(findings.router,dependencies=[Depends(get_current_user)])
app.include_router(notes.router,dependencies=[Depends(get_current_user)])
app.include_router(assets.router,dependencies=[Depends(get_current_user)])
app.include_router(admin.router,dependencies=[Depends(get_current_user)])