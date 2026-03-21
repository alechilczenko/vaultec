"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import Depends, FastAPI
from contextlib import asynccontextmanager
from database.db import engine
from database.models import Base
from auth.auth_setup import setup_admin_user
from auth.auth_utils import get_current_user
from routes import catalog, findings, notes, auth, assets, admin

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    
    # Launch admin config
    setup_admin_user()
    
    yield

app = FastAPI(lifespan=lifespan)

app.include_router(auth.router) # Only unprotected endpoint

app.include_router(catalog.router,dependencies=[Depends(get_current_user)])
app.include_router(findings.router,dependencies=[Depends(get_current_user)])
app.include_router(notes.router,dependencies=[Depends(get_current_user)])
app.include_router(assets.router,dependencies=[Depends(get_current_user)])
app.include_router(admin.router,dependencies=[Depends(get_current_user)])