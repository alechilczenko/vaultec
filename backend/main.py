from fastapi import Depends, FastAPI
from contextlib import asynccontextmanager
from db import engine
from models import Base
from auth.auth_setup import setup_admin_user
from auth.auth_utils import get_current_user
from routes import vulnerabilities, notes, auth

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    
    # Launch admin config
    setup_admin_user()
    
    yield

app = FastAPI(lifespan=lifespan)

app.include_router(auth.router) # Only unprotected endpoint

app.include_router(vulnerabilities.router,dependencies=[Depends(get_current_user)])
app.include_router(notes.router,dependencies=[Depends(get_current_user)])
