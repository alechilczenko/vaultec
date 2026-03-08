from fastapi import FastAPI
from contextlib import asynccontextmanager
from db import engine
from models import Base
from auth_setup import setup_admin_user
from routes import vulnerabilities

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    
    # Launch admin config
    setup_admin_user()
    
    yield

app = FastAPI(lifespan=lifespan)
app.include_router(vulnerabilities.router)