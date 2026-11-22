"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU AGPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from starlette import status
from database.db import get_db
from auth.utils import create_access_token, get_current_user
from schemas import auth
from schemas.user import UserRead

from services import auth_service
router = APIRouter(
    prefix="/auth",
    tags=["Authentication"])

@router.post("/token", response_model=auth.Token)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = auth_service.authenticate_user(db, form_data.username, form_data.password)
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/verify", status_code=status.HTTP_200_OK, response_model=UserRead, summary="Verify JWT token validity")
def verify_token(current_user: auth_service.models.User = Depends(get_current_user)):
    return auth_service.verify_user_token(current_user)