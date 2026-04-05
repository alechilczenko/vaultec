"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException, status
import database.models as models
from auth.utils import verify_password

def authenticate_user(db: Session, username: str, password: str):
    """
    Validates user credentials against the database.
    Raises 401 Unauthorized if invalid.
    """
    user = db.query(models.User).filter(models.User.username == username).first()
    
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},)
    return user