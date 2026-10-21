"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from loguru import logger
from sqlalchemy.orm import Session
from fastapi import HTTPException, status
import database.models as models
from auth.utils import verify_password

def authenticate_user(db: Session, username: str, password: str):
    """
    Validates user credentials against the database.
    Raises 401 Unauthorized if invalid or the account is inactive.
    """
    user = db.query(models.User).filter(models.User.username == username).first()
    
    if not user or not verify_password(password, user.hashed_password):
        logger.warning(f"Failed login attempt for username: '{username}'")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},)

    if not user.is_active:
        logger.warning(f"Login blocked for inactive user: '{username}'")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user account",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    logger.info(f"User authenticated successfully: '{username}'")
    return user

def verify_user_token(current_user: models.User):
    """
    Session bootstrap helper. is_active is already enforced by get_current_user.
    """
    logger.debug(f"Token verified for active user: '{current_user.username}'")
    return current_user