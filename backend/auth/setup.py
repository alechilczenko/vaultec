"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

import os
import re
import sys
import database.models as models
from dotenv import load_dotenv
from database.db import SessionLocal
from .utils import hash_password
from loguru import logger

def is_password_strong(password: str):
    """
    Check if the password meets the minimum security requirements.
    """
    rules = [
        lambda s: len(s) >= 12,                          # Minimum length
        lambda s: bool(re.search(r"[A-Z]", s)),          # At least one uppercase letter
        lambda s: bool(re.search(r"[a-z]", s)),          # At least one lowercase letter
        lambda s: bool(re.search(r"\d", s)),             # At least one digit
        lambda s: bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", s)) # At least one symbol
    ]
    return all(rule(password) for rule in rules)

def validate_environment():
    """
    Validate that required environment variables are set and secure.
    """
    load_dotenv()
    
    secret_key = os.getenv("SECRET_KEY")
    if not secret_key:
        logger.critical("SECRET_KEY is missing from the environment variables")
        sys.exit(1)
 
    if len(secret_key) < 32:
        logger.critical("The SECRET_KEY is too short (minimum 32 characters)")
        logger.info("Hint: Generate a strong one with 'openssl rand -hex 32'")
        sys.exit(1)

    admin_password = os.getenv("ADMIN_SETUP_PASSWORD")
    if not admin_password:
        logger.critical("ADMIN_SETUP_PASSWORD is missing from the environment variables")
        sys.exit(1)
        
    if not is_password_strong(admin_password):
        logger.critical("ADMIN_SETUP_PASSWORD is too weak.")
        logger.info("Requirements: 12+ characters, including uppercase, lowercase, numbers, and symbols")
        sys.exit(1)        
    return admin_password

def setup_admin_user():
    # Validate environment and get the secure password
    admin_password = validate_environment()

    db = SessionLocal()
    try:
        admin = db.query(models.User).filter(models.User.username == "admin").first()
        
        if not admin:
            admin = models.User(
            username="admin",
            hashed_password=hash_password(admin_password),
            is_active=True)
            db.add(admin)
            db.commit()
            db.refresh(admin)
            logger.info("Admin user created successfully")
        else:
            # Update password from environment variable
            admin.hashed_password = hash_password(admin_password)
            db.commit()
            logger.info("Admin password updated from the environment variable")

    except Exception as e:
        logger.error(f"Database error during admin setup: {e}")
        sys.exit(1)
        
    finally:
        db.close()