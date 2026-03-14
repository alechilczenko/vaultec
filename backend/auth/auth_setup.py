"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from dotenv import load_dotenv
from db import SessionLocal
import os
import secrets
import string
import models

from .auth_utils import hash_password

def setup_admin_user():
    # Load ENV if exists
    load_dotenv()

    # Get ENV password
    ENV_PASSWORD = os.getenv("ADMIN_SETUP_PASSWORD")

    # Get random string if not defined
    if not ENV_PASSWORD:
        ADMIN_PASSWORD = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
        USING_RANDOM = True
    else:
        ADMIN_PASSWORD = ENV_PASSWORD
        USING_RANDOM = False

    db = SessionLocal()
    try:
        admin = db.query(models.User).filter(models.User.username == "admin").first()
        
        if not admin:
            admin = models.User(
            username="admin",
            hashed_password=hash_password(ADMIN_PASSWORD),
            is_active=True
        )
            db.add(admin)
            db.commit()
            db.refresh(admin)
            print("NEW ADMIN CREATED")
            print(f"PASSWORD: {ADMIN_PASSWORD}")
        
        elif not USING_RANDOM:
            admin.hashed_password = hash_password(ADMIN_PASSWORD)
            db.commit()
            print("PASSWORD UPDATED FROM THE ENVIRONMENT")
            print(f"PASSWORD: {ADMIN_PASSWORD}")
        else:
            print("MAINTAINING EXISTING PASSWORD")
        
    finally:
        db.close()