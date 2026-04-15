from fastapi import Depends
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import project_service
from schemas.common import SafeIntID

def validate_project(project_id: SafeIntID, db: Session = Depends(get_db)):
    """
    Dependency to validate project existence.
    If it doesn't exist, it raises the 404 automatically.
    """
    return project_service.get_project_by_id(db, project_id)
