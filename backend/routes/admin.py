from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import admin_service

router = APIRouter(prefix="/admin/clear", tags=["Maintenance"])

@router.delete("/findings", status_code=status.HTTP_204_NO_CONTENT)
def clear_findings(db: Session = Depends(get_db)):
    admin_service.clear_all_findings(db)
    return None

@router.delete("/assets", status_code=status.HTTP_204_NO_CONTENT)
def clear_assets(db: Session = Depends(get_db)):
    admin_service.clear_all_assets(db)
    return None

@router.delete("/catalog", status_code=status.HTTP_204_NO_CONTENT)
def clear_catalog(db: Session = Depends(get_db)):
    admin_service.clear_all_catalog(db)
    return None