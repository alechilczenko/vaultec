"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from database.db import get_db
from database.crud import project_service
import schemas
from schemas.common import SafeIntID

router = APIRouter(
    prefix="/projects",
    tags=["Projects"]
)

@router.get("/", response_model=schemas.ProjectList)
def list_projects(
    db: Session = Depends(get_db), 
    skip: int = Query(0, ge=0), 
    limit: int = Query(100, ge=1, le=500)
):
    projects_data = project_service.get_projects(db, skip=skip, limit=limit)
    return {"projects": projects_data}

@router.post("/create", response_model=schemas.ProjectRead, status_code=status.HTTP_201_CREATED)
def create_project(data: schemas.ProjectCreate, db: Session = Depends(get_db)):
    return project_service.create_project(db, data)

@router.get("/{id}", response_model=schemas.ProjectRead)
def get_project(id: SafeIntID, db: Session = Depends(get_db)):
    return project_service.get_project_by_id(db, id)

@router.patch("/{id}", response_model=schemas.ProjectRead)
def update_project(
    id: SafeIntID, 
    data: schemas.ProjectCreate, 
    db: Session = Depends(get_db)
):
    return project_service.update_project(db, id, data)

@router.delete("/{id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_project(id: SafeIntID, db: Session = Depends(get_db)):
    project_service.delete_project(db, id)
    return None