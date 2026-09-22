"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException, status
import database.models as models
import schemas

def create_project(db: Session, project: schemas.ProjectCreate):
    """
    Creates a new project.
    Raises an exception if the internal name (slug) already exists.
    """
    db_project = models.Project(
        name=project.name,
        client_name=project.client_name)
    try:
        db.add(db_project)
        db.commit()
        db.refresh(db_project)
        return db_project
    except IntegrityError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Project with name '{project.name}' already exists."
        )

def update_project(db: Session, project_id: int, project_update: schemas.ProjectCreate):
    """
    Updates an existing project's information.
    Checks if the new project name already exists to avoid collisions.
    """
    db_project = get_project_by_id(db, project_id)
    
    # Check if the name is being changed and if the new name is already taken
    if db_project.name != project_update.name:
        existing_name = db.query(models.Project).filter(models.Project.name == project_update.name).first()
        if existing_name:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Project with name '{project_update.name}' already exists."
            )
    # Update fields
    db_project.name = project_update.name
    db_project.client_name = project_update.client_name

    try:
        db.commit()
        db.refresh(db_project)
        return db_project
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while updating the project."
        )
    
def get_projects(db: Session, skip: int = 0, limit: int = 100):
    """
    Lists all projects for the pre-selection screen.
    """
    return db.query(models.Project).offset(skip).limit(limit).all()

def get_project_by_id(db: Session, project_id: int):
    """
    Retrieves a project by its ID. Useful for endpoint validations.
    """
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found."
        )
    return project

def delete_project(db: Session, project_id: int):
    """
    Deletes a project and, thanks to 'cascade="all, delete-orphan"',
    automatically removes all associated assets, findings, and notes.
    """
    db_project = get_project_by_id(db, project_id)
    db.delete(db_project)
    db.commit()
    return {"message": f"Project '{db_project.name}' and all associated data have been deleted."}