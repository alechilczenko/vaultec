"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException
from loguru import logger
import database.models as models
import schemas

def get_all_notes(db: Session, project_id:int):
    """
    Retrieve all notes from the database.
    """
    return db.query(models.Note).filter(models.Note.project_id == project_id).all()

def create_note(db: Session, note_data: schemas.NoteCreate, project_id:int):
    """
    Create a new note and save it to the database.
    """
    note_title = note_data.title
    db_note = models.Note(
        title=note_data.title,
        content=note_data.content,
        project_id=project_id
    )
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    logger.info(f"Note created successfully: '{note_title}' (ID: {db_note.id}) in Project {project_id}")
    return db_note

def update_note(db: Session, db_note: models.Note, update_data: dict):
    """
    Apply updates to an existing note and commit the changes.
    """
    original_title = db_note.title
    project_id = db_note.project_id

    for key, value in update_data.items():
        setattr(db_note, key, value)
    
    db.commit()
    db.refresh(db_note)
    logger.info(f"Note '{original_title}' updated successfully in Project {project_id}")
    return db_note

def delete_note(db: Session, db_note: models.Note):
    """
    Delete a note from the database with error handling and rollback.
    """
    note_id = db_note.id
    note_title = db_note.title
    project_id = db_note.project_id

    try:
        db.delete(db_note)
        db.commit()
        logger.info(f"Note '{note_title}' deleted successfully from Project {project_id}")
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error deleting note '{note_title}': {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Delete Error: Could not delete note ID {note_id}. Transaction rolled back."
        )

def get_note_or_404(db: Session, note_id: int, project_id:int):
    """
    Fetch a note from the database or raise a 404 error if it doesn't exist.
    """
    # Perform the database query
    db_note = db.query(models.Note).filter(
        models.Note.id == note_id,
        models.Note.project_id == project_id
    ).first()
    if not db_note:
        # Stop execution and return the error to the client
        raise HTTPException(status_code=404, detail=f"Note Error: Note with ID {note_id} was not found in this project.")
    return db_note
