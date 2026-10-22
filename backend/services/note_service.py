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

def get_all_notes(db: Session):
    return db.query(models.Note).all()

def create_note(db: Session, note_data: schemas.NoteCreate):
    note_title = note_data.title
    db_note = models.Note(
        title=note_data.title,
        content=note_data.content
    )
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    logger.info(f"Note created successfully: '{note_title}' (ID: {db_note.id})")
    return db_note

def update_note(db: Session, db_note: models.Note, update_data: dict):
    original_title = db_note.title

    for key, value in update_data.items():
        setattr(db_note, key, value)
    
    db.commit()
    db.refresh(db_note)
    logger.info(f"Note '{original_title}' updated successfully")
    return db_note

def delete_note(db: Session, db_note: models.Note):
    note_id = db_note.id
    note_title = db_note.title

    try:
        db.delete(db_note)
        db.commit()
        logger.info(f"Note '{note_title}' deleted successfully")
        return True
    except Exception as e:
        db.rollback()
        logger.error(f"Unexpected error deleting note '{note_title}': {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Delete Error: Could not delete note ID {note_id}. Transaction rolled back."
        )

def get_note_or_404(db: Session, note_id: int):
    db_note = db.query(models.Note).filter(models.Note.id == note_id).first()
    if not db_note:
        raise HTTPException(
            status_code=404, 
            detail=f"Note Error: Note with ID {note_id} was not found in active workspace."
        )
    return db_note