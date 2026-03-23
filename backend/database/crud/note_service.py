"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException
import database.models as models
import schemas

def get_all_notes(db: Session):
    """
    Retrieve all notes from the database.
    """
    return db.query(models.Note).all()

def create_note(db: Session, note_data: schemas.NoteCreate):
    """
    Create a new note and save it to the database.
    """
    db_note = models.Note(
        title=note_data.title,
        content=note_data.content
    )
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    return db_note

def update_note(db: Session, db_note: models.Note, update_data: dict):
    """
    Apply updates to an existing note and commit the changes.
    """
    for key, value in update_data.items():
        setattr(db_note, key, value)
    
    db.commit()
    db.refresh(db_note)
    return db_note

def delete_note(db: Session, db_note: models.Note):
    """
    Delete a note from the database.
    """
    db.delete(db_note)
    db.commit()

def get_note_or_404(db: Session, note_id: int):
    """
    Fetch a note from the database or raise a 404 error if it doesn't exist.
    """
    # Perform the database query
    db_note = db.query(models.Note).filter(models.Note.id == note_id).first()
    if not db_note:
        # Stop execution and return the error to the client
        raise HTTPException(status_code=404, detail="Note not found")
    return db_note
