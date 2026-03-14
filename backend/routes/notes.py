"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
import models, schemas
from db import get_db
from crud import get_note_or_404

router = APIRouter(
    prefix="/notes",
    tags=["Notes"]
)

@router.get("", response_model=List[schemas.NoteRead])
def get_notes(db: Session = Depends(get_db)):

    return db.query(models.Note).all()

@router.post("", response_model=schemas.NoteRead)
def create_note(note: schemas.NoteCreate, db: Session = Depends(get_db)):
    # Initialize the new note object from the schema
    db_note = models.Note(
        title=note.title,
        content=note.content
    )
    db.add(db_note)
    db.commit()
    db.refresh(db_note)
    
    return db_note

@router.patch("/{note_id}", response_model=schemas.NoteRead)
def update_note(note_id: int, note_update: schemas.NoteUpdate, db: Session = Depends(get_db)):

    db_note = get_note_or_404(db, note_id)

    update_data = note_update.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_note, key, value)

    db.commit()
    db.refresh(db_note)

    return db_note

@router.delete("/{note_id}", status_code=204)
def delete_note(note_id: int, db: Session = Depends(get_db)):
   
    db_note = get_note_or_404(db, note_id)
    # Delete and commit the transaction
    db.delete(db_note)
    db.commit()
    
    # 204 No Content is the standard response for successful deletion
    return None