"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List
from database.db import get_db
from database.crud import note_service
import schemas
from schemas.common import SafeIntID

router = APIRouter(
    prefix="/notes",
    tags=["Notes"]
)

@router.get("", response_model=List[schemas.NoteRead])
def get_notes(db: Session = Depends(get_db)):
    return note_service.get_all_notes(db)

@router.post("", response_model=schemas.NoteRead)
def create_note(note: schemas.NoteCreate, db: Session = Depends(get_db)):
    return note_service.create_note(db,note)

@router.patch("/{id}", response_model=schemas.NoteRead)
def update_note(id: SafeIntID, note_update: schemas.NoteUpdate, db: Session = Depends(get_db)):
    db_note = note_service.get_note_or_404(db,id)
    update_data = note_update.model_dump(exclude_unset=True)
    return note_service.update_note(db, db_note, update_data)

@router.delete("/{id}", status_code=204)
def delete_note(id: SafeIntID, db: Session = Depends(get_db)):
    db_note = note_service.get_note_or_404(db,id)
    note_service.delete_note(db, db_note)
    return None