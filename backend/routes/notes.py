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
from dependencies.project import validate_project

router = APIRouter(
    prefix="/notes",
    tags=["Notes"],
    dependencies=[Depends(validate_project)]
)

@router.get("", response_model=schemas.NoteListRead)
def get_notes(project_id: SafeIntID, db: Session = Depends(get_db)):
    return {"notes": note_service.get_all_notes(db,project_id)}

@router.post("/create", response_model=schemas.NoteRead)
def create_note(project_id: SafeIntID, note: schemas.NoteCreate, db: Session = Depends(get_db)):
    return note_service.create_note(db,note,project_id)

@router.patch("/{id}", response_model=schemas.NoteRead)
def update_note(project_id: SafeIntID, id: SafeIntID, note_update: schemas.NoteUpdate, db: Session = Depends(get_db)):
    db_note = note_service.get_note_or_404(db,id,project_id)
    update_data = note_update.model_dump(exclude_unset=True)
    return note_service.update_note(db, db_note, update_data)

@router.delete("/{id}", status_code=204)
def delete_note(project_id: SafeIntID, id: SafeIntID, db: Session = Depends(get_db)):
    db_note = note_service.get_note_or_404(db,id, project_id)
    note_service.delete_note(db, db_note)
    return None