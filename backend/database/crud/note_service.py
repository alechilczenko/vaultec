"""
Vulnerability Management Platform
Copyright (C) 2026 Alejandro Chilczenko
Licensed under GNU GPLv3 - See the LICENSE file for details
"""

from sqlalchemy.orm import Session
from fastapi import HTTPException
import database.models as models

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
