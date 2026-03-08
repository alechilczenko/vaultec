from sqlalchemy.orm import Session
from fastapi import HTTPException
import models

def get_or_create_definition(db: Session, title: str, severity: str, description: str, recommendation: str):
    # Search if exists
    defn = db.query(models.VulnerabilityDefinition).filter(
        models.VulnerabilityDefinition.title == title
    ).first()
    
    if not defn:
        defn = models.VulnerabilityDefinition(
            title=title,
            severity=severity,
            description=description,
            recommendation=recommendation
        )
        db.add(defn)
        db.commit()
        db.refresh(defn)
    return defn

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