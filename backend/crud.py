from sqlalchemy.orm import Session
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
