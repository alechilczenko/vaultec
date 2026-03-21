from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database.db import get_db
import database.models as models

router = APIRouter(prefix="/admin/clear", tags=["Maintenance"])

@router.delete("/findings", status_code=status.HTTP_204_NO_CONTENT)
def clear_findings(db: Session = Depends(get_db)):
    try:
        db.query(models.Vulnerability).delete()
        db.commit()
        print("DEBUG: All findings have been cleared from the database.")
    except Exception as e:
        db.rollback()
        print(f"ERROR: Could not clear findings. {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear findings. Please check server logs."
        )
    return None

@router.delete("/assets", status_code=status.HTTP_204_NO_CONTENT)
def clear_assets(db: Session = Depends(get_db)):
    """
    Deletes all assets. Requires no existing findings.
    """
    try:
        # Check for dependent findings
        if db.query(models.Vulnerability).count() > 0:
            print("WARNING: Integrity check failed for asset deletion.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot delete assets. There are findings still linked to them."
            )
        
        db.query(models.Asset).delete()
        db.commit()
        print("DEBUG: All assets have been cleared.")
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"ERROR: Could not clear assets. {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear assets due to an internal error."
        )
    return None

@router.delete("/catalog", status_code=status.HTTP_204_NO_CONTENT)
def clear_catalog(db: Session = Depends(get_db)):
    """
    Deletes the entire vulnerability catalog. Requires no active findings.
    """
    try:
        # Check if catalog is being used
        if db.query(models.Vulnerability).count() > 0:
            print("WARNING: Integrity check failed for catalog deletion.")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot clear catalog. Definitions are referenced by existing findings."
            )

        db.query(models.VulnerabilityDefinition).delete()
        db.commit()
        print("DEBUG: Catalog has been cleared.")
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"ERROR: Could not clear catalog. {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to clear catalog. Integrity constraints might be active."
        )
    return None