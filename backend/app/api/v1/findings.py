from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DBSession

from app.core.database import get_db
from app.core.errors import SMSException
from app.core.security import verify_token
from app.models import Finding
from app.schemas import FindingResponse, AnalystFeedbackRequest

router = APIRouter(prefix="/findings", tags=["Findings"])

@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding_detail(
    finding_id: str,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    finding = db.query(Finding).filter(Finding.finding_id == finding_id).first()
    if not finding:
        raise SMSException(404, "FINDING_NOT_FOUND", f"Finding {finding_id} not found")
    return finding

@router.patch("/{finding_id}/feedback")
def update_analyst_feedback(
    finding_id: str,
    req: AnalystFeedbackRequest,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    finding = db.query(Finding).filter(Finding.finding_id == finding_id).first()
    if not finding:
        raise SMSException(404, "FINDING_NOT_FOUND", f"Finding {finding_id} not found")
    
    finding.analyst_feedback = req.feedback
    finding.analyst_notes = req.notes
    db.commit()
    return {"status": "success", "finding_id": finding_id, "feedback": req.feedback}
