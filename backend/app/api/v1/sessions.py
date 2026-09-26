from typing import Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DBSession

from app.core.database import get_db
from app.core.errors import SMSException
from app.core.security import verify_token
from app.models import Session, Score, Finding
from app.schemas import SessionResponse, ScoreResponse, FindingListResponse

router = APIRouter(prefix="/sessions", tags=["Sessions"])

@router.get("/{session_id}", response_model=SessionResponse)
def get_session_detail(
    session_id: str,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    session = db.query(Session).filter(Session.session_id == session_id).first()
    if not session:
        raise SMSException(404, "SESSION_NOT_FOUND", f"Session {session_id} not found")
    return session

@router.get("/{session_id}/score", response_model=ScoreResponse)
def get_session_score(
    session_id: str,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    score = db.query(Score).filter(Score.scope == "session", Score.scope_id == session_id).first()
    if not score:
        raise SMSException(404, "SCORE_NOT_FOUND", f"Score not found for session {session_id}")
    breakdown_data = score.breakdown_json or {}
    return {
        "score_id": score.score_id,
        "scope": score.scope,
        "scope_id": score.scope_id,
        "posture_score": score.posture_score,
        "breakdown": breakdown_data.get("breakdown", []),
        "audit_trail": breakdown_data.get("audit_trail", []),
        "disclaimer": score.disclaimer
    }

@router.get("/{session_id}/findings", response_model=FindingListResponse)
def get_session_findings(
    session_id: str,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    findings = db.query(Finding).filter(Finding.session_id == session_id).all()
    return {"items": findings, "total": len(findings), "limit": len(findings), "cursor": None}
