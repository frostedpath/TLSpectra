from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DBSession

from app.core.database import get_db
from app.core.errors import SMSException
from app.core.security import verify_token
from app.models import Host, Score
from app.schemas import ScoreResponse

router = APIRouter(prefix="/hosts", tags=["Hosts"])

@router.get("/{host_id}/score", response_model=ScoreResponse)
def get_host_score(
    host_id: str,
    db: DBSession = Depends(get_db),
    token: str = Depends(verify_token)
):
    score = db.query(Score).filter(Score.scope == "host", Score.scope_id == host_id).first()
    if not score:
        raise SMSException(404, "SCORE_NOT_FOUND", f"Score not found for host {host_id}")
    
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
