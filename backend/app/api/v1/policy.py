from fastapi import APIRouter, Depends
from app.core.config import settings
from app.core.security import verify_token
from app.schemas import PolicyModel

router = APIRouter(prefix="/policy", tags=["Policy"])

active_policy = settings.DEFAULT_POLICY.copy()

@router.get("", response_model=PolicyModel)
def get_current_policy(token: str = Depends(verify_token)):
    return active_policy

@router.put("", response_model=PolicyModel)
def update_policy(new_policy: PolicyModel, token: str = Depends(verify_token)):
    global active_policy
    active_policy = new_policy.model_dump()
    return active_policy
