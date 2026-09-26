from fastapi import APIRouter
from app.schemas import HealthResponse
from app.ml.anomaly_detector import get_ml_telemetry

router = APIRouter(tags=["Health"])

@router.get("/health", response_model=HealthResponse)
def health_check():
    return {
        "status": "ok",
        "version": "1.0.0",
        "database": "connected",
        "storage": "writable",
        "parsers_ready": True,
        "ml_telemetry": get_ml_telemetry()
    }
