import os
from pathlib import Path
from typing import Dict, Any
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "TLSpectra"
    TAGLINE: str = "Evidence-Driven Cryptographic Network Forensics"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    
    # Security: Static Bearer Token
    STATIC_BEARER_TOKEN: str = os.getenv("SECUREMAILSCOPE_TOKEN", "sms_sec_token_v1")
    
    # Storage paths
    BASE_DIR: Path = Path(__file__).resolve().parent.parent.parent
    STORAGE_DIR: Path = BASE_DIR / "storage"
    UPLOAD_DIR: Path = STORAGE_DIR / "uploads"
    REPORTS_DIR: Path = STORAGE_DIR / "reports"
    CORPUS_DIR: Path = BASE_DIR.parent / "corpus"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR}/securemailscope.db")
    
    # Stress and Upload Limits
    MAX_UPLOAD_SIZE_BYTES: int = 2 * 1024 * 1024 * 1024  # 2 GB per benchmark
    
    # Machine Learning Engine Configuration
    # Options: "isolation_forest" (default production), "autoencoder" (optional/experimental PyTorch GPU/CPU)
    ML_ANOMALY_ENGINE: str = os.getenv("SMS_ML_ENGINE", "isolation_forest")
    
    # Default Policy Thresholds
    DEFAULT_POLICY: Dict[str, Any] = {
        "tls_min_version": "TLS 1.2",
        "cert_max_validity_days": 398,
        "rsa_min_key_bits": 2048,
        "ec_min_key_bits": 224,
        "allow_self_signed": False,
        "require_forward_secrecy": True,
        "require_starttls": True,
        "repeated_failures_threshold": 3,
        "scoring_weights": {
            "protocol_security": 25,
            "cryptographic_security": 30,
            "certificate_security": 25,
            "starttls_security": 15,
            "behavioural_anomaly": 5
        }
    }

    model_config = SettingsConfigDict(case_sensitive=True)

settings = Settings()

# Ensure directories exist
settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
