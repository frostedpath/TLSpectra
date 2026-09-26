from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict

# --- Capture Schemas ---
class CaptureBase(BaseModel):
    filename: str
    size_bytes: int = 0
    status: str = "QUEUED"
    completeness: float = 1.0
    error_message: Optional[str] = None
    error_stage: Optional[str] = None
    processing_stage: str = "QUEUED"
    passive_visibility_rate: float = 1.0

class CaptureResponse(CaptureBase):
    capture_id: str
    uploaded_at: datetime
    processed_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class CaptureListResponse(BaseModel):
    items: List[CaptureResponse]
    total: int
    limit: int
    cursor: Optional[str] = None


# --- Certificate Schemas ---
class CertificateResponse(BaseModel):
    cert_id: str
    handshake_id: str
    subject: Optional[str] = None
    issuer: Optional[str] = None
    san: List[str] = Field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    public_key_alg: Optional[str] = None
    key_bits: Optional[int] = None
    signature_alg: Optional[str] = None
    basic_constraints: Optional[str] = None
    key_usage: Optional[str] = None
    extended_key_usage: Optional[str] = None
    chain_position: int = 0
    is_self_signed: bool = False

    model_config = ConfigDict(from_attributes=True)


# --- TLS Handshake Schemas ---
class TLSHandshakeResponse(BaseModel):
    handshake_id: str
    session_id: str
    version: Optional[str] = None
    cipher_suite: Optional[str] = None
    key_exchange: Optional[str] = None
    forward_secrecy: bool = False
    sni: Optional[str] = None
    alpn: Optional[str] = None
    supported_groups: List[Any] = Field(default_factory=list)
    signature_algorithm: Optional[str] = None
    session_resumption: bool = False
    handshake_sequence: List[Any] = Field(default_factory=list)
    alerts: List[Dict[str, Any]] = Field(default_factory=list)
    ja3_fingerprint: Optional[str] = None
    ja3s_fingerprint: Optional[str] = None
    duration_ms: float = 0.0
    certificates: List[CertificateResponse] = Field(default_factory=list)

    model_config = ConfigDict(from_attributes=True)


# --- Session Schemas ---
class SessionBase(BaseModel):
    protocol: str = "UNKNOWN"
    protocol_confidence: str = "DIRECT"
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    starttls_state: str = "NOT_OFFERED"
    capture_completeness: float = 1.0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    packet_count: int = 0
    byte_count: int = 0
    auth_observed: bool = False
    auth_plaintext: bool = False

class SessionResponse(SessionBase):
    session_id: str
    capture_id: str
    host_id: Optional[str] = None
    handshake: Optional[TLSHandshakeResponse] = None

    model_config = ConfigDict(from_attributes=True)

class SessionListResponse(BaseModel):
    items: List[SessionResponse]
    total: int
    limit: int
    cursor: Optional[str] = None
    starttls_counts: Optional[Dict[str, int]] = None


# --- Finding Schemas ---
class FindingResponse(BaseModel):
    finding_id: str
    capture_id: str
    session_id: Optional[str] = None
    rule_id: str
    ml_model_id: Optional[str] = None
    title: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: str  # DIRECT, HIGH CONFIDENCE, MEDIUM CONFIDENCE, EXTERNAL VALIDATION, UNKNOWN
    protocol: Optional[str] = None
    evidence_json: Dict[str, Any] = Field(default_factory=dict)
    impact: str
    recommendation: str
    limitations_json: Dict[str, Any] = Field(default_factory=dict)
    standards_ref: str
    category: str
    analyst_feedback: Optional[str] = None
    analyst_notes: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int
    limit: int
    cursor: Optional[str] = None
    severity_counts: Optional[Dict[str, int]] = None

class AnalystFeedbackRequest(BaseModel):
    feedback: str  # Useful, Not useful
    notes: Optional[str] = None


# --- Host Schemas ---
class HostResponse(BaseModel):
    host_id: str
    capture_id: str
    ip: str
    hostname: Optional[str] = None
    session_count: int = 0
    posture_score: Optional[int] = None

    model_config = ConfigDict(from_attributes=True)

class HostListResponse(BaseModel):
    items: List[HostResponse]
    total: int
    limit: int
    cursor: Optional[str] = None


# --- Score Schemas ---
class ScoreBreakdownItem(BaseModel):
    category: str
    deduction: int
    findings_count: int
    grouped_rules: List[str]

class ScoreResponse(BaseModel):
    score_id: str
    scope: str
    scope_id: str
    posture_score: int
    breakdown: List[ScoreBreakdownItem] = Field(default_factory=list)
    audit_trail: List[Dict[str, Any]] = Field(default_factory=list)
    disclaimer: str

    model_config = ConfigDict(from_attributes=True)


# --- Policy Schemas ---
class PolicyModel(BaseModel):
    tls_min_version: str = "TLS 1.2"
    cert_max_validity_days: int = 398
    rsa_min_key_bits: int = 2048
    ec_min_key_bits: int = 224
    allow_self_signed: bool = False
    require_forward_secrecy: bool = True
    require_starttls: bool = True
    repeated_failures_threshold: int = 3
    scoring_weights: Dict[str, int] = Field(
        default_factory=lambda: {
            "protocol_security": 25,
            "cryptographic_security": 30,
            "certificate_security": 25,
            "starttls_security": 15,
            "behavioural_anomaly": 5
        }
    )


# --- System Health Schema ---
class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "1.0.0"
    database: str = "connected"
    storage: str = "writable"
    parsers_ready: bool = True
    ml_telemetry: Optional[Dict[str, Any]] = None
