from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, BigInteger, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.core.database import Base

class Capture(Base):
    __tablename__ = "captures"

    capture_id = Column(String(64), primary_key=True, index=True)
    filename = Column(String(255), nullable=False)
    size_bytes = Column(BigInteger, default=0)
    status = Column(String(32), default="QUEUED", index=True)  # QUEUED, PROCESSING, COMPLETE, FAILED, PARTIAL
    completeness = Column(Float, default=1.0)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    processed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    error_stage = Column(String(64), nullable=True)
    processing_stage = Column(String(64), default="QUEUED")
    passive_visibility_rate = Column(Float, default=1.0)

    # Relationships
    hosts = relationship("Host", back_populates="capture", cascade="all, delete-orphan")
    sessions = relationship("Session", back_populates="capture", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="capture", cascade="all, delete-orphan")


class Host(Base):
    __tablename__ = "hosts"

    host_id = Column(String(64), primary_key=True, index=True)
    capture_id = Column(String(64), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    ip = Column(String(64), nullable=False, index=True)
    hostname = Column(String(255), nullable=True)

    capture = relationship("Capture", back_populates="hosts")
    sessions = relationship("Session", back_populates="host")


class Session(Base):
    __tablename__ = "sessions"

    session_id = Column(String(64), primary_key=True, index=True)
    capture_id = Column(String(64), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    host_id = Column(String(64), ForeignKey("hosts.host_id", ondelete="SET NULL"), nullable=True, index=True)
    protocol = Column(String(32), default="UNKNOWN", index=True)  # SMTP, IMAP, POP3, UNKNOWN
    protocol_confidence = Column(String(32), default="DIRECT")
    client_ip = Column(String(64), nullable=False)
    client_port = Column(Integer, nullable=False)
    server_ip = Column(String(64), nullable=False)
    server_port = Column(Integer, nullable=False)
    starttls_state = Column(String(64), default="NOT_OFFERED")
    capture_completeness = Column(Float, default=1.0)
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    packet_count = Column(Integer, default=0)
    byte_count = Column(BigInteger, default=0)
    auth_observed = Column(Boolean, default=False)
    auth_plaintext = Column(Boolean, default=False)  # Redacted credentials

    capture = relationship("Capture", back_populates="sessions")
    host = relationship("Host", back_populates="sessions")
    handshake = relationship("TLSHandshake", back_populates="session", uselist=False, cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="session", cascade="all, delete-orphan")


class TLSHandshake(Base):
    __tablename__ = "tls_handshakes"

    handshake_id = Column(String(64), primary_key=True, index=True)
    session_id = Column(String(64), ForeignKey("sessions.session_id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    version = Column(String(32), nullable=True)  # TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3
    cipher_suite = Column(String(128), nullable=True)
    key_exchange = Column(String(64), nullable=True)
    forward_secrecy = Column(Boolean, default=False)
    sni = Column(String(255), nullable=True)
    alpn = Column(String(64), nullable=True)
    supported_groups = Column(JSON, default=list)
    signature_algorithm = Column(String(64), nullable=True)
    session_resumption = Column(Boolean, default=False)
    handshake_sequence = Column(JSON, default=list)
    alerts = Column(JSON, default=list)
    ja3_fingerprint = Column(String(64), nullable=True)
    ja3s_fingerprint = Column(String(64), nullable=True)
    duration_ms = Column(Float, default=0.0)

    session = relationship("Session", back_populates="handshake")
    certificates = relationship("Certificate", back_populates="handshake", cascade="all, delete-orphan")


class Certificate(Base):
    __tablename__ = "certificates"

    cert_id = Column(String(64), primary_key=True, index=True)
    handshake_id = Column(String(64), ForeignKey("tls_handshakes.handshake_id", ondelete="CASCADE"), nullable=False, index=True)
    subject = Column(Text, nullable=True)
    issuer = Column(Text, nullable=True)
    san = Column(JSON, default=list)
    not_before = Column(DateTime, nullable=True)
    not_after = Column(DateTime, nullable=True)
    public_key_alg = Column(String(64), nullable=True)
    key_bits = Column(Integer, nullable=True)
    signature_alg = Column(String(64), nullable=True)
    basic_constraints = Column(Text, nullable=True)
    key_usage = Column(Text, nullable=True)
    extended_key_usage = Column(Text, nullable=True)
    chain_position = Column(Integer, default=0)
    is_self_signed = Column(Boolean, default=False)

    handshake = relationship("TLSHandshake", back_populates="certificates")


class Finding(Base):
    __tablename__ = "findings"

    finding_id = Column(String(64), primary_key=True, index=True)
    capture_id = Column(String(64), ForeignKey("captures.capture_id", ondelete="CASCADE"), nullable=False, index=True)
    session_id = Column(String(64), ForeignKey("sessions.session_id", ondelete="SET NULL"), nullable=True, index=True)
    rule_id = Column(String(32), nullable=False, index=True)
    ml_model_id = Column(String(64), nullable=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(32), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(String(32), nullable=False)  # DIRECT, HIGH CONFIDENCE, MEDIUM CONFIDENCE, EXTERNAL VALIDATION, UNKNOWN
    protocol = Column(String(32), nullable=True)
    evidence_json = Column(JSON, default=dict)
    impact = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    limitations_json = Column(JSON, default=dict)
    standards_ref = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False, index=True)
    analyst_feedback = Column(String(32), nullable=True)  # Useful, Not useful
    analyst_notes = Column(Text, nullable=True)

    capture = relationship("Capture", back_populates="findings")
    session = relationship("Session", back_populates="findings")


class Score(Base):
    __tablename__ = "scores"

    score_id = Column(String(64), primary_key=True, index=True)
    scope = Column(String(32), nullable=False, index=True)  # capture, host, session
    scope_id = Column(String(64), nullable=False, index=True)
    posture_score = Column(Integer, nullable=False)  # 0 to 100
    breakdown_json = Column(JSON, default=dict)
    disclaimer = Column(Text, nullable=False)
