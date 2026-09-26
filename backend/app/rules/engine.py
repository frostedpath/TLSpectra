import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session as DBSession

from app.models import Session, TLSHandshake, Certificate, Finding
from app.rules.definitions import RULE_DEFINITIONS
from app.core.config import settings

def evaluate_rules(capture_id: str, db: DBSession, policy: Optional[Dict[str, Any]] = None):
    """
    Executes the 21 deterministic rules across all sessions in the capture.
    Creates Finding entities linked to sessions and evidence.
    """
    pol = policy or settings.DEFAULT_POLICY
    sessions = db.query(Session).filter(Session.capture_id == capture_id).all()

    for sess in sessions:
        hs = sess.handshake
        certs = hs.certificates if hs else []
        leaf_cert = certs[0] if certs else None

        # --- FLOW-001: Unexpected protocol on email port ---
        if sess.protocol == "UNKNOWN" and sess.server_port in {25, 465, 587, 110, 995, 143, 993}:
            _add_finding(db, capture_id, sess.session_id, "FLOW-001", {
                "server_port": sess.server_port,
                "protocol": sess.protocol,
                "packet_count": sess.packet_count
            })

        # --- ST-001: STARTTLS advertised but not used ---
        if sess.starttls_state == "CLEARTEXT_AFTER_OFFER":
            _add_finding(db, capture_id, sess.session_id, "ST-001", {
                "starttls_state": sess.starttls_state,
                "protocol": sess.protocol,
                "server_port": sess.server_port
            })

        # --- ST-002: STARTTLS attempt failed ---
        if sess.starttls_state in {"REJECTED", "FAILED"}:
            _add_finding(db, capture_id, sess.session_id, "ST-002", {
                "starttls_state": sess.starttls_state,
                "protocol": sess.protocol,
                "server_port": sess.server_port
            })

        # --- ST-003: Authentication before TLS ---
        if sess.auth_plaintext:
            _add_finding(db, capture_id, sess.session_id, "ST-003", {
                "auth_observed": True,
                "auth_plaintext": True,
                "credentials_redacted": True,
                "starttls_state": sess.starttls_state
            })

        # --- TLS Rules (evaluated if handshake present) ---
        if hs:
            # TLS-001: Deprecated TLS version
            if hs.version in {"SSL 3.0", "TLS 1.0", "TLS 1.1"}:
                _add_finding(db, capture_id, sess.session_id, "TLS-001", {
                    "negotiated_version": hs.version,
                    "policy_minimum": pol.get("tls_min_version", "TLS 1.2")
                })

            # TLS-002: Weak / deprecated cipher
            if hs.cipher_suite and any(w in hs.cipher_suite for w in ["3DES", "RC4", "DES", "NULL", "EXPORT"]):
                _add_finding(db, capture_id, sess.session_id, "TLS-002", {
                    "cipher_suite": hs.cipher_suite
                })

            # TLS-003: No forward secrecy
            if not hs.forward_secrecy and hs.version != "TLS 1.3":
                _add_finding(db, capture_id, sess.session_id, "TLS-003", {
                    "key_exchange": hs.key_exchange,
                    "cipher_suite": hs.cipher_suite
                })

            # TLS-004: Static RSA key exchange
            if hs.key_exchange == "RSA":
                _add_finding(db, capture_id, sess.session_id, "TLS-004", {
                    "key_exchange": "RSA",
                    "cipher_suite": hs.cipher_suite
                })

            # TLS-005: Weak cryptographic algorithm
            if hs.cipher_suite and ("3DES" in hs.cipher_suite or "DES" in hs.cipher_suite or "MD5" in hs.cipher_suite):
                _add_finding(db, capture_id, sess.session_id, "TLS-005", {
                    "cipher_suite": hs.cipher_suite
                })

            # TLS-006: Possible downgrade / fallback indicator
            # Inferred if Client supports modern TLS but Server negotiates TLS 1.0/1.1
            if hs.version in {"TLS 1.0", "TLS 1.1"} and ("ClientHello" in hs.handshake_sequence):
                _add_finding(db, capture_id, sess.session_id, "TLS-006", {
                    "negotiated_version": hs.version,
                    "indicator": "Version negotiation fallback"
                })

            # TLS-007: Repeated handshake failures
            failure_threshold = pol.get("repeated_failures_threshold", 3)
            if len(hs.alerts) >= failure_threshold:
                _add_finding(db, capture_id, sess.session_id, "TLS-007", {
                    "alert_count": len(hs.alerts),
                    "alerts": hs.alerts,
                    "threshold": failure_threshold
                })

        # --- Certificate Rules (evaluated if leaf cert observed) ---
        if leaf_cert:
            session_ref_time = sess.start_time or datetime.now(timezone.utc)

            # CERT-001: Certificate expired
            if leaf_cert.not_after and leaf_cert.not_after < session_ref_time:
                _add_finding(db, capture_id, sess.session_id, "CERT-001", {
                    "not_after": leaf_cert.not_after.isoformat(),
                    "session_time": session_ref_time.isoformat(),
                    "subject": leaf_cert.subject
                })

            # CERT-002: Certificate not yet valid
            if leaf_cert.not_before and leaf_cert.not_before > session_ref_time:
                _add_finding(db, capture_id, sess.session_id, "CERT-002", {
                    "not_before": leaf_cert.not_before.isoformat(),
                    "session_time": session_ref_time.isoformat(),
                    "subject": leaf_cert.subject
                })

            # CERT-003: Self-signed certificate
            if leaf_cert.is_self_signed:
                _add_finding(db, capture_id, sess.session_id, "CERT-003", {
                    "subject": leaf_cert.subject,
                    "issuer": leaf_cert.issuer
                })

            # CERT-004: Hostname mismatch
            if hs and hs.sni:
                san_names = leaf_cert.san or []
                sni_match = False
                for san_entry in san_names:
                    if san_entry.lower() == hs.sni.lower():
                        sni_match = True
                        break
                    # Wildcard check (e.g. *.domain.com)
                    if san_entry.startswith("*.") and hs.sni.lower().endswith(san_entry[1:].lower()):
                        sni_match = True
                        break
                if not sni_match and hs.sni:
                    _add_finding(db, capture_id, sess.session_id, "CERT-004", {
                        "sni": hs.sni,
                        "san": san_names,
                        "subject": leaf_cert.subject
                    })

            # CERT-005: Weak public key
            min_rsa = pol.get("rsa_min_key_bits", 2048)
            min_ec = pol.get("ec_min_key_bits", 224)
            if leaf_cert.key_bits:
                if "RSA" in (leaf_cert.public_key_alg or "") and leaf_cert.key_bits < min_rsa:
                    _add_finding(db, capture_id, sess.session_id, "CERT-005", {
                        "public_key_alg": leaf_cert.public_key_alg,
                        "key_bits": leaf_cert.key_bits,
                        "minimum_required": min_rsa
                    })
                elif "EC" in (leaf_cert.public_key_alg or "") and leaf_cert.key_bits < min_ec:
                    _add_finding(db, capture_id, sess.session_id, "CERT-005", {
                        "public_key_alg": leaf_cert.public_key_alg,
                        "key_bits": leaf_cert.key_bits,
                        "minimum_required": min_ec
                    })

            # CERT-006: Weak signature algorithm
            if leaf_cert.signature_alg and any(bad in leaf_cert.signature_alg.lower() for bad in ["md5", "sha1", "sha-1"]):
                _add_finding(db, capture_id, sess.session_id, "CERT-006", {
                    "signature_algorithm": leaf_cert.signature_alg
                })

            # CERT-007: Observed certificate chain incomplete
            # Note: Never auto-escalated to server chain broken (passive visibility applies)
            if len(certs) == 1 and not leaf_cert.is_self_signed:
                _add_finding(db, capture_id, sess.session_id, "CERT-007", {
                    "observed_certificates_count": len(certs),
                    "note": "Only leaf certificate observed. Client caching or passive visibility may apply."
                })

            # CERT-008: Untrusted issuer (external validation only)
            # Flagged with EXTERNAL VALIDATION confidence
            if not leaf_cert.is_self_signed and "Let's Encrypt" not in (leaf_cert.issuer or "") and "DigiCert" not in (leaf_cert.issuer or ""):
                _add_finding(db, capture_id, sess.session_id, "CERT-008", {
                    "issuer": leaf_cert.issuer,
                    "confidence": "EXTERNAL VALIDATION"
                })

            # CERT-009: Excessive validity period (policy-dependent)
            max_days = pol.get("cert_max_validity_days", 398)
            if leaf_cert.not_before and leaf_cert.not_after:
                validity_days = (leaf_cert.not_after - leaf_cert.not_before).days
                if validity_days > max_days:
                    _add_finding(db, capture_id, sess.session_id, "CERT-009", {
                        "validity_days": validity_days,
                        "policy_maximum_days": max_days
                    })

    db.commit()

def _add_finding(db: DBSession, capture_id: str, session_id: Optional[str], rule_id: str, evidence_data: Dict[str, Any]):
    rule_meta = RULE_DEFINITIONS.get(rule_id, {
        "title": f"Rule {rule_id}",
        "severity": "MEDIUM",
        "confidence": "DIRECT",
        "category": "General Security",
        "standards_ref": "RFC",
        "impact": "Security weakness detected.",
        "recommendation": "Remediate according to security best practices.",
        "limitations": {}
    })

    finding_id = f"find-{uuid.uuid4().hex}"
    confidence = evidence_data.get("confidence", rule_meta["confidence"])

    finding = Finding(
        finding_id=finding_id,
        capture_id=capture_id,
        session_id=session_id,
        rule_id=rule_id,
        ml_model_id=None,
        title=rule_meta["title"],
        severity=rule_meta["severity"],
        confidence=confidence,
        protocol="SMTP",
        evidence_json=evidence_data,
        impact=rule_meta["impact"],
        recommendation=rule_meta["recommendation"],
        limitations_json=rule_meta["limitations"],
        standards_ref=rule_meta["standards_ref"],
        category=rule_meta["category"]
    )
    db.add(finding)
