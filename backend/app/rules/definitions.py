from typing import Dict, Any, List, Optional
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session as DBSession
from app.models import Finding, Session, TLSHandshake, Certificate, Capture
from app.core.config import settings

# 21 Deterministic Rules metadata based on RFCs and NIST guidelines
RULE_DEFINITIONS: Dict[str, Dict[str, Any]] = {
    "TLS-001": {
        "title": "Deprecated TLS version observed",
        "severity": "CRITICAL",
        "confidence": "DIRECT",
        "category": "Cryptographic Security",
        "standards_ref": "RFC 8996",
        "impact": "Session negotiated a deprecated TLS version (TLS 1.0, TLS 1.1, or SSL 3.0) vulnerable to known protocol attacks.",
        "recommendation": "Configure email server to disable TLS 1.0 and TLS 1.1, enforcing TLS 1.2 or TLS 1.3.",
        "limitations": {"passive_accuracy": "DIRECT packet observation of ServerHello version field."}
    },
    "TLS-002": {
        "title": "Weak / deprecated cipher observed",
        "severity": "HIGH",
        "confidence": "DIRECT",
        "category": "Cryptographic Security",
        "standards_ref": "RFC 7465, NIST SP 800-52 Rev. 2",
        "impact": "Observed cipher suite utilizes deprecated algorithms (e.g. RC4, 3DES, or NULL ciphers) susceptible to cryptanalysis.",
        "recommendation": "Disable legacy ciphers and require modern authenticated encryption suites (AES-GCM, CHACHA20-POLY1305).",
        "limitations": {"passive_accuracy": "Direct inspection of negotiated cipher suite ID."}
    },
    "TLS-003": {
        "title": "No forward secrecy indicated",
        "severity": "MEDIUM",
        "confidence": "DIRECT",
        "category": "Cryptographic Security",
        "standards_ref": "NIST SP 800-52 Rev. 2",
        "impact": "Key exchange does not support forward secrecy. Past recorded sessions could be decrypted if the private key is compromised.",
        "recommendation": "Enforce ephemeral Diffie-Hellman (ECDHE or DHE) key exchange modes.",
        "limitations": {"passive_accuracy": "Evaluated from key exchange mechanism in cipher suite."}
    },
    "TLS-004": {
        "title": "Static RSA / key-exchange weakness",
        "severity": "HIGH",
        "confidence": "DIRECT",
        "category": "Cryptographic Security",
        "standards_ref": "NIST SP 800-131A Rev. 2",
        "impact": "Static RSA key exchange observed. RSA encryption of pre-master secret lacks forward secrecy and is vulnerable to Bleichenbacher-style attacks.",
        "recommendation": "Deprecate TLS_RSA suites and transition to ECDHE key exchange.",
        "limitations": {"passive_accuracy": "Direct inspection of ServerHello cipher suite."}
    },
    "TLS-005": {
        "title": "Weak cryptographic algorithm",
        "severity": "HIGH",
        "confidence": "DIRECT",
        "category": "Cryptographic Security",
        "standards_ref": "NIST SP 800-131A Rev. 2",
        "impact": "Cryptographic suite relies on algorithms known to have effective security margins below 112 bits (DES, 3DES, MD5).",
        "recommendation": "Update TLS configuration to require minimum 128-bit security margin algorithms.",
        "limitations": {"passive_accuracy": "Direct observation."}
    },
    "TLS-006": {
        "title": "Possible downgrade/fallback indicator",
        "severity": "HIGH",
        "confidence": "HIGH CONFIDENCE",
        "category": "Cryptographic Security",
        "standards_ref": "RFC 7507, RFC 8446",
        "impact": "Client demonstrated capability for modern TLS versions but negotiated a legacy version, or TLS_FALLBACK_SCSV was triggered.",
        "recommendation": "Inspect intermediate proxies and mail transfer agents for forced SSL/TLS stripping or downgrade attacks.",
        "limitations": {"passive_accuracy": "Inferred from ClientHello supported versions vs ServerHello selection."}
    },
    "TLS-007": {
        "title": "Repeated handshake failures",
        "severity": "MEDIUM",
        "confidence": "HIGH CONFIDENCE",
        "category": "Cryptographic Security",
        "standards_ref": "RFC 8446",
        "impact": "Burst of TLS handshake alert failures observed, indicating cipher mismatch, untrusted certs, or handshake tampering.",
        "recommendation": "Verify client-server cipher compatibility and certificate trust chains.",
        "limitations": {"passive_accuracy": "Alert count evaluated against session event timeline."}
    },
    "ST-001": {
        "title": "STARTTLS advertised but not used",
        "severity": "HIGH",
        "confidence": "DIRECT",
        "category": "STARTTLS Security",
        "standards_ref": "RFC 8314 §3, RFC 3207",
        "impact": "Mail server advertised STARTTLS in response to EHLO, but client continued session in plaintext without issuing STARTTLS.",
        "recommendation": "Configure client to require STARTTLS or enforce mandatory TLS policy on mail routing.",
        "limitations": {"passive_accuracy": "Directly observable in SMTP command sequence."}
    },
    "ST-002": {
        "title": "STARTTLS attempt failed",
        "severity": "HIGH",
        "confidence": "DIRECT",
        "category": "STARTTLS Security",
        "standards_ref": "RFC 3207",
        "impact": "Client requested STARTTLS, but server returned an error response or TLS handshake failed immediately following STARTTLS.",
        "recommendation": "Check server STARTTLS service health, certificate bindings, and port settings.",
        "limitations": {"passive_accuracy": "Direct observation of SMTP/IMAP/POP3 error codes or immediate alert."}
    },
    "ST-003": {
        "title": "Authentication before TLS",
        "severity": "CRITICAL",
        "confidence": "DIRECT",
        "category": "Protocol Security",
        "standards_ref": "RFC 8314 §3, RFC 3207",
        "impact": "Authentication command (AUTH PLAIN/LOGIN/USER/PASS) observed across unencrypted connection prior to TLS establishment.",
        "recommendation": "Enforce mandatory TLS before authentication commands and disable plaintext authentication mechanisms over non-TLS connections.",
        "limitations": {"passive_accuracy": "Directly observed command verbs. Credentials redacted per privacy policy."}
    },
    "CERT-001": {
        "title": "Certificate expired",
        "severity": "HIGH",
        "confidence": "DIRECT",
        "category": "Certificate Security",
        "standards_ref": "RFC 5280",
        "impact": "Presented server certificate validity period ended before the session timestamp.",
        "recommendation": "Renew and install updated TLS certificate immediately.",
        "limitations": {"passive_accuracy": "Direct timestamp comparison of not_after vs session capture time."}
    },
    "CERT-002": {
        "title": "Certificate not yet valid",
        "severity": "MEDIUM",
        "confidence": "DIRECT",
        "category": "Certificate Security",
        "standards_ref": "RFC 5280",
        "impact": "Certificate not_before date is in the future relative to the session start time.",
        "recommendation": "Verify system clock synchronization and certificate start date.",
        "limitations": {"passive_accuracy": "Direct timestamp comparison."}
    },
    "CERT-003": {
        "title": "Self-signed certificate",
        "severity": "MEDIUM",
        "confidence": "HIGH CONFIDENCE",
        "category": "Certificate Security",
        "standards_ref": "RFC 5280",
        "impact": "Certificate subject and issuer are identical, indicating self-signed certificate without third-party CA validation.",
        "recommendation": "Deploy a certificate signed by a recognized, trusted public or enterprise Certificate Authority.",
        "limitations": {"passive_accuracy": "Observed X.509 subject and issuer equality."}
    },
    "CERT-004": {
        "title": "Hostname mismatch",
        "severity": "HIGH",
        "confidence": "DIRECT",
        "category": "Certificate Security",
        "standards_ref": "RFC 6125",
        "impact": "Observed ClientHello Server Name Indication (SNI) does not match any DNS names or IPs in certificate SAN or Subject CN.",
        "recommendation": "Update server certificate to include correct Subject Alternative Names (SAN) for all mail service endpoints.",
        "limitations": {"passive_accuracy": "Requires observable SNI in ClientHello and observable certificate in Server Certificate."}
    },
    "CERT-005": {
        "title": "Weak public key",
        "severity": "HIGH",
        "confidence": "DIRECT",
        "category": "Certificate Security",
        "standards_ref": "NIST SP 800-131A Rev. 2",
        "impact": "Server certificate public key length is below recommended threshold (RSA < 2048 bits or EC < 224 bits).",
        "recommendation": "Reissue certificate with minimum 2048-bit RSA key or 256-bit ECDSA key.",
        "limitations": {"passive_accuracy": "Direct extraction of public key parameters."}
    },
    "CERT-006": {
        "title": "Weak signature algorithm",
        "severity": "HIGH",
        "confidence": "DIRECT",
        "category": "Certificate Security",
        "standards_ref": "NIST SP 800-131A Rev. 2",
        "impact": "Certificate signature uses a deprecated collision-vulnerable hash algorithm (e.g. SHA-1 or MD5).",
        "recommendation": "Reissue certificate signed with SHA-256 or stronger digest algorithm.",
        "limitations": {"passive_accuracy": "Direct inspection of signatureAlgorithm OID."}
    },
    "CERT-007": {
        "title": "Observed certificate chain incomplete",
        "severity": "LOW",
        "confidence": "MEDIUM CONFIDENCE",
        "category": "Certificate Security",
        "standards_ref": "RFC 5280",
        "impact": "Only the leaf certificate was observed in the capture. Note: Incomplete observed chain does not prove server chain is broken (client may cache intermediate CA).",
        "recommendation": "Ensure mail server bundles full intermediate CA certificate chain in TLS handshake.",
        "limitations": {"passive_accuracy": "Passive capture limitation: client or intermediate packet loss may affect chain observation."}
    },
    "CERT-008": {
        "title": "Untrusted issuer, external validation only",
        "severity": "MEDIUM",
        "confidence": "EXTERNAL VALIDATION",
        "category": "Certificate Security",
        "standards_ref": "RFC 5280",
        "impact": "Certificate issuer not present in default operating system trust store; requires external trust anchor verification.",
        "recommendation": "Verify internal enterprise root CA distribution across mail client endpoints.",
        "limitations": {"passive_accuracy": "External validation required; passive capture cannot definitively verify trust without local store."}
    },
    "CERT-009": {
        "title": "Excessive validity period, policy-dependent",
        "severity": "LOW",
        "confidence": "DIRECT",
        "category": "Certificate Security",
        "standards_ref": "CA/Browser Forum, RFC 5280",
        "impact": "Certificate validity exceeds recommended policy threshold (e.g. 398 days).",
        "recommendation": "Shorten certificate lifetime in line with modern CA/Browser Forum and NIST guidelines.",
        "limitations": {"passive_accuracy": "Direct calculation: not_after - not_before evaluated against policy."}
    },
    "FLOW-001": {
        "title": "Unexpected protocol on expected email port",
        "severity": "MEDIUM",
        "confidence": "DIRECT",
        "category": "Protocol Security",
        "standards_ref": "RFC 8314",
        "impact": "Traffic on standard email ports (25, 587, 465, 110, 995, 143, 993) did not conform to email protocol syntax.",
        "recommendation": "Investigate host for misconfigured services or non-mail traffic tunneling over email ports.",
        "limitations": {"passive_accuracy": "Evaluated against protocol heuristic detection."}
    }
}
