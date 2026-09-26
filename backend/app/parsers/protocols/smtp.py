import re
from typing import Dict, Any, List


def parse_smtp_stream(c2s_data: bytes, s2c_data: bytes, server_port: int) -> Dict[str, Any]:
    c2s_text = c2s_data.decode("latin-1", errors="ignore")
    s2c_text = s2c_data.decode("latin-1", errors="ignore")

    is_smtp = (server_port in {25, 465, 587}) or ("220" in s2c_text and ("ESMTP" in s2c_text or "SMTP" in s2c_text))
    
    starttls_offered = bool(re.search(r"250[- ]STARTTLS", s2c_text, re.IGNORECASE))
    starttls_requested = bool(re.search(r"\bSTARTTLS\b", c2s_text, re.IGNORECASE))
    starttls_accepted = bool(re.search(r"220[ -].*(?:ready|start|tls)", s2c_text, re.IGNORECASE))
    starttls_rejected = bool(re.search(r"(?:454|501|503)[ -].*(?:tls|starttls)", s2c_text, re.IGNORECASE))

    # Plaintext authentication detection
    auth_patterns = [
        r"\bAUTH\s+(?:PLAIN|LOGIN|CRAM-MD5|EXTERNAL)\b",
        r"\bAUTH\b"
    ]
    auth_observed = any(re.search(p, c2s_text, re.IGNORECASE) for p in auth_patterns)

    # Transition state determination
    if starttls_accepted:
        state = "ACCEPTED"
    elif starttls_rejected:
        state = "REJECTED"
    elif starttls_requested:
        state = "REQUESTED"
    elif starttls_offered:
        # Check if traffic continued in cleartext without requesting STARTTLS
        if re.search(r"\b(?:MAIL FROM|RCPT TO|DATA|AUTH)\b", c2s_text, re.IGNORECASE):
            state = "CLEARTEXT_AFTER_OFFER"
        else:
            state = "OFFERED"
    else:
        state = "NOT_OFFERED"

    return {
        "is_protocol": is_smtp,
        "protocol": "SMTP",
        "starttls_offered": starttls_offered,
        "starttls_requested": starttls_requested,
        "starttls_accepted": starttls_accepted,
        "starttls_rejected": starttls_rejected,
        "starttls_state": state,
        "auth_observed": auth_observed,
        "auth_plaintext": auth_observed and (state in {"NOT_OFFERED", "OFFERED", "CLEARTEXT_AFTER_OFFER", "REJECTED"})
    }
