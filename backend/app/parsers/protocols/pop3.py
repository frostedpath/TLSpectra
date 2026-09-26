import re
from typing import Dict, Any

def parse_pop3_stream(c2s_data: bytes, s2c_data: bytes, server_port: int) -> Dict[str, Any]:
    c2s_text = c2s_data.decode("latin-1", errors="ignore")
    s2c_text = s2c_data.decode("latin-1", errors="ignore")

    is_pop3 = (server_port in {110, 995}) or ("+OK" in s2c_text and ("POP3" in s2c_text or "CAPA" in s2c_text))

    starttls_offered = bool(re.search(r"\bSTLS\b", s2c_text, re.IGNORECASE))
    starttls_requested = bool(re.search(r"\bSTLS\b", c2s_text, re.IGNORECASE))
    starttls_accepted = bool(re.search(r"\+OK\b.*(?:begin|start|tls)", s2c_text, re.IGNORECASE))
    starttls_rejected = bool(re.search(r"-ERR\b.*(?:stls|tls)", s2c_text, re.IGNORECASE))

    auth_observed = bool(re.search(r"\b(?:USER|PASS|AUTH)\b", c2s_text, re.IGNORECASE))

    if starttls_accepted:
        state = "ACCEPTED"
    elif starttls_rejected:
        state = "REJECTED"
    elif starttls_requested:
        state = "REQUESTED"
    elif starttls_offered:
        if re.search(r"\b(?:USER|PASS|STAT|LIST|RETR)\b", c2s_text, re.IGNORECASE):
            state = "CLEARTEXT_AFTER_OFFER"
        else:
            state = "OFFERED"
    else:
        state = "NOT_OFFERED"

    return {
        "is_protocol": is_pop3,
        "protocol": "POP3",
        "starttls_offered": starttls_offered,
        "starttls_requested": starttls_requested,
        "starttls_accepted": starttls_accepted,
        "starttls_rejected": starttls_rejected,
        "starttls_state": state,
        "auth_observed": auth_observed,
        "auth_plaintext": auth_observed and (state in {"NOT_OFFERED", "OFFERED", "CLEARTEXT_AFTER_OFFER", "REJECTED"})
    }
