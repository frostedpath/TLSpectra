import struct
import hashlib
from typing import Dict, Any, List, Optional, Tuple

# Comprehensive standard cipher suites mapping
CIPHER_SUITES: Dict[int, Dict[str, Any]] = {
    # TLS 1.3 (RFC 8446)
    0x1301: {"name": "TLS_AES_128_GCM_SHA256", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.3"},
    0x1302: {"name": "TLS_AES_256_GCM_SHA384", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.3"},
    0x1303: {"name": "TLS_CHACHA20_POLY1305_SHA256", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.3"},
    0x1304: {"name": "TLS_AES_128_CCM_SHA256", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.3"},
    0x1305: {"name": "TLS_AES_128_CCM_8_SHA256", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.3"},

    # Modern TLS 1.2 ECDHE suites (Forward Secret)
    0xC02F: {"name": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.2"},
    0xC030: {"name": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.2"},
    0xC02B: {"name": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.2"},
    0xC02C: {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.2"},
    0xCCA8: {"name": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.2"},
    0xCCA9: {"name": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", "kx": "ECDHE", "fs": True, "weak": False, "version": "TLS 1.2"},

    # Static RSA suites (No Forward Secrecy, High risk per TLS-003/004)
    0x002F: {"name": "TLS_RSA_WITH_AES_128_CBC_SHA", "kx": "RSA", "fs": False, "weak": False, "version": "TLS 1.2"},
    0x0035: {"name": "TLS_RSA_WITH_AES_256_CBC_SHA", "kx": "RSA", "fs": False, "weak": False, "version": "TLS 1.2"},
    0x009C: {"name": "TLS_RSA_WITH_AES_128_GCM_SHA256", "kx": "RSA", "fs": False, "weak": False, "version": "TLS 1.2"},
    0x009D: {"name": "TLS_RSA_WITH_AES_256_GCM_SHA384", "kx": "RSA", "fs": False, "weak": False, "version": "TLS 1.2"},

    # Deprecated & Insecure suites (RC4, 3DES, DES, EXPORT, NULL)
    0x000A: {"name": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "kx": "RSA", "fs": False, "weak": True, "version": "TLS 1.0"},
    0x0005: {"name": "TLS_RSA_WITH_RC4_128_SHA", "kx": "RSA", "fs": False, "weak": True, "version": "TLS 1.0"},
    0x0004: {"name": "TLS_RSA_WITH_RC4_128_MD5", "kx": "RSA", "fs": False, "weak": True, "version": "TLS 1.0"},
    0x0009: {"name": "TLS_RSA_WITH_DES_CBC_SHA", "kx": "RSA", "fs": False, "weak": True, "version": "TLS 1.0"},
    0x0001: {"name": "TLS_RSA_WITH_NULL_MD5", "kx": "RSA", "fs": False, "weak": True, "version": "TLS 1.0"},
    0x0002: {"name": "TLS_RSA_WITH_NULL_SHA", "kx": "RSA", "fs": False, "weak": True, "version": "TLS 1.0"},
}

TLS_VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3"
}

ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    30: "decompression_failure",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    70: "protocol_version",
    80: "internal_error"
}

def parse_tls_stream(c2s_bytes: bytes, s2c_bytes: bytes) -> Optional[Dict[str, Any]]:
    """
    Scans for TLS records in bidirectional traffic, parses ClientHello, ServerHello,
    Certificate, Alerts, and computes JA3/JA3S fingerprints.
    """
    client_hello = _find_and_parse_client_hello(c2s_bytes)
    server_hello, cert_der_list, alerts = _find_and_parse_server_messages(s2c_bytes)

    if not client_hello and not server_hello and not alerts:
        return None

    # Determine negotiated version and cipher
    negotiated_version = None
    cipher_suite_name = None
    key_exchange = None
    forward_secrecy = False
    is_weak_cipher = False

    if server_hello:
        negotiated_version = server_hello.get("version")
        cipher_id = server_hello.get("cipher_suite_id")
        cipher_info = CIPHER_SUITES.get(cipher_id, {
            "name": f"UNKNOWN_CIPHER_0x{cipher_id:04x}" if cipher_id else "UNKNOWN",
            "kx": "UNKNOWN",
            "fs": False,
            "weak": False,
            "version": negotiated_version or "UNKNOWN"
        })
        cipher_suite_name = cipher_info["name"]
        key_exchange = cipher_info["kx"]
        forward_secrecy = cipher_info["fs"]
        is_weak_cipher = cipher_info["weak"]
    elif client_hello:
        negotiated_version = client_hello.get("version")

    # JA3 / JA3S fingerprints
    ja3 = client_hello.get("ja3") if client_hello else None
    ja3s = server_hello.get("ja3s") if server_hello else None

    return {
        "version": negotiated_version,
        "cipher_suite": cipher_suite_name,
        "key_exchange": key_exchange,
        "forward_secrecy": forward_secrecy,
        "is_weak_cipher": is_weak_cipher,
        "sni": client_hello.get("sni") if client_hello else None,
        "alpn": client_hello.get("alpn") if client_hello else None,
        "supported_groups": client_hello.get("supported_groups", []) if client_hello else [],
        "signature_algorithm": client_hello.get("signature_algorithms", [None])[0] if client_hello else None,
        "session_resumption": bool(client_hello and client_hello.get("session_id")),
        "handshake_sequence": ["ClientHello"] if client_hello else [] + (["ServerHello"] if server_hello else []),
        "alerts": alerts,
        "ja3_fingerprint": ja3,
        "ja3s_fingerprint": ja3s,
        "certificate_der_list": cert_der_list,
        "is_tls13": (negotiated_version == "TLS 1.3")
    }

def _find_and_parse_client_hello(data: bytes) -> Optional[Dict[str, Any]]:
    # Search for TLS Record: ContentType=0x16 (Handshake), Version=0x0301/0x0303
    offset = 0
    while offset + 5 <= len(data):
        content_type, major, minor, length = struct.unpack("!BBBH", data[offset:offset+5])
        if content_type == 0x16 and major == 3:
            record_data = data[offset+5:offset+5+length]
            if len(record_data) >= 4:
                hs_type, hs_len1, hs_len2 = struct.unpack("!BBH", record_data[:4])
                hs_len = (hs_len1 << 16) | hs_len2
                if hs_type == 0x01:  # ClientHello
                    return _parse_client_hello(record_data[4:4+hs_len])
        offset += 1
    return None

def _parse_client_hello(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 34:
        return None
    ver_num = struct.unpack("!H", data[:2])[0]
    client_version = TLS_VERSIONS.get(ver_num, f"0x{ver_num:04x}")
    # skip random (32 bytes)
    offset = 34
    if offset >= len(data):
        return None
    session_id_len = data[offset]
    offset += 1 + session_id_len
    if offset + 2 > len(data):
        return None
    cipher_len = struct.unpack("!H", data[offset:offset+2])[0]
    offset += 2
    ciphers = []
    for i in range(0, cipher_len, 2):
        if offset + i + 2 <= len(data):
            ciphers.append(struct.unpack("!H", data[offset+i:offset+i+2])[0])
    offset += cipher_len

    if offset >= len(data):
        return None
    comp_len = data[offset]
    offset += 1 + comp_len

    extensions = []
    sni = None
    alpn = None
    supported_groups = []
    ec_point_formats = []
    supported_versions = []

    if offset + 2 <= len(data):
        ext_total_len = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        end_ext = offset + ext_total_len
        while offset + 4 <= min(end_ext, len(data)):
            ext_type, ext_len = struct.unpack("!HH", data[offset:offset+4])
            offset += 4
            ext_data = data[offset:offset+ext_len]
            extensions.append(ext_type)

            if ext_type == 0x0000:  # SNI
                if len(ext_data) > 5:
                    sni_len = struct.unpack("!H", ext_data[3:5])[0]
                    sni = ext_data[5:5+sni_len].decode("utf-8", errors="ignore")
            elif ext_type == 0x000a:  # Supported Groups
                if len(ext_data) >= 2:
                    grp_len = struct.unpack("!H", ext_data[:2])[0]
                    for g in range(0, grp_len, 2):
                        if 2 + g + 2 <= len(ext_data):
                            supported_groups.append(struct.unpack("!H", ext_data[2+g:2+g+2])[0])
            elif ext_type == 0x000b:  # EC Point Formats
                if len(ext_data) >= 1:
                    ec_point_formats = list(ext_data[1:])
            elif ext_type == 0x0010:  # ALPN
                if len(ext_data) > 2:
                    alpn_len = ext_data[2]
                    alpn = ext_data[3:3+alpn_len].decode("utf-8", errors="ignore")
            elif ext_type == 0x002b:  # Supported Versions
                if len(ext_data) >= 1:
                    v_len = ext_data[0]
                    for v in range(0, v_len, 2):
                        if 1 + v + 2 <= len(ext_data):
                            supported_versions.append(struct.unpack("!H", ext_data[1+v:1+v+2])[0])

            offset += ext_len

    if 0x0304 in supported_versions:
        client_version = "TLS 1.3"

    # Compute JA3 fingerprint: SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
    # Exclude GREASE values
    ciphers_clean = [str(c) for c in ciphers if (c & 0x0F0F) != 0x0A0A]
    exts_clean = [str(e) for e in extensions if (e & 0x0F0F) != 0x0A0A]
    groups_clean = [str(g) for g in supported_groups if (g & 0x0F0F) != 0x0A0A]
    points_clean = [str(p) for p in ec_point_formats]
    ja3_str = f"{ver_num},{'-'.join(ciphers_clean)},{'-'.join(exts_clean)},{'-'.join(groups_clean)},{'-'.join(points_clean)}"
    ja3_hash = hashlib.md5(ja3_str.encode("utf-8")).hexdigest()

    return {
        "version": client_version,
        "sni": sni,
        "alpn": alpn,
        "ciphers": ciphers,
        "extensions": extensions,
        "supported_groups": supported_groups,
        "ja3": ja3_hash,
        "session_id": session_id_len > 0
    }

def _find_and_parse_server_messages(data: bytes) -> Tuple[Optional[Dict[str, Any]], List[bytes], List[Dict[str, Any]]]:
    server_hello = None
    cert_list: List[bytes] = []
    alerts: List[Dict[str, Any]] = []

    offset = 0
    while offset + 5 <= len(data):
        content_type, major, minor, length = struct.unpack("!BBBH", data[offset:offset+5])
        if content_type == 0x15:  # Alert
            alert_data = data[offset+5:offset+5+length]
            if len(alert_data) >= 2:
                level = "FATAL" if alert_data[0] == 2 else "WARNING"
                desc = ALERT_DESCRIPTIONS.get(alert_data[1], f"unknown_{alert_data[1]}")
                alerts.append({"level": level, "description": desc, "code": alert_data[1]})
            offset += 5 + length
            continue

        if content_type == 0x16 and major == 3:  # Handshake
            rec_body = data[offset+5:offset+5+length]
            rec_offset = 0
            while rec_offset + 4 <= len(rec_body):
                hs_type = rec_body[rec_offset]
                hs_len = (rec_body[rec_offset+1] << 16) | (rec_body[rec_offset+2] << 8) | rec_body[rec_offset+3]
                hs_payload = rec_body[rec_offset+4:rec_offset+4+hs_len]

                if hs_type == 0x02:  # ServerHello
                    server_hello = _parse_server_hello(hs_payload)
                elif hs_type == 0x0b:  # Certificate (TLS 1.2 and earlier)
                    cert_list = _parse_certificate_message(hs_payload)

                rec_offset += 4 + hs_len
            offset += 5 + length
            continue

        offset += 1

    return server_hello, cert_list, alerts

def _parse_server_hello(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 34:
        return None
    ver_num = struct.unpack("!H", data[:2])[0]
    server_version = TLS_VERSIONS.get(ver_num, f"0x{ver_num:04x}")
    # skip random (32 bytes)
    offset = 34
    session_id_len = data[offset]
    offset += 1 + session_id_len
    if offset + 2 > len(data):
        return None
    cipher_id = struct.unpack("!H", data[offset:offset+2])[0]
    offset += 2 + 1  # cipher + compression

    extensions = []
    if offset + 2 <= len(data):
        ext_len = struct.unpack("!H", data[offset:offset+2])[0]
        offset += 2
        end_ext = offset + ext_len
        while offset + 4 <= min(end_ext, len(data)):
            ext_type, ext_dlen = struct.unpack("!HH", data[offset:offset+4])
            offset += 4
            ext_data = data[offset:offset+ext_dlen]
            extensions.append(ext_type)
            if ext_type == 0x002b and len(ext_data) >= 2:  # Supported versions (TLS 1.3)
                selected_ver = struct.unpack("!H", ext_data[:2])[0]
                if selected_ver == 0x0304:
                    server_version = "TLS 1.3"
            offset += ext_dlen

    # Compute JA3S: SSLVersion,Cipher,SSLExtension
    exts_clean = [str(e) for e in extensions if (e & 0x0F0F) != 0x0A0A]
    ja3s_str = f"{ver_num},{cipher_id},{'-'.join(exts_clean)}"
    ja3s_hash = hashlib.md5(ja3s_str.encode("utf-8")).hexdigest()

    return {
        "version": server_version,
        "cipher_suite_id": cipher_id,
        "extensions": extensions,
        "ja3s": ja3s_hash
    }

def _parse_certificate_message(data: bytes) -> List[bytes]:
    certs = []
    if len(data) < 3:
        return certs
    total_len = (data[0] << 16) | (data[1] << 8) | data[2]
    offset = 3
    end = min(3 + total_len, len(data))
    while offset + 3 <= end:
        c_len = (data[offset] << 16) | (data[offset+1] << 8) | data[offset+2]
        offset += 3
        if offset + c_len <= end:
            certs.append(data[offset:offset+c_len])
        offset += c_len
    return certs
