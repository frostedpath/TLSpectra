from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, NameOID

def parse_x509_certificate(der_bytes: bytes, chain_position: int = 0) -> Optional[Dict[str, Any]]:
    """
    Parses DER-encoded X.509 certificate using Python cryptography library.
    Extracts all required cryptographic fields.
    """
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception:
        return None

    # Subject and Issuer (RFC 4514 format)
    subject = cert.subject.rfc4514_string()
    issuer = cert.issuer.rfc4514_string()

    # Subject Alternative Names (SAN)
    san_list = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            san_list.append(str(name.value))
    except x509.ExtensionNotFound:
        pass

    # Validity window (with UTC timezone awareness)
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)

    # Public Key Algorithm & Key Length
    pub_key = cert.public_key()
    key_bits = None
    if isinstance(pub_key, rsa.RSAPublicKey):
        pub_key_alg = "RSA"
        key_bits = pub_key.key_size
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        pub_key_alg = f"EC ({pub_key.curve.name})"
        key_bits = pub_key.key_size
    elif isinstance(pub_key, dsa.DSAPublicKey):
        pub_key_alg = "DSA"
        key_bits = pub_key.key_size
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        pub_key_alg = "Ed25519"
        key_bits = 256
    elif isinstance(pub_key, ed448.Ed448PublicKey):
        pub_key_alg = "Ed448"
        key_bits = 448
    else:
        pub_key_alg = type(pub_key).__name__

    # Signature Algorithm
    sig_alg = cert.signature_algorithm_oid._name if hasattr(cert, "signature_algorithm_oid") else "unknown"

    # Basic Constraints
    basic_constraints = None
    try:
        bc_ext = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        ca_flag = "CA:TRUE" if bc_ext.value.ca else "CA:FALSE"
        path_len = f", pathlen:{bc_ext.value.path_length}" if bc_ext.value.path_length is not None else ""
        basic_constraints = f"{ca_flag}{path_len}"
    except x509.ExtensionNotFound:
        pass

    # Key Usage
    key_usage = None
    try:
        ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        ku_list = []
        if ku_ext.value.digital_signature: ku_list.append("Digital Signature")
        if ku_ext.value.content_commitment: ku_list.append("Non Repudiation")
        if ku_ext.value.key_encipherment: ku_list.append("Key Encipherment")
        if ku_ext.value.data_encipherment: ku_list.append("Data Encipherment")
        if ku_ext.value.key_agreement: ku_list.append("Key Agreement")
        if ku_ext.value.key_cert_sign: ku_list.append("Certificate Sign")
        if ku_ext.value.crl_sign: ku_list.append("CRL Sign")
        key_usage = ", ".join(ku_list)
    except (x509.ExtensionNotFound, ValueError):
        pass

    # Extended Key Usage
    extended_key_usage = None
    try:
        eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        extended_key_usage = ", ".join(oid._name for oid in eku_ext.value)
    except x509.ExtensionNotFound:
        pass

    # Self-signed check
    is_self_signed = (subject == issuer)
    if is_self_signed:
        # Verify self-signature if possible
        try:
            pub_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_hash_algorithm
            )
            is_self_signed = True
        except Exception:
            pass

    return {
        "subject": subject,
        "issuer": issuer,
        "san": san_list,
        "not_before": not_before,
        "not_after": not_after,
        "public_key_alg": pub_key_alg,
        "key_bits": key_bits,
        "signature_alg": sig_alg,
        "basic_constraints": basic_constraints,
        "key_usage": key_usage,
        "extended_key_usage": extended_key_usage,
        "chain_position": chain_position,
        "is_self_signed": is_self_signed
    }
