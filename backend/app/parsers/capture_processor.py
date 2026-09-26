import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session as DBSession

from app.core.config import settings
from app.core.database import SessionLocal
from app.models import Capture, Host, Session, TLSHandshake, Certificate
from app.parsers.pcap_reader import PCAPReader
from app.parsers.tcp_reassembler import TCPReassembler, TCPStream, EMAIL_PORTS
from app.parsers.protocols.smtp import parse_smtp_stream
from app.parsers.protocols.imap import parse_imap_stream
from app.parsers.protocols.pop3 import parse_pop3_stream
from app.parsers.tls import parse_tls_stream
from app.parsers.certificate import parse_x509_certificate
from app.rules.engine import evaluate_rules
from app.scoring.engine import calculate_scores
from app.ml.anomaly_detector import run_anomaly_detection

def safe_fromtimestamp(ts: Optional[float]) -> datetime:
    if ts is None:
        return datetime.now(timezone.utc)
    # If timestamp is wildly large (> year 3000 in seconds), scale down
    while ts > 1e11:
        ts /= 1000.0
    try:
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return datetime.now(timezone.utc)

def process_pcap_file(capture_id: str, db: Optional[DBSession] = None):
    """
    Background worker that parses the PCAP/PCAPNG capture, creates database entities,
    evaluates deterministic rules, calculates posture scores, and runs ML anomaly detection.
    """
    owns_db = False
    if db is None:
        db = SessionLocal()
        owns_db = True

    try:
        capture = db.query(Capture).filter(Capture.capture_id == capture_id).first()
        if not capture:
            return

        filepath = settings.UPLOAD_DIR / f"{capture_id}_{capture.filename}"
        if not filepath.exists():
            capture.status = "FAILED"
            capture.error_message = f"File not found on disk: {filepath}"
            capture.error_stage = "FILE_VERIFICATION"
            db.commit()
            return

        capture.status = "PROCESSING"
        capture.processing_stage = "READING_PCAP"
        db.commit()

        # Step 1: Stream packets through TCP reassembler
        reassembler = TCPReassembler()
        packet_count = 0
        with PCAPReader(str(filepath)) as reader:
            for pkt in reader.read_packets():
                packet_count += 1
                reassembler.process_packet(pkt)

        capture.processing_stage = "REASSEMBLING_STREAMS"
        db.commit()

        streams = reassembler.get_completed_streams()
        hosts_map: Dict[str, Host] = {}

        total_sessions = len(streams)
        tls13_count = 0
        observed_fields_count = 0
        expected_fields_count = 0

        created_sessions: List[Session] = []

        # Step 2: Parse protocols and crypto for each stream
        for idx, stream in enumerate(streams):
            c2s_bytes = stream.get_c2s_stream()
            s2c_bytes = stream.get_s2c_stream()

            # Host creation/lookup for server
            server_ip = stream.server_ip
            if server_ip not in hosts_map:
                existing_host = db.query(Host).filter(
                    Host.capture_id == capture_id,
                    Host.ip == server_ip
                ).first()
                if not existing_host:
                    host_id = f"host-{uuid.uuid4().hex}"
                    new_host = Host(
                        host_id=host_id,
                        capture_id=capture_id,
                        ip=server_ip,
                        hostname=None
                    )
                    db.add(new_host)
                    db.flush()
                    hosts_map[server_ip] = new_host
                else:
                    hosts_map[server_ip] = existing_host

            host_obj = hosts_map[server_ip]

            # Protocol detection
            proto_result = {"is_protocol": False, "protocol": "UNKNOWN", "starttls_state": "NOT_OFFERED", "auth_observed": False, "auth_plaintext": False}
            if stream.server_port in {25, 465, 587} or (25 in {stream.client_port, stream.server_port}):
                proto_result = parse_smtp_stream(c2s_bytes, s2c_bytes, stream.server_port)
            elif stream.server_port in {143, 993} or (143 in {stream.client_port, stream.server_port}):
                proto_result = parse_imap_stream(c2s_bytes, s2c_bytes, stream.server_port)
            elif stream.server_port in {110, 995} or (110 in {stream.client_port, stream.server_port}):
                proto_result = parse_pop3_stream(c2s_bytes, s2c_bytes, stream.server_port)
            else:
                # Check for plaintext greetings
                if b"220" in s2c_bytes and b"SMTP" in s2c_bytes:
                    proto_result = parse_smtp_stream(c2s_bytes, s2c_bytes, stream.server_port)
                elif b"* OK" in s2c_bytes and b"IMAP" in s2c_bytes:
                    proto_result = parse_imap_stream(c2s_bytes, s2c_bytes, stream.server_port)
                elif b"+OK" in s2c_bytes and b"POP3" in s2c_bytes:
                    proto_result = parse_pop3_stream(c2s_bytes, s2c_bytes, stream.server_port)

            # TLS Parsing
            tls_data = parse_tls_stream(c2s_bytes, s2c_bytes)
            starttls_state = proto_result.get("starttls_state", "NOT_OFFERED")
            if tls_data and starttls_state == "ACCEPTED":
                starttls_state = "TLS_ESTABLISHED"
            elif tls_data and stream.server_port in {465, 993, 995}:
                starttls_state = "TLS_ESTABLISHED"  # Implicit TLS

            session_id = f"sess-{uuid.uuid4().hex}"
            sess_model = Session(
                session_id=session_id,
                capture_id=capture_id,
                host_id=host_obj.host_id,
                protocol=proto_result.get("protocol", "UNKNOWN"),
                protocol_confidence="DIRECT" if proto_result.get("is_protocol") else "UNKNOWN",
                client_ip=stream.client_ip,
                client_port=stream.client_port,
                server_ip=stream.server_ip,
                server_port=stream.server_port,
                starttls_state=starttls_state,
                capture_completeness=1.0,
                start_time=safe_fromtimestamp(stream.start_time),
                end_time=safe_fromtimestamp(stream.end_time),
                packet_count=stream.packet_count,
                byte_count=stream.byte_count,
                auth_observed=proto_result.get("auth_observed", False),
                auth_plaintext=proto_result.get("auth_plaintext", False)
            )
            db.add(sess_model)
            db.flush()
            created_sessions.append(sess_model)

            expected_fields_count += 5
            observed_fields_count += 3

            # Add TLS Handshake and Certificates if found
            if tls_data:
                handshake_id = f"hs-{uuid.uuid4().hex}"
                if tls_data.get("is_tls13"):
                    tls13_count += 1

                # Update SNI as hostname if discovered
                if tls_data.get("sni") and not host_obj.hostname:
                    host_obj.hostname = tls_data.get("sni")

                hs_model = TLSHandshake(
                    handshake_id=handshake_id,
                    session_id=session_id,
                    version=tls_data.get("version"),
                    cipher_suite=tls_data.get("cipher_suite"),
                    key_exchange=tls_data.get("key_exchange"),
                    forward_secrecy=tls_data.get("forward_secrecy", False),
                    sni=tls_data.get("sni"),
                    alpn=tls_data.get("alpn"),
                    supported_groups=tls_data.get("supported_groups", []),
                    signature_algorithm=tls_data.get("signature_algorithm"),
                    session_resumption=tls_data.get("session_resumption", False),
                    handshake_sequence=tls_data.get("handshake_sequence", []),
                    alerts=tls_data.get("alerts", []),
                    ja3_fingerprint=tls_data.get("ja3_fingerprint"),
                    ja3s_fingerprint=tls_data.get("ja3s_fingerprint"),
                    duration_ms=(stream.end_time - stream.start_time) * 1000
                )
                db.add(hs_model)
                db.flush()

                # Parse X.509 certs
                cert_der_list = tls_data.get("certificate_der_list", [])
                for c_idx, der in enumerate(cert_der_list):
                    cert_dict = parse_x509_certificate(der, chain_position=c_idx)
                    if cert_dict:
                        cert_model = Certificate(
                            cert_id=f"cert-{uuid.uuid4().hex}",
                            handshake_id=handshake_id,
                            subject=cert_dict["subject"],
                            issuer=cert_dict["issuer"],
                            san=cert_dict["san"],
                            not_before=cert_dict["not_before"],
                            not_after=cert_dict["not_after"],
                            public_key_alg=cert_dict["public_key_alg"],
                            key_bits=cert_dict["key_bits"],
                            signature_alg=cert_dict["signature_alg"],
                            basic_constraints=cert_dict["basic_constraints"],
                            key_usage=cert_dict["key_usage"],
                            extended_key_usage=cert_dict["extended_key_usage"],
                            chain_position=cert_dict["chain_position"],
                            is_self_signed=cert_dict["is_self_signed"]
                        )
                        db.add(cert_model)
                db.flush()

        # Step 3: Run Deterministic Rules Engine
        capture.processing_stage = "EVALUATING_RULES"
        db.commit()
        evaluate_rules(capture_id, db)

        # Step 4: Run Machine Learning Anomaly Detection (Optional/P1)
        capture.processing_stage = "RUNNING_ANOMALY_DETECTION"
        db.commit()
        try:
            run_anomaly_detection(capture_id, db)
        except Exception as ml_err:
            # Anomaly detection is optional — do not fail the pipeline if
            # scikit-learn cannot load (e.g. Windows Application Control
            # blocking native DLLs) or if the model raises any other error.
            import logging
            logging.getLogger(__name__).warning(
                "Anomaly detection skipped for %s: %s", capture_id, ml_err
            )

        # Step 5: Calculate Posture Scores & Audit Trail
        capture.processing_stage = "CALCULATING_SCORES"
        db.commit()
        calculate_scores(capture_id, db)

        # Step 6: Mark Complete
        visibility_rate = 1.0
        if total_sessions > 0 and tls13_count > 0:
            visibility_rate = max(0.4, 1.0 - (tls13_count / total_sessions * 0.5))

        capture.status = "COMPLETE"
        capture.processing_stage = "COMPLETE"
        capture.processed_at = datetime.now(timezone.utc)
        capture.completeness = 1.0
        capture.passive_visibility_rate = round(visibility_rate, 2)
        db.commit()

    except Exception as e:
        db.rollback()
        capture.status = "FAILED"
        capture.error_stage = capture.processing_stage
        capture.error_message = str(e)
        db.commit()
    finally:
        if owns_db:
            db.close()
