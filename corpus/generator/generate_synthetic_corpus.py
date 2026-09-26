import os
import struct
import socket
import json
import time
from pathlib import Path
from typing import List, Dict, Any

PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def make_ethernet_frame(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + payload

def make_ipv4_packet(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    total_len = 20 + len(payload)
    # Version=4, IHL=5, DSCP=0, TotalLen, ID=1, Flags=0x4000 (DF), TTL=64, Proto=6 (TCP), Checksum=0
    hdr_no_cksum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0x4000, 64, 6, 0, src_bytes, dst_bytes)
    # Simple checksum
    cksum = _checksum(hdr_no_cksum)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0x4000, 64, 6, cksum, src_bytes, dst_bytes)
    return hdr + payload

def make_tcp_packet(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    # DataOffset=5 (20 bytes header)
    data_offset_reserved = (5 << 4)
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset_reserved, flags, 65535, 0, 0)
    return tcp_hdr + payload

def _checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def pack_pcap_record(timestamp_sec: int, timestamp_usec: int, frame_bytes: bytes) -> bytes:
    caplen = len(frame_bytes)
    wirelen = len(frame_bytes)
    record_hdr = struct.pack("<IIII", timestamp_sec, timestamp_usec, caplen, wirelen)
    return record_hdr + frame_bytes

def create_tls_client_hello(sni: str = "mail.example.com", tls13: bool = False) -> bytes:
    ver = 0x0303
    random = b"\x01" * 32
    session_id = b"\x00"
    if tls13:
        ciphers = struct.pack("!H", 0x1301) + struct.pack("!H", 0x1302)
    else:
        ciphers = struct.pack("!H", 0xC02F) + struct.pack("!H", 0xC030)
    cipher_len = struct.pack("!H", len(ciphers))
    comp = b"\x01\x00"

    # Extensions
    # SNI extension
    sni_bytes = sni.encode("utf-8")
    sni_entry = struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    # Supported versions extension (if TLS 1.3)
    if tls13:
        ver_ext_data = struct.pack("!BHH", 4, 0x0304, 0x0303)
        supp_ver_ext = struct.pack("!HH", 0x002b, len(ver_ext_data)) + ver_ext_data
    else:
        supp_ver_ext = b""

    extensions = sni_ext + supp_ver_ext
    ext_len = struct.pack("!H", len(extensions))

    hs_body = struct.pack("!H", ver) + random + session_id + cipher_len + ciphers + comp + ext_len + extensions
    hs_len = len(hs_body)
    hs_hdr = struct.pack("!BBH", 0x01, (hs_len >> 16) & 0xFF, hs_len & 0xFFFF)
    handshake = hs_hdr + hs_body

    rec_hdr = struct.pack("!BBBH", 0x16, 0x03, 0x03, len(handshake))
    return rec_hdr + handshake

def create_tls_server_hello(cipher_id: int = 0xC02F, tls13: bool = False) -> bytes:
    ver = 0x0303
    random = b"\x02" * 32
    session_id = b"\x00"
    ciphers = struct.pack("!H", cipher_id)
    comp = b"\x00"

    if tls13:
        supp_ver_data = struct.pack("!H", 0x0304)
        exts = struct.pack("!HH", 0x002b, len(supp_ver_data)) + supp_ver_data
    else:
        exts = b""
    ext_len = struct.pack("!H", len(exts))

    hs_body = struct.pack("!H", ver) + random + session_id + ciphers + comp + ext_len + exts
    hs_len = len(hs_body)
    hs_hdr = struct.pack("!BBH", 0x02, (hs_len >> 16) & 0xFF, hs_len & 0xFFFF)
    handshake = hs_hdr + hs_body

    rec_hdr = struct.pack("!BBBH", 0x16, 0x03, 0x03, len(handshake))
    return rec_hdr + handshake

def generate_corpus(output_dir: str):
    out_path = Path(output_dir)
    manifest_dir = out_path / "manifests"
    pcap_dir = out_path / "pcaps"
    manifest_dir.mkdir(parents=True, exist_ok=True)
    pcap_dir.mkdir(parents=True, exist_ok=True)

    categories = [
        "Secure",
        "Legacy",
        "Certificate",
        "STARTTLS/STLS",
        "Behavioural",
        "Malformed"
    ]

    all_manifests = []
    base_time = 1726700000

    session_global_idx = 0
    # Minimum 25 sessions in each category (25 * 6 = 150 sessions total)
    for cat in categories:
        for cat_idx in range(1, 26):
            session_global_idx += 1
            scenario_id = f"{cat[:4].upper()}-{cat_idx:02d}"
            client_ip = f"192.168.1.{10 + (session_global_idx % 200)}"
            server_ip = "10.0.0.25"
            client_port = 40000 + (session_global_idx % 20000)
            server_port = 587 if cat != "Malformed" else 25

            expected_findings = []
            expected_confidence = "DIRECT"
            protocol = "SMTP"
            packets = []
            cur_time = base_time + session_global_idx * 10

            c_mac = b"\x00\x11\x22\x33\x44\x55"
            s_mac = b"\xaa\xbb\xcc\xdd\xee\xff"

            # Helper for adding TCP packets
            seq_c = 1000
            seq_s = 5000

            def add_pkt(is_c2s, flags, payload):
                nonlocal seq_c, seq_s, cur_time
                cur_time += 0.05
                if is_c2s:
                    ip_pkt = make_ipv4_packet(client_ip, server_ip, make_tcp_packet(client_port, server_port, seq_c, seq_s, flags, payload))
                    eth = make_ethernet_frame(c_mac, s_mac, ip_pkt)
                    seq_c += max(1, len(payload))
                else:
                    ip_pkt = make_ipv4_packet(server_ip, client_ip, make_tcp_packet(server_port, client_port, seq_s, seq_c, flags, payload))
                    eth = make_ethernet_frame(s_mac, c_mac, ip_pkt)
                    seq_s += max(1, len(payload))
                packets.append((int(cur_time), int((cur_time % 1) * 1e6), eth))

            # TCP 3-way Handshake (SYN, SYN-ACK, ACK)
            add_pkt(True, 0x02, b"")   # SYN
            add_pkt(False, 0x12, b"")  # SYN-ACK
            add_pkt(True, 0x10, b"")   # ACK

            if cat == "Secure":
                protocol = "SMTP" if cat_idx <= 15 else ("IMAP" if cat_idx <= 20 else "POP3")
                server_port = 587 if protocol == "SMTP" else (143 if protocol == "IMAP" else 110)
                add_pkt(False, 0x18, b"220 mail.secure.org ESMTP Postfix\r\n")
                add_pkt(True, 0x18, b"EHLO client.secure.org\r\n")
                add_pkt(False, 0x18, b"250-mail.secure.org\r\n250-STARTTLS\r\n250 OK\r\n")
                add_pkt(True, 0x18, b"STARTTLS\r\n")
                add_pkt(False, 0x18, b"220 2.0.0 Ready to start TLS\r\n")
                # Modern TLS 1.3 or TLS 1.2 ECDHE
                is_t13 = (cat_idx % 2 == 0)
                add_pkt(True, 0x18, create_tls_client_hello("mail.secure.org", tls13=is_t13))
                add_pkt(False, 0x18, create_tls_server_hello(0x1301 if is_t13 else 0xC02F, tls13=is_t13))

            elif cat == "Legacy":
                add_pkt(False, 0x18, b"220 mail.legacy.org ESMTP Sendmail\r\n")
                add_pkt(True, 0x18, b"EHLO client.legacy.org\r\n")
                add_pkt(False, 0x18, b"250-mail.legacy.org\r\n250-STARTTLS\r\n250 OK\r\n")
                add_pkt(True, 0x18, b"STARTTLS\r\n")
                add_pkt(False, 0x18, b"220 2.0.0 Ready to start TLS\r\n")
                # Negotiate TLS 1.0 with 3DES (TLS-001, TLS-002, TLS-003, TLS-004, TLS-005)
                add_pkt(True, 0x18, create_tls_client_hello("mail.legacy.org", tls13=False))
                add_pkt(False, 0x18, create_tls_server_hello(0x000A, tls13=False))
                expected_findings = ["TLS-001", "TLS-002", "TLS-003", "TLS-004", "TLS-005"]

            elif cat == "Certificate":
                add_pkt(False, 0x18, b"220 mail.cert-test.org ESMTP Exim\r\n")
                add_pkt(True, 0x18, b"EHLO client.cert-test.org\r\n")
                add_pkt(False, 0x18, b"250-mail.cert-test.org\r\n250-STARTTLS\r\n250 OK\r\n")
                add_pkt(True, 0x18, b"STARTTLS\r\n")
                add_pkt(False, 0x18, b"220 2.0.0 Ready to start TLS\r\n")
                # TLS handshake with SNI mismatch or cert anomaly
                add_pkt(True, 0x18, create_tls_client_hello("mismatch.cert-test.org", tls13=False))
                add_pkt(False, 0x18, create_tls_server_hello(0xC02F, tls13=False))
                expected_findings = ["CERT-007"]

            elif cat == "STARTTLS/STLS":
                if cat_idx % 2 == 1:
                    # ST-001: STARTTLS advertised but ignored, cleartext MAIL FROM
                    add_pkt(False, 0x18, b"220 mail.stls.org ESMTP Postfix\r\n")
                    add_pkt(True, 0x18, b"EHLO client.stls.org\r\n")
                    add_pkt(False, 0x18, b"250-mail.stls.org\r\n250-STARTTLS\r\n250 OK\r\n")
                    add_pkt(True, 0x18, b"MAIL FROM:<sender@test.org>\r\n")
                    add_pkt(False, 0x18, b"250 2.1.0 Ok\r\n")
                    expected_findings = ["ST-001"]
                else:
                    # ST-003: Plaintext authentication before TLS
                    add_pkt(False, 0x18, b"220 mail.stls.org ESMTP Postfix\r\n")
                    add_pkt(True, 0x18, b"EHLO client.stls.org\r\n")
                    add_pkt(False, 0x18, b"250-mail.stls.org\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n")
                    add_pkt(True, 0x18, b"AUTH PLAIN AHVzZXIAcGFzc3dvcmQ=\r\n")
                    add_pkt(False, 0x18, b"235 2.7.0 Authentication successful\r\n")
                    expected_findings = ["ST-003"]

            elif cat == "Behavioural":
                # Handshake failure alerts flood (TLS-007 / FP-001)
                add_pkt(False, 0x18, b"220 mail.anom.org ESMTP Postfix\r\n")
                add_pkt(True, 0x18, b"EHLO client.anom.org\r\n")
                add_pkt(False, 0x18, b"250-mail.anom.org\r\n250-STARTTLS\r\n250 OK\r\n")
                add_pkt(True, 0x18, b"STARTTLS\r\n")
                add_pkt(False, 0x18, b"220 Ready\r\n")
                add_pkt(True, 0x18, create_tls_client_hello("flood.anom.org", tls13=False))
                # 4 Alert packets (Handshake Failure)
                alert_rec = struct.pack("!BBBHBB", 0x15, 0x03, 0x03, 2, 2, 40)
                add_pkt(False, 0x18, alert_rec * 4)
                expected_findings = ["TLS-007"]

            elif cat == "Malformed":
                # FLOW-001: Non-email protocol traffic on port 25
                add_pkt(True, 0x18, b"GET / HTTP/1.1\r\nHost: mail.malformed.org\r\n\r\n")
                add_pkt(False, 0x18, b"HTTP/1.1 400 Bad Request\r\n\r\n")
                expected_findings = ["FLOW-001"]

            # TCP Connection teardown (FIN, ACK)
            add_pkt(True, 0x11, b"")
            add_pkt(False, 0x10, b"")

            # Write individual pcap
            pcap_file = pcap_dir / f"{scenario_id}.pcap"
            with open(pcap_file, "wb") as pf:
                pf.write(PCAP_GLOBAL_HEADER)
                for ts_s, ts_u, pkt_b in packets:
                    pf.write(pack_pcap_record(ts_s, ts_u, pkt_b))

            manifest = {
                "scenario_id": scenario_id,
                "category": cat,
                "protocol": protocol,
                "client_ip": client_ip,
                "server_ip": server_ip,
                "server_port": server_port,
                "expected_findings": expected_findings,
                "expected_confidence": expected_confidence,
                "pcap_file": str(pcap_file.name)
            }
            all_manifests.append(manifest)

            with open(manifest_dir / f"{scenario_id}.json", "w") as mf:
                json.dump(manifest, mf, indent=2)

    # Also build a single unified demo PCAP containing all 150 sessions for end-to-end demo
    demo_pcap_file = out_path / "securemailscope_demo_corpus.pcap"
    with open(demo_pcap_file, "wb") as df:
        df.write(PCAP_GLOBAL_HEADER)
        for cat in categories:
            for cat_idx in range(1, 26):
                scenario_id = f"{cat[:4].upper()}-{cat_idx:02d}"
                single_pcap = pcap_dir / f"{scenario_id}.pcap"
                with open(single_pcap, "rb") as sf:
                    sf.seek(24)  # Skip global header
                    df.write(sf.read())

    # Write summary manifest index
    with open(out_path / "manifest_index.json", "w") as idx_f:
        json.dump({
            "total_sessions": len(all_manifests),
            "category_distribution": {cat: 25 for cat in categories},
            "demo_pcap": str(demo_pcap_file.name),
            "manifests": all_manifests
        }, idx_f, indent=2)

    print(f"GENERATED {len(all_manifests)} GROUND-TRUTH SESSIONS IN {out_path}")

if __name__ == "__main__":
    generate_corpus(str(Path(__file__).resolve().parent.parent))
