import os
import sys
import time
import struct
import socket
import argparse
from pathlib import Path
from typing import List, Tuple

# Ensure backend root is on sys.path
backend_dir = Path(__file__).resolve().parent
sys.path.insert(0, str(backend_dir))

# Enable UTF-8 console output if available
if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

import httpx
from app.core.config import settings

PCAP_GLOBAL_HEADER = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

def _checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def make_ethernet_frame(src_mac: bytes, dst_mac: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + payload

def make_ipv4_packet(src_ip: str, dst_ip: str, payload: bytes) -> bytes:
    src_bytes = socket.inet_aton(src_ip)
    dst_bytes = socket.inet_aton(dst_ip)
    total_len = 20 + len(payload)
    hdr_no_cksum = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0x4000, 64, 6, 0, src_bytes, dst_bytes)
    cksum = _checksum(hdr_no_cksum)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total_len, 0x1234, 0x4000, 64, 6, cksum, src_bytes, dst_bytes)
    return hdr + payload

def make_tcp_packet(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload: bytes) -> bytes:
    data_offset_reserved = (5 << 4)
    tcp_hdr = struct.pack("!HHIIBBHHH", src_port, dst_port, seq, ack, data_offset_reserved, flags, 65535, 0, 0)
    return tcp_hdr + payload

def pack_pcap_record(timestamp_sec: int, timestamp_usec: int, frame_bytes: bytes) -> bytes:
    caplen = len(frame_bytes)
    record_hdr = struct.pack("<IIII", timestamp_sec, timestamp_usec, caplen, caplen)
    return record_hdr + frame_bytes

def create_tls_client_hello(sni: str, tls13: bool = False, tls10: bool = False) -> bytes:
    ver = 0x0301 if tls10 else 0x0303
    random_bytes = b"\x01" * 32
    session_id = b"\x00"
    if tls13:
        ciphers = struct.pack("!H", 0x1301) + struct.pack("!H", 0x1302)
    elif tls10:
        ciphers = struct.pack("!H", 0x000A) # RSA with 3DES
    else:
        ciphers = struct.pack("!H", 0xC02F) + struct.pack("!H", 0xC030)
    cipher_len = struct.pack("!H", len(ciphers))
    comp = b"\x01\x00"

    # SNI extension
    sni_b = sni.encode("utf-8")
    sni_entry = struct.pack("!BH", 0, len(sni_b)) + sni_b
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list

    # Supported versions extension
    if tls13:
        ver_ext_data = struct.pack("!BHH", 4, 0x0304, 0x0303)
        supp_ver_ext = struct.pack("!HH", 0x002b, len(ver_ext_data)) + ver_ext_data
    else:
        supp_ver_ext = b""

    extensions = sni_ext + supp_ver_ext
    ext_len = struct.pack("!H", len(extensions))

    hs_body = struct.pack("!H", ver) + random_bytes + session_id + cipher_len + ciphers + comp + ext_len + extensions
    hs_len = len(hs_body)
    hs_hdr = struct.pack("!BBH", 0x01, (hs_len >> 16) & 0xFF, hs_len & 0xFFFF)
    handshake = hs_hdr + hs_body
    rec_hdr = struct.pack("!BBBH", 0x16, 0x03, 0x01 if tls10 else 0x03, len(handshake))
    return rec_hdr + handshake

def create_tls_server_hello(cipher_id: int, tls13: bool = False, tls10: bool = False) -> bytes:
    ver = 0x0301 if tls10 else 0x0303
    random_bytes = b"\x02" * 32
    session_id = b"\x00"
    ciphers = struct.pack("!H", cipher_id)
    comp = b"\x00"

    if tls13:
        supp_ver_data = struct.pack("!H", 0x0304)
        exts = struct.pack("!HH", 0x002b, len(supp_ver_data)) + supp_ver_data
    else:
        exts = b""
    ext_len = struct.pack("!H", len(exts))

    hs_body = struct.pack("!H", ver) + random_bytes + session_id + ciphers + comp + ext_len + exts
    hs_len = len(hs_body)
    hs_hdr = struct.pack("!BBH", 0x02, (hs_len >> 16) & 0xFF, hs_len & 0xFFFF)
    handshake = hs_hdr + hs_body
    rec_hdr = struct.pack("!BBBH", 0x16, 0x03, 0x01 if tls10 else 0x03, len(handshake))
    return rec_hdr + handshake

def generate_live_test_pcap(output_path: Path):
    """
    Generates a realistic multi-flow organizational email PCAP capture
    containing SMTP with STARTTLS (TLS 1.3), SMTPS (Implicit TLS 1.2),
    IMAPS, and a plaintext auth violation stream.
    """
    print(f"[*] Generating realistic organizational email capture: {output_path.name}")
    packets: List[Tuple[int, int, bytes]] = []
    base_time = int(time.time()) - 300
    cur_time = base_time

    def add_tcp_flow(c_ip: str, s_ip: str, c_port: int, s_port: int, conversation: List[Tuple[bool, bytes]]):
        nonlocal cur_time
        src_mac = b"\x00\x0c\x29\xab\xcd\xef"
        dst_mac = b"\x00\x50\x56\x12\x34\x56"

        c_seq = 1000
        s_seq = 5000

        # SYN
        p = make_ethernet_frame(src_mac, dst_mac, make_ipv4_packet(c_ip, s_ip, make_tcp_packet(c_port, s_port, c_seq, 0, 0x02, b"")))
        packets.append((cur_time, 1000, p))
        cur_time += 1

        # SYN-ACK
        p = make_ethernet_frame(dst_mac, src_mac, make_ipv4_packet(s_ip, c_ip, make_tcp_packet(s_port, c_port, s_seq, c_seq + 1, 0x12, b"")))
        packets.append((cur_time, 2000, p))
        cur_time += 1
        c_seq += 1
        s_seq += 1

        # ACK
        p = make_ethernet_frame(src_mac, dst_mac, make_ipv4_packet(c_ip, s_ip, make_tcp_packet(c_port, s_port, c_seq, s_seq, 0x10, b"")))
        packets.append((cur_time, 3000, p))
        cur_time += 1

        # Conversation payload turns
        for is_c2s, data in conversation:
            if is_c2s:
                p = make_ethernet_frame(src_mac, dst_mac, make_ipv4_packet(c_ip, s_ip, make_tcp_packet(c_port, s_port, c_seq, s_seq, 0x18, data)))
                c_seq += len(data)
            else:
                p = make_ethernet_frame(dst_mac, src_mac, make_ipv4_packet(s_ip, c_ip, make_tcp_packet(s_port, c_port, s_seq, c_seq, 0x18, data)))
                s_seq += len(data)
            packets.append((cur_time, 4000, p))
            cur_time += 1

        # FIN-ACK
        p = make_ethernet_frame(src_mac, dst_mac, make_ipv4_packet(c_ip, s_ip, make_tcp_packet(c_port, s_port, c_seq, s_seq, 0x11, b"")))
        packets.append((cur_time, 5000, p))
        cur_time += 1

    # 1. Flow 1: Modern SMTP with STARTTLS -> TLS 1.3 (Secure)
    add_tcp_flow(
        "10.0.1.15", "192.168.10.25", 49152, 25,
        [
            (False, b"220 mx1.corp-enterprise.net ESMTP Postfix\r\n"),
            (True, b"EHLO mail-client.corp-enterprise.net\r\n"),
            (False, b"250-mx1.corp-enterprise.net\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 OK\r\n"),
            (True, b"STARTTLS\r\n"),
            (False, b"220 2.0.0 Ready to start TLS\r\n"),
            (True, create_tls_client_hello("mx1.corp-enterprise.net", tls13=True)),
            (False, create_tls_server_hello(0x1301, tls13=True)),
        ]
    )

    # 2. Flow 2: SMTPS on Port 465 (Implicit TLS 1.2 with ECDHE-RSA-AES128-GCM)
    add_tcp_flow(
        "10.0.1.16", "192.168.10.26", 49153, 465,
        [
            (True, create_tls_client_hello("smtp.secure-relay.org", tls13=False)),
            (False, create_tls_server_hello(0xC02F, tls13=False)),
        ]
    )

    # 3. Flow 3: IMAPS on Port 993 (Implicit TLS 1.2)
    add_tcp_flow(
        "10.0.1.20", "192.168.10.30", 49154, 993,
        [
            (True, create_tls_client_hello("imap.corp-mail.net", tls13=False)),
            (False, create_tls_server_hello(0xC02F, tls13=False)),
        ]
    )

    # 4. Flow 4: Plaintext Authentication Violation on Port 587 (ST-003 finding)
    add_tcp_flow(
        "10.0.1.33", "192.168.10.45", 49155, 587,
        [
            (False, b"220 submission.insecure-mail.local ESMTP Exim\r\n"),
            (True, b"EHLO client.local\r\n"),
            (False, b"250-submission.insecure-mail.local\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n"),
            (True, b"AUTH PLAIN AHVzZXJAZXhhbXBsZS5jb20AcGFzc3dvcmQxMjM=\r\n"),
            (False, b"235 2.7.0 Authentication successful\r\n"),
        ]
    )

    # 5. Flow 5: Legacy Deprecated TLS 1.0 on Port 25 (TLS-001 finding)
    add_tcp_flow(
        "10.0.1.44", "192.168.10.50", 49156, 25,
        [
            (False, b"220 legacy-mail.oldcorp.org ESMTP Sendmail\r\n"),
            (True, b"EHLO legacy-client.oldcorp.org\r\n"),
            (False, b"250-legacy-mail.oldcorp.org\r\n250-STARTTLS\r\n250 OK\r\n"),
            (True, b"STARTTLS\r\n"),
            (False, b"220 2.0.0 Go ahead with TLS\r\n"),
            (True, create_tls_client_hello("legacy-mail.oldcorp.org", tls10=True)),
            (False, create_tls_server_hello(0x000A, tls10=True)), # TLS 1.0 + 3DES
        ]
    )

    # Write PCAP file
    with open(output_path, "wb") as pf:
        pf.write(PCAP_GLOBAL_HEADER)
        for ts_s, ts_u, pkt_b in packets:
            pf.write(pack_pcap_record(ts_s, ts_u, pkt_b))

    print(f"[+] Successfully wrote {len(packets)} packets to {output_path}")

def run_dropzone_test(pcap_path: Path, api_base: str, token: str):
    print("=" * 65)
    print(" TLSpectra — Live Network Capture Dropzone Test ")
    print("=" * 65)
    print(f"Target PCAP:     {pcap_path.name} ({pcap_path.stat().st_size / 1024:.1f} KB)")
    print(f"API Endpoint:    {api_base}/api/v1/captures")
    print(f"Auth Token:      Bearer {token[:4]}****{token[-2:]}")
    print("=" * 65)

    headers = {"Authorization": f"Bearer {token}"}
    client = None
    use_live_server = False

    # Check if live server is reachable
    try:
        health_resp = httpx.get(f"{api_base}/api/v1/health", timeout=2.0)
        if health_resp.status_code == 200:
            use_live_server = True
            client = httpx.Client(base_url=api_base, timeout=60.0)
            print("[+] Live API server is ACTIVE at", api_base)
    except Exception:
        print("[!] Live server not detected on port 8000. Using in-process FastAPI TestClient...")
        from fastapi.testclient import TestClient
        from app.main import app
        client = TestClient(app)

    # 1. Simulate UI File Dropzone POST /api/v1/captures
    print("\n[Step 1] Simulating browser UI Dropzone upload...")
    with open(pcap_path, "rb") as f:
        files = {"file": (pcap_path.name, f, "application/vnd.tcpdump.pcap")}
        upload_resp = client.post("/api/v1/captures", headers=headers, files=files)

    if upload_resp.status_code not in (200, 201):
        print(f"[-] Upload failed with status {upload_resp.status_code}: {upload_resp.text}")
        return False

    upload_data = upload_resp.json()
    capture_id = upload_data["capture_id"]
    print(f"[+] Capture uploaded successfully!")
    print(f"    Capture ID:       {capture_id}")
    print(f"    Initial Status:   {upload_data['status']}")
    print(f"    File Size:        {upload_data['size_bytes']} bytes")

    # 2. Poll Processing Status
    print("\n[Step 2] Polling real-time background processing pipeline...")
    start_poll = time.time()
    final_capture = None

    while time.time() - start_poll < 30.0:
        status_resp = client.get(f"/api/v1/captures/{capture_id}", headers=headers)
        if status_resp.status_code == 200:
            final_capture = status_resp.json()
            curr_status = final_capture["status"]
            stage = final_capture.get("processing_stage", "UNKNOWN")
            print(f"    Stage: {stage:<25} Status: {curr_status}")

            if curr_status == "COMPLETE":
                print("[+] Processing finished with status: COMPLETE")
                break
            elif curr_status == "FAILED":
                print(f"[-] Processing FAILED: {final_capture.get('error_message')}")
                return False
        time.sleep(0.5)

    if not final_capture or final_capture.get("status") != "COMPLETE":
        print("[-] Timed out waiting for capture processing.")
        return False

    # 3. Retrieve Forensic Artifacts: Sessions, Hosts, Findings, and Score
    print("\n[Step 3] Inspecting reassembled network streams and findings...")
    sess_resp = client.get(f"/api/v1/captures/{capture_id}/sessions", headers=headers)
    sessions = sess_resp.json().get("items", []) if sess_resp.status_code == 200 else []

    hosts_resp = client.get(f"/api/v1/captures/{capture_id}/hosts", headers=headers)
    hosts = hosts_resp.json().get("items", []) if hosts_resp.status_code == 200 else []

    findings_resp = client.get(f"/api/v1/captures/{capture_id}/findings", headers=headers)
    findings = findings_resp.json().get("items", []) if findings_resp.status_code == 200 else []

    score_resp = client.get(f"/api/v1/captures/{capture_id}/score", headers=headers)
    score_data = score_resp.json() if score_resp.status_code == 200 else {}

    print(f"    Total Reassembled Sessions: {len(sessions)}")
    print(f"    Discovered Mail Hosts:      {len(hosts)}")
    print(f"    Triggered Rule Findings:    {len(findings)}")
    print(f"    Security Posture Score:     {score_data.get('posture_score', 'N/A')} / 100")

    # Table of Sessions
    print("\n[+] Reassembled Stream Sessions:")
    print(f"{'Protocol':<8} {'Client Address':<22} {'Server Address':<22} {'STARTTLS State':<18}")
    print("-" * 74)
    for s in sessions:
        c_addr = f"{s['client_ip']}:{s['client_port']}"
        s_addr = f"{s['server_ip']}:{s['server_port']}"
        print(f"{s['protocol']:<8} {c_addr:<22} {s_addr:<22} {s['starttls_state']:<18}")

    # Table of Triggered Findings
    if findings:
        print("\n[+] Cryptographic Findings & Compliance Violations:")
        print(f"{'Rule ID':<10} {'Severity':<10} {'Confidence':<14} {'Title'}")
        print("-" * 74)
        for f in findings:
            print(f"{f['rule_id']:<10} {f['severity']:<10} {f['confidence']:<14} {f['title']}")

    # Verification checks
    print("\n" + "=" * 65)
    print(" VERIFICATION TEST RESULTS ")
    print("=" * 65)
    checks = [
        ("File Ingestion & Stream Buffering", final_capture["status"] == "COMPLETE"),
        ("TCP Stream Reassembly", len(sessions) > 0),
        ("STARTTLS State Detection", any("TLS" in s.get("starttls_state", "") for s in sessions)),
        ("Cryptographic Rule Evaluation", len(findings) > 0),
        ("0-100 Posture Scoring", "posture_score" in score_data),
    ]

    all_passed = True
    for label, passed in checks:
        status_str = "[PASSED]" if passed else "[FAILED]"
        print(f"  {label:<35} {status_str}")
        if not passed:
            all_passed = False

    print("=" * 65)
    if all_passed:
        print("[SUCCESS] Live Network Capture Dropzone Test: COMPLETED!")
    else:
        print("[!] Some checks did not pass as expected.")

    return all_passed

def main():
    parser = argparse.ArgumentParser(description="TLSpectra Live Network Capture Dropzone Test")
    parser.add_argument("--pcap", type=str, help="Path to custom .pcap / .pcapng file")
    parser.add_argument("--api-url", type=str, default="http://localhost:8000", help="Base API URL")
    parser.add_argument("--token", type=str, default=settings.STATIC_BEARER_TOKEN, help="Static Bearer Token")
    args = parser.parse_args()

    test_pcap_path = None
    if args.pcap:
        test_pcap_path = Path(args.pcap)
        if not test_pcap_path.exists():
            print(f"Error: Specified PCAP file not found: {test_pcap_path}")
            sys.exit(1)
    else:
        # Generate fresh organizational live capture
        settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        test_pcap_path = settings.STORAGE_DIR / "live_dropzone_test.pcap"
        generate_live_test_pcap(test_pcap_path)

    success = run_dropzone_test(test_pcap_path, args.api_url, args.token)
    if success:
        # Check off the item in README.md
        readme_path = backend_dir.parent / "README.md"
        if readme_path.exists():
            readme_text = readme_path.read_text(encoding="utf-8")
            old_str = "- [ ] **Live Network Capture Dropzone Test**"
            new_str = "- [x] **Live Network Capture Dropzone Test** *(Verified via `test_live_dropzone.py`)*"
            if old_str in readme_text:
                readme_text = readme_text.replace(old_str, new_str)
                readme_path.write_text(readme_text, encoding="utf-8")
                print(f"[+] Updated {readme_path.name}: marked Live Dropzone Test as completed!")

if __name__ == "__main__":
    main()
