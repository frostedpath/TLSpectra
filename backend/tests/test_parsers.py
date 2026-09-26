import os
import pytest
from pathlib import Path
from app.parsers.pcap_reader import PCAPReader
from app.parsers.tcp_reassembler import TCPReassembler

CORPUS_DIR = Path(__file__).resolve().parent.parent.parent / "corpus"
PCAP_DIR = CORPUS_DIR / "pcaps"

def test_pcap_reader_reads_packets():
    pcap_file = PCAP_DIR / "SECU-01.pcap"
    assert pcap_file.exists(), f"Missing corpus file {pcap_file}"

    packets = []
    with PCAPReader(str(pcap_file)) as reader:
        for pkt in reader.read_packets():
            packets.append(pkt)

    assert len(packets) >= 5
    assert packets[0]["protocol"] == "TCP"
    assert packets[0]["src_port"] > 0
    assert packets[0]["dst_port"] > 0

def test_tcp_reassembler_creates_streams():
    pcap_file = PCAP_DIR / "SECU-01.pcap"
    reassembler = TCPReassembler()

    with PCAPReader(str(pcap_file)) as reader:
        for pkt in reader.read_packets():
            reassembler.process_packet(pkt)

    streams = reassembler.get_completed_streams()
    assert len(streams) == 1
    stream = streams[0]
    assert stream.client_ip.startswith("192.168.1.")
    assert stream.server_ip == "10.0.0.25"
    assert stream.server_port == 587
    assert b"220" in stream.get_s2c_stream()
    assert b"STARTTLS" in stream.get_c2s_stream()
