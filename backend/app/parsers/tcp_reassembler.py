from typing import Dict, List, Tuple, Any, Optional
from datetime import datetime, timezone

EMAIL_PORTS = {25, 465, 587, 110, 995, 143, 993}

class TCPStream:
    """
    Bidirectional TCP flow tracking and reassembly.
    """
    def __init__(self, session_key: Tuple[str, int, str, int], first_packet: Dict[str, Any]):
        self.session_key = session_key
        # Canonical client/server assignment:
        # If one port is a known email port, that is the server.
        src_ip, src_port, dst_ip, dst_port = session_key
        if dst_port in EMAIL_PORTS:
            self.client_ip = src_ip
            self.client_port = src_port
            self.server_ip = dst_ip
            self.server_port = dst_port
        elif src_port in EMAIL_PORTS:
            self.client_ip = dst_ip
            self.client_port = dst_port
            self.server_ip = src_ip
            self.server_port = src_port
        else:
            # Fallback based on ephemeral port heuristics
            if src_port > dst_port:
                self.client_ip = src_ip
                self.client_port = src_port
                self.server_ip = dst_ip
                self.server_port = dst_port
            else:
                self.client_ip = dst_ip
                self.client_port = dst_port
                self.server_ip = src_ip
                self.server_port = src_port

        self.start_time = first_packet["timestamp"]
        self.end_time = first_packet["timestamp"]
        self.packet_count = 0
        self.byte_count = 0
        self.packet_numbers: List[int] = []

        # Directional buffers: chunks stored as (seq, payload, packet_num, timestamp)
        self.c2s_chunks: List[Tuple[int, bytes, int, float]] = []
        self.s2c_chunks: List[Tuple[int, bytes, int, float]] = []
        
        # Interleaved chronological record of exchanges
        self.chronological_payloads: List[Dict[str, Any]] = []

    def add_packet(self, pkt: Dict[str, Any]):
        self.packet_count += 1
        self.byte_count += pkt["wirelen"]
        self.end_time = pkt["timestamp"]
        self.packet_numbers.append(pkt["packet_num"])

        payload = pkt["payload"]
        if not payload:
            return

        is_c2s = (pkt["src_ip"] == self.client_ip and pkt["src_port"] == self.client_port)
        chunk = (pkt["seq"], payload, pkt["packet_num"], pkt["timestamp"])

        if is_c2s:
            self.c2s_chunks.append(chunk)
            self.chronological_payloads.append({
                "direction": "C2S",
                "seq": pkt["seq"],
                "data": payload,
                "packet_num": pkt["packet_num"],
                "timestamp": pkt["timestamp"]
            })
        else:
            self.s2c_chunks.append(chunk)
            self.chronological_payloads.append({
                "direction": "S2C",
                "seq": pkt["seq"],
                "data": payload,
                "packet_num": pkt["packet_num"],
                "timestamp": pkt["timestamp"]
            })

    def get_c2s_stream(self) -> bytes:
        # Sort by sequence number and reassemble
        sorted_chunks = sorted(self.c2s_chunks, key=lambda x: x[0])
        return b"".join(c[1] for c in sorted_chunks)

    def get_s2c_stream(self) -> bytes:
        sorted_chunks = sorted(self.s2c_chunks, key=lambda x: x[0])
        return b"".join(c[1] for c in sorted_chunks)


class TCPReassembler:
    """
    Groups packets by flow and tracks stream reassembly.
    """
    def __init__(self):
        self.streams: Dict[Tuple[str, int, str, int], TCPStream] = {}

    def _normalize_key(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> Tuple[str, int, str, int]:
        if (src_ip, src_port) < (dst_ip, dst_port):
            return (src_ip, src_port, dst_ip, dst_port)
        return (dst_ip, dst_port, src_ip, src_port)

    def process_packet(self, pkt: Dict[str, Any]):
        key = self._normalize_key(pkt["src_ip"], pkt["src_port"], pkt["dst_ip"], pkt["dst_port"])
        if key not in self.streams:
            self.streams[key] = TCPStream(key, pkt)
        self.streams[key].add_packet(pkt)

    def get_completed_streams(self) -> List[TCPStream]:
        return list(self.streams.values())
