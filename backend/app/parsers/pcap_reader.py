import struct
import socket
from typing import Generator, Tuple, Optional, Dict, Any

class PCAPReader:
    """
    Pure Python stream-oriented PCAP / PCAPNG reader.
    Complies with memory performance requirements (streaming, no full-file in-memory buffer).
    Extracts Ethernet/IPv4/IPv6/TCP headers and payloads with exact byte offsets.
    """

    PCAP_MAGIC_MICROSECONDS = 0xa1b2c3d4
    PCAP_MAGIC_NANOSECONDS  = 0xa1b23c4d
    PCAP_MAGIC_SWAPPED      = 0xd4c3b2a1
    PCAPNG_MAGIC_SHB        = 0x0a0d0d0a

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file = None
        self.is_pcapng = False
        self.endianness = "<"
        self.ts_factor = 1e-6
        self.link_type = 1  # 1 = Ethernet

    def __enter__(self):
        self.file = open(self.filepath, "rb")
        self._read_header()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.file:
            self.file.close()

    def _read_header(self):
        magic_bytes = self.file.read(4)
        if len(magic_bytes) < 4:
            raise ValueError("File too short to be a valid PCAP/PCAPNG capture")

        magic = struct.unpack("<I", magic_bytes)[0]

        if magic == self.PCAPNG_MAGIC_SHB:
            self.is_pcapng = True
            self._init_pcapng()
        elif magic == self.PCAP_MAGIC_MICROSECONDS:
            self.endianness = "<"
            self.ts_factor = 1e-6
            self._init_pcap()
        elif magic == self.PCAP_MAGIC_NANOSECONDS:
            self.endianness = "<"
            self.ts_factor = 1e-9
            self._init_pcap()
        elif magic == self.PCAP_MAGIC_SWAPPED:
            self.endianness = ">"
            self.ts_factor = 1e-6
            self._init_pcap()
        else:
            raise ValueError(f"Unsupported capture magic bytes: 0x{magic:08x}")

    def _init_pcap(self):
        header = self.file.read(20)
        if len(header) < 20:
            raise ValueError("Corrupt PCAP global header")
        version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            f"{self.endianness}HHIIII", header
        )
        self.link_type = network

    def _init_pcapng(self):
        # Read the rest of the Section Header Block (SHB)
        hdr = self.file.read(8)
        if len(hdr) < 8:
            return
        block_len, bom = struct.unpack("<II", hdr)
        if bom == 0x1a2b3c4d:
            self.endianness = "<"
        else:
            self.endianness = ">"
        # Seek past the rest of SHB
        remaining = block_len - 12
        if remaining > 0:
            self.file.seek(remaining, 1)

    def read_packets(self) -> Generator[Dict[str, Any], None, None]:
        """
        Yields decoded packet dictionaries:
        {
            'packet_num': int,
            'timestamp': float,
            'src_ip': str,
            'src_port': int,
            'dst_ip': str,
            'dst_port': int,
            'protocol': str,  # 'TCP'
            'seq': int,
            'ack': int,
            'flags': dict,
            'payload': bytes,
            'wirelen': int
        }
        """
        if self.is_pcapng:
            yield from self._read_pcapng_packets()
        else:
            yield from self._read_pcap_packets()

    def _read_pcap_packets(self) -> Generator[Dict[str, Any], None, None]:
        pkt_num = 0
        while True:
            hdr_bytes = self.file.read(16)
            if len(hdr_bytes) < 16:
                break
            pkt_num += 1
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
                f"{self.endianness}IIII", hdr_bytes
            )
            timestamp = float(ts_sec) + float(ts_usec) * self.ts_factor
            raw_pkt = self.file.read(incl_len)
            if len(raw_pkt) < incl_len:
                break

            parsed = self._parse_frame(raw_pkt, pkt_num, timestamp, orig_len)
            if parsed:
                yield parsed

    def _read_pcapng_packets(self) -> Generator[Dict[str, Any], None, None]:
        pkt_num = 0
        while True:
            hdr = self.file.read(8)
            if len(hdr) < 8:
                break
            block_type, block_len = struct.unpack(f"{self.endianness}II", hdr)
            if block_len < 12:
                break
            body = self.file.read(block_len - 12)
            trailer = self.file.read(4)  # block total length copy

            # Interface Description Block (IDB) = 0x00000001
            if block_type == 0x00000001:
                if len(body) >= 2:
                    self.link_type = struct.unpack(f"{self.endianness}H", body[:2])[0]
                continue

            # Enhanced Packet Block (EPB) = 0x00000006
            if block_type == 0x00000006:
                if len(body) < 20:
                    continue
                pkt_num += 1
                interface_id, ts_high, ts_low, caplen, origlen = struct.unpack(
                    f"{self.endianness}IIIII", body[:20]
                )
                ts_raw = (ts_high << 32) | ts_low
                # Auto-scale timestamp if nanoseconds (1e9) or microseconds (1e6)
                if ts_raw > 1e16:
                    timestamp = float(ts_raw) * 1e-9
                elif ts_raw > 1e13:
                    timestamp = float(ts_raw) * 1e-6
                elif ts_raw > 1e10:
                    timestamp = float(ts_raw) * 1e-3
                else:
                    timestamp = float(ts_raw) * 1e-6
                raw_pkt = body[20:20 + caplen]
                parsed = self._parse_frame(raw_pkt, pkt_num, timestamp, origlen)
                if parsed:
                    yield parsed

    def _parse_frame(self, raw_pkt: bytes, pkt_num: int, timestamp: float, orig_len: int) -> Optional[Dict[str, Any]]:
        offset = 0
        eth_proto = 0

        # Link layer parsing
        if self.link_type == 0:  # DLT_NULL / Loopback (Windows Npcap / BSD Loopback)
            if len(raw_pkt) < 4:
                return None
            family = struct.unpack(f"{self.endianness}I", raw_pkt[:4])[0]
            offset = 4
            if family == 2:  # AF_INET (IPv4)
                eth_proto = 0x0800
            elif family in (24, 28, 30):  # AF_INET6 (IPv6)
                eth_proto = 0x86DD
            else:
                family_be = struct.unpack("!I", raw_pkt[:4])[0]
                if family_be == 2:
                    eth_proto = 0x0800
                elif family_be in (24, 28, 30):
                    eth_proto = 0x86DD
                else:
                    return None

        elif self.link_type == 1:  # Ethernet (DLT_EN10MB)
            if len(raw_pkt) < 14:
                return None
            eth_proto = struct.unpack("!H", raw_pkt[12:14])[0]
            offset = 14
            # Handle 802.1Q VLAN tagging
            if eth_proto == 0x8100:
                if len(raw_pkt) < 18:
                    return None
                eth_proto = struct.unpack("!H", raw_pkt[16:18])[0]
                offset = 18

        elif self.link_type == 113:  # Linux cooked capture (SLL)
            if len(raw_pkt) < 16:
                return None
            eth_proto = struct.unpack("!H", raw_pkt[14:16])[0]
            offset = 16

        elif self.link_type in (12, 14, 101):  # Raw IP
            if len(raw_pkt) < 20:
                return None
            ver = (raw_pkt[0] >> 4) & 0x0F
            if ver == 4:
                eth_proto = 0x0800
            elif ver == 6:
                eth_proto = 0x86DD
            offset = 0

        else:
            # Fallback: check if packet starts directly with IPv4
            if len(raw_pkt) >= 20 and ((raw_pkt[0] >> 4) & 0x0F) == 4:
                eth_proto = 0x0800
                offset = 0
            else:
                return None

        # IPv4 = 0x0800
        if eth_proto == 0x0800:
            if len(raw_pkt) < offset + 20:
                return None
            ip_hdr = raw_pkt[offset:offset + 20]
            ihl = (ip_hdr[0] & 0x0F) * 4
            proto = ip_hdr[9]
            src_ip = socket.inet_ntoa(ip_hdr[12:16])
            dst_ip = socket.inet_ntoa(ip_hdr[16:20])
            ip_payload_offset = offset + ihl

            # TCP protocol = 6
            if proto == 6:
                return self._parse_tcp(raw_pkt, ip_payload_offset, pkt_num, timestamp, src_ip, dst_ip, orig_len)

        # IPv6 = 0x86DD
        elif eth_proto == 0x86DD:
            if len(raw_pkt) < offset + 40:
                return None
            ip_hdr = raw_pkt[offset:offset + 40]
            nxt_hdr = ip_hdr[6]
            src_ip = socket.inet_ntop(socket.AF_INET6, ip_hdr[8:24])
            dst_ip = socket.inet_ntop(socket.AF_INET6, ip_hdr[24:40])
            ip_payload_offset = offset + 40
            if nxt_hdr == 6:
                return self._parse_tcp(raw_pkt, ip_payload_offset, pkt_num, timestamp, src_ip, dst_ip, orig_len)

        return None

    def _parse_tcp(self, raw_pkt: bytes, offset: int, pkt_num: int, timestamp: float,
                   src_ip: str, dst_ip: str, orig_len: int) -> Optional[Dict[str, Any]]:
        if len(raw_pkt) < offset + 20:
            return None
        tcp_hdr = raw_pkt[offset:offset + 20]
        src_port, dst_port, seq, ack, offset_reserved, flags_byte = struct.unpack("!HHIIBB", tcp_hdr[:14])
        data_offset = ((offset_reserved >> 4) & 0x0F) * 4
        payload = raw_pkt[offset + data_offset:]

        flags = {
            "FIN": bool(flags_byte & 0x01),
            "SYN": bool(flags_byte & 0x02),
            "RST": bool(flags_byte & 0x04),
            "PSH": bool(flags_byte & 0x08),
            "ACK": bool(flags_byte & 0x10),
            "URG": bool(flags_byte & 0x20),
        }

        return {
            "packet_num": pkt_num,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": "TCP",
            "seq": seq,
            "ack": ack,
            "flags": flags,
            "payload": payload,
            "wirelen": orig_len
        }
