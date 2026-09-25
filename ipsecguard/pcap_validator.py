"""PCAP file integrity & format validator for IPsecGuard AI.

Performs robust pre-flight checks on uploaded and local capture files:
- File existence & access permissions
- Empty file (0-byte) detection
- Magic bytes header validation (PCAP microsecond/nanosecond & PCAPNG)
- Packet structure integrity & corruption checks
- Packet count & protocol census (IPv4, IPv6, IKE, ESP)
"""
import os
import struct
from typing import Any, Dict, List, Optional, Tuple, Union

from .errors import (
    ErrorCode,
    PCAPFileNotFoundError,
    EmptyPCAPError,
    CorruptedPCAPError,
    UnsupportedPCAPFormatError,
    InsufficientPacketsError,
)

# Known Magic Numbers for PCAP / PCAPNG
PCAP_MAGIC_NUMBERS = {
    b"\xa1\xb2\xc3\xd4": "pcap (microsecond, big-endian)",
    b"\xd4\xc3\xb2\xa1": "pcap (microsecond, little-endian)",
    b"\xa1\xb2\x3c\x4d": "pcap (nanosecond, big-endian)",
    b"\x4d\x3c\xb2\xa1": "pcap (nanosecond, little-endian)",
    b"\x0a\x0d\x0d\x0a": "pcapng (Section Header Block)",
}


def check_pcap_magic_header(file_path_or_bytes: Union[str, bytes]) -> Tuple[bool, str, Optional[str]]:
    """Checks the first 4 bytes against standard libpcap and pcapng magic numbers."""
    magic = b""
    if isinstance(file_path_or_bytes, bytes):
        magic = file_path_or_bytes[:4]
    elif isinstance(file_path_or_bytes, str):
        if not os.path.exists(file_path_or_bytes):
            return False, "unknown", None
        try:
            with open(file_path_or_bytes, "rb") as f:
                magic = f.read(4)
        except Exception:
            return False, "unreadable", None

    if len(magic) < 4:
        return False, "incomplete", magic.hex() if magic else None

    if magic in PCAP_MAGIC_NUMBERS:
        fmt = "pcapng" if magic == b"\x0a\x0d\x0d\x0a" else "pcap"
        return True, fmt, PCAP_MAGIC_NUMBERS[magic]

    return False, "unsupported", magic.hex()


def _validate_binary_pcap_structure(file_path: str, size: int) -> None:
    """Performs deep binary verification of libpcap global and packet record headers."""
    with open(file_path, "rb") as f:
        data = f.read(min(size, 1048576))  # Inspect up to first 1MB

    if len(data) < 24:
        raise CorruptedPCAPError(file_path, reason="PCAP global header is truncated")

    magic = data[:4]
    endian = ">" if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"

    if magic == b"\x0a\x0d\x0d\x0a":
        # PCAPNG: verify section header block length >= 12
        if len(data) >= 12:
            _type, block_len = struct.unpack(f"{endian}II", data[:8])
            if block_len < 12 or (block_len > size and size < 1048576):
                raise CorruptedPCAPError(file_path, reason="PCAPNG section header block length is invalid")
        return

    # Libpcap global header
    try:
        _m, ver_maj, ver_min, _tz, _sig, snaplen, net = struct.unpack(f"{endian}IHHiIII", data[:24])
    except Exception as e:
        raise CorruptedPCAPError(file_path, reason=f"Unparseable PCAP global header: {e}")

    # Walk packet record headers
    offset = 24
    pkt_idx = 0
    while offset + 16 <= len(data):
        try:
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", data[offset:offset+16])
        except Exception:
            raise CorruptedPCAPError(file_path, reason=f"Malformed packet header at packet #{pkt_idx+1}")

        # Sanity check packet lengths
        if incl_len > 262144 or incl_len > size or (orig_len > 0 and incl_len > orig_len * 10):
            raise CorruptedPCAPError(
                file_path,
                reason=f"Invalid packet length ({incl_len} bytes) in record #{pkt_idx+1}"
            )

        offset += 16 + incl_len
        pkt_idx += 1
        if pkt_idx >= 100:  # Validate first 100 packets
            break


def validate_pcap_file(
    file_path: str,
    min_packets: int = 1,
    require_ipsec: bool = False
) -> Dict[str, Any]:
    """Performs end-to-end validation of an IPv4/IPv6 PCAP file before analysis.

    Raises specific PCAPValidationError subclasses on failure or returns a
    census dictionary describing packet contents and IP version on success.
    """
    # 1. Existence and path checks
    if not isinstance(file_path, str) or not file_path.strip():
        raise PCAPFileNotFoundError(str(file_path))

    if not os.path.exists(file_path):
        raise PCAPFileNotFoundError(file_path)

    if os.path.isdir(file_path):
        raise CorruptedPCAPError(file_path, reason="Path points to a directory, not a capture file")

    # 2. File size check
    try:
        size = os.path.getsize(file_path)
    except Exception as e:
        raise CorruptedPCAPError(file_path, reason=f"Cannot read file metadata: {e}")

    if size == 0:
        raise EmptyPCAPError(file_path)

    if size < 24:  # Minimum PCAP global header is 24 bytes
        raise CorruptedPCAPError(file_path, reason=f"File too small to contain a valid PCAP header ({size} bytes)")

    # 3. Magic Number validation
    is_valid_magic, fmt, desc = check_pcap_magic_header(file_path)
    if not is_valid_magic:
        raise UnsupportedPCAPFormatError(file_path, detected_header=desc)

    # 4. Binary structural validation
    _validate_binary_pcap_structure(file_path, size)

    # 5. Scapy Packet Dissection & Integrity Check
    try:
        from scapy.all import rdpcap, IP, IPv6, UDP
        from scapy.layers.ipsec import ESP
        packets = rdpcap(file_path)
    except Exception as e:
        raise CorruptedPCAPError(file_path, reason=f"Scapy packet parser failed: {str(e)}")

    total_packets = len(packets)
    if total_packets == 0:
        if size > 24:
            raise CorruptedPCAPError(file_path, reason="PCAP contains invalid or unparseable packet headers")
        raise InsufficientPacketsError(
            path=file_path,
            packet_count=0,
            min_required=min_packets,
            traffic_type="packets"
        )

    if total_packets < min_packets:
        raise InsufficientPacketsError(
            path=file_path,
            packet_count=total_packets,
            min_required=min_packets,
            traffic_type="packets"
        )

    # 6. Protocol and IP Version census
    ipv4_count = 0
    ipv6_count = 0
    ike_count = 0
    esp_count = 0
    src_ips = set()
    dst_ips = set()
    warnings = []

    for p in packets:
        is_v4 = p.haslayer(IP)
        is_v6 = p.haslayer(IPv6)

        if is_v4:
            ipv4_count += 1
            ip_layer = p[IP]
            src_ips.add(str(ip_layer.src))
            dst_ips.add(str(ip_layer.dst))
            proto = ip_layer.proto
            if p.haslayer(ESP) or proto == 50:
                esp_count += 1
            elif p.haslayer(UDP) and (p[UDP].dport == 4500 or p[UDP].sport == 4500):
                esp_count += 1

        elif is_v6:
            ipv6_count += 1
            ip_layer = p[IPv6]
            src_ips.add(str(ip_layer.src))
            dst_ips.add(str(ip_layer.dst))
            nh = ip_layer.nh
            if p.haslayer(ESP) or nh == 50:
                esp_count += 1
            elif p.haslayer(UDP) and (p[UDP].dport == 4500 or p[UDP].sport == 4500):
                esp_count += 1

        # Check IKE
        if p.haslayer(UDP):
            udp = p[UDP]
            if udp.dport in (500, 4500) or udp.sport in (500, 4500):
                ike_count += 1

    total_ip = ipv4_count + ipv6_count
    if ipv6_count > 0 and ipv4_count == 0:
        ip_version = "v6"
    elif ipv4_count > 0 and ipv6_count == 0:
        ip_version = "v4"
    elif ipv4_count > 0 and ipv6_count > 0:
        ip_version = "dual-stack"
    else:
        ip_version = "none"

    has_ipsec = (ike_count > 0 or esp_count > 0)
    if total_ip == 0:
        warnings.append("No IPv4 or IPv6 packets found in capture.")

    if not has_ipsec:
        warnings.append("No IPsec (IKE or ESP) packets detected in capture.")
        if require_ipsec:
            raise InsufficientPacketsError(
                path=file_path,
                packet_count=0,
                min_required=1,
                traffic_type="IPsec (IKE/ESP) packets"
            )

    return {
        "is_valid": True,
        "path": file_path,
        "file_size": size,
        "format": fmt,
        "format_description": desc,
        "ip_version": ip_version,
        "total_packets": total_packets,
        "ip_packets": total_ip,
        "ipv4_packets": ipv4_count,
        "ipv6_packets": ipv6_count,
        "ike_packets": ike_count,
        "esp_packets": esp_count,
        "has_ipsec_traffic": has_ipsec,
        "endpoints": {
            "sources": sorted(list(src_ips)),
            "destinations": sorted(list(dst_ips)),
            "primary_src": sorted(list(src_ips))[0] if src_ips else None,
            "primary_dst": sorted(list(dst_ips))[0] if dst_ips else None,
        },
        "warnings": warnings,
    }
