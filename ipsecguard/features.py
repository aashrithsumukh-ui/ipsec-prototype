"""ESP flow feature extractor — THE BRIDGE from real captures to the pipeline.

Reads packet metadata (size, time, direction, IP version) from IPv4 & IPv6 ESP packets —
never payload contents. ESP is IP proto 50 (IPv4) or Next Header 50 (IPv6),
or UDP/4500 when NAT-T encapsulated.
"""
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
from scapy.all import rdpcap, IP, IPv6, UDP
from scapy.layers.ipsec import ESP
from .schema import FLOW_FEATURES
from .errors import InsufficientPacketsError, FeatureExtractionError


def _esp_packets(pkts, peer=None):
    """Filters ESP and NAT-T encapsulated packets across IPv4 and IPv6."""
    out = []
    for p in pkts:
        ipl = p.getlayer(IP) or p.getlayer(IPv6)
        if ipl is None:
            continue
        is_esp = p.haslayer(ESP) or (p.haslayer(UDP) and (p[UDP].dport == 4500 or p[UDP].sport == 4500))
        # raw ESP shows as IP proto 50 or IPv6 nh 50
        proto = getattr(ipl, "proto", None) or getattr(ipl, "nh", None)
        if is_esp or proto == 50:
            ip_ver = "v6" if p.haslayer(IPv6) else "v4"
            out.append((float(p.time), len(p), str(ipl.src), str(ipl.dst), ip_ver))
    return out


def extract_flow_features(pcap_path_or_packets: Union[str, list, Any], min_esp: int = 1) -> Dict[str, float]:
    """Extracts standard 18-dimensional ESP flow feature vector safely from IPv4 or IPv6 captures."""
    try:
        if isinstance(pcap_path_or_packets, str):
            pkts = rdpcap(pcap_path_or_packets)
        elif isinstance(pcap_path_or_packets, (list, tuple)):
            pkts = list(pcap_path_or_packets)
        else:
            pkts = [pcap_path_or_packets]
    except Exception as e:
        raise FeatureExtractionError(f"Failed to load packet stream for feature extraction: {e}")

    esp = _esp_packets(pkts)
    if len(esp) < min_esp:
        path_label = str(pcap_path_or_packets) if isinstance(pcap_path_or_packets, str) else "<packet_list>"
        raise InsufficientPacketsError(
            path=path_label,
            packet_count=len(esp),
            min_required=min_esp,
            traffic_type="ESP packets"
        )

    times = np.array([t for t, _, _, _, _ in esp])
    sizes = np.array([s for _, s, _, _, _ in esp], dtype=float)
    srcs  = [s for _, _, s, _, _ in esp]
    t0 = times.min(); times = times - t0
    order = np.argsort(times); times = times[order]; sizes = sizes[order]
    iats = np.diff(times) * 1000.0 if len(times) > 1 else np.array([0.0])
    top_src = max(set(srcs), key=srcs.count) if srcs else ""
    up = sum(sz for (_, sz, s, _, _) in esp if s == top_src)
    down = sum(sz for (_, sz, s, _, _) in esp if s != top_src) or 1
    dur = float(times.max() - times.min()) if len(times) > 0 else 0.0
    if dur <= 0.0:
        dur = 1.0

    return {
        "pkt_size_mean": float(sizes.mean()) if len(sizes) > 0 else 0.0,
        "pkt_size_std":  float(sizes.std()) if len(sizes) > 0 else 0.0,
        "pkt_size_p10":  float(np.percentile(sizes, 10)) if len(sizes) > 0 else 0.0,
        "pkt_size_p50":  float(np.percentile(sizes, 50)) if len(sizes) > 0 else 0.0,
        "pkt_size_p90":  float(np.percentile(sizes, 90)) if len(sizes) > 0 else 0.0,
        "iat_mean":      float(iats.mean()) if len(iats) > 0 else 0.0,
        "iat_std":       float(iats.std()) if len(iats) > 0 else 0.0,
        "burstiness":    float(np.clip(iats.std() / (iats.mean() + 1e-6) / 5.0, 0, 1)) if len(iats) > 0 else 0.0,
        "pps":           float(len(esp) / dur),
        "bytes_ratio_updown": float(up / down),
        "small_pkt_frac": float((sizes < 300).mean()) if len(sizes) > 0 else 0.0,
        "large_pkt_frac": float((sizes > 1000).mean()) if len(sizes) > 0 else 0.0,
        "flow_dur_s":    dur,
        "pkt_count":     float(len(esp)),
        "iat_cv":        float(iats.std() / (iats.mean() + 1e-6)) if len(iats) > 0 else 0.0,
        "size_cv":       float(sizes.std() / (sizes.mean() + 1e-6)) if len(sizes) > 0 else 0.0,
        "iat_p10":       float(np.percentile(iats, 10)) if len(iats) > 1 else 0.0,
        "iat_p90":       float(np.percentile(iats, 90)) if len(iats) > 1 else 0.0,
    }


def extract_ip_flow_metadata(pcap_path_or_packets: Union[str, list, Any]) -> Dict[str, Any]:
    """Extracts IPv4/IPv6 session-level network and endpoint metadata."""
    try:
        if isinstance(pcap_path_or_packets, str):
            pkts = rdpcap(pcap_path_or_packets)
        elif isinstance(pcap_path_or_packets, (list, tuple)):
            pkts = list(pcap_path_or_packets)
        else:
            pkts = [pcap_path_or_packets]
    except Exception as e:
        raise FeatureExtractionError(f"Failed to load packet stream for metadata extraction: {e}")

    v4_count = 0
    v6_count = 0
    total_bytes = 0
    src_v4 = set()
    dst_v4 = set()
    src_v6 = set()
    dst_v6 = set()
    times = []

    for p in pkts:
        total_bytes += len(p)
        times.append(float(p.time))
        if p.haslayer(IP):
            v4_count += 1
            src_v4.add(str(p[IP].src))
            dst_v4.add(str(p[IP].dst))
        elif p.haslayer(IPv6):
            v6_count += 1
            src_v6.add(str(p[IPv6].src))
            dst_v6.add(str(p[IPv6].dst))

    dur = (max(times) - min(times)) if times else 0.0

    if v6_count > 0 and v4_count == 0:
        ip_version = "v6"
    elif v4_count > 0 and v6_count == 0:
        ip_version = "v4"
    elif v4_count > 0 and v6_count > 0:
        ip_version = "dual-stack"
    else:
        ip_version = "none"

    return {
        "ip_version": ip_version,
        "total_packets": len(pkts),
        "total_bytes": total_bytes,
        "ipv4_packets": v4_count,
        "ipv6_packets": v6_count,
        "flow_duration_s": dur,
        "ipv6_endpoints": {
            "sources": sorted(list(src_v6)),
            "destinations": sorted(list(dst_v6)),
        } if v6_count > 0 else None,
        "ipv4_endpoints": {
            "sources": sorted(list(src_v4)),
            "destinations": sorted(list(dst_v4)),
        } if v4_count > 0 else None,
    }
