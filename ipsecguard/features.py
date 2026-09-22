"""ESP flow feature extractor — THE BRIDGE from real captures to the pipeline.

extract_flow_features(pcap) returns exactly the FLOW_FEATURES schema that
synth.generate() mimics. That identical schema is why a model trained on
synthetic data runs unchanged on real testbed pcaps: swap synth for this,
nothing downstream changes.

Reads ONLY packet metadata (size, time, direction) from ESP packets — never
payload contents. ESP is IP proto 50, or UDP/4500 when NAT-T encapsulated.
"""
import numpy as np
from scapy.all import rdpcap, IP, IPv6, UDP
from scapy.layers.ipsec import ESP
from .schema import FLOW_FEATURES

def _esp_packets(pkts, peer=None):
    out = []
    for p in pkts:
        ipl = p.getlayer(IP) or p.getlayer(IPv6)
        if ipl is None:
            continue
        is_esp = p.haslayer(ESP) or (p.haslayer(UDP) and (p[UDP].dport == 4500 or p[UDP].sport == 4500))
        # raw ESP shows as IP proto 50
        proto = getattr(ipl, "proto", None) or getattr(ipl, "nh", None)
        if is_esp or proto == 50:
            out.append((float(p.time), len(p), ipl.src, ipl.dst))
    return out

def extract_flow_features(pcap_path):
    pkts = rdpcap(pcap_path)
    esp = _esp_packets(pkts)
    if len(esp) < 5:
        raise ValueError(f"Too few ESP packets in {pcap_path} ({len(esp)}). "
                         "Capture on the tunnel interface / peer.")
    times = np.array([t for t, _, _, _ in esp])
    sizes = np.array([s for _, s, _, _ in esp], dtype=float)
    srcs  = [s for _, _, s, _ in esp]
    t0 = times.min(); times = times - t0
    order = np.argsort(times); times = times[order]; sizes = sizes[order]
    iats = np.diff(times) * 1000.0 if len(times) > 1 else np.array([0.0])
    top_src = max(set(srcs), key=srcs.count)
    up = sum(sz for (_, sz, s, _) in esp if s == top_src)
    down = sum(sz for (_, sz, s, _) in esp if s != top_src) or 1
    dur = float(times.max() - times.min()) or 1.0
    return {
        "pkt_size_mean": float(sizes.mean()),
        "pkt_size_std":  float(sizes.std()),
        "pkt_size_p10":  float(np.percentile(sizes, 10)),
        "pkt_size_p50":  float(np.percentile(sizes, 50)),
        "pkt_size_p90":  float(np.percentile(sizes, 90)),
        "iat_mean":      float(iats.mean()),
        "iat_std":       float(iats.std()),
        "burstiness":    float(np.clip(iats.std() / (iats.mean() + 1e-6) / 5.0, 0, 1)),
        "pps":           float(len(esp) / dur),
        "bytes_ratio_updown": float(up / down),
        "small_pkt_frac": float((sizes < 300).mean()),
        "large_pkt_frac": float((sizes > 1000).mean()),
        "flow_dur_s":    dur,
    }
