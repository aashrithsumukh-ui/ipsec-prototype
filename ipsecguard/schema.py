"""Shared vocabulary: the config space and the ESP flow feature list.

This is the single source of truth for what a 'session' looks like. The real
strongSwan testbed produces exactly these fields per capture; the synthetic
generator mimics them so the ML trains without live pcaps.
"""

# ---- Ground-truth configuration space (what the testbed sweeps) ----
MODES        = ["tunnel", "transport"]
IKE_VERSIONS = [1, 2]
ENC_ALGOS    = ["aes128-gcm", "aes256-gcm", "aes128-cbc", "aes256-cbc", "3des-cbc"]
INTEGRITY    = ["sha256", "sha384", "sha1", "md5", "none"]   # 'none' only valid with GCM
DH_GROUPS    = [2, 5, 14, 19, 20, 21]                        # 2/5 legacy, 14 MODP, 19-21 ECP
PFS          = ["on", "off"]
IP_VERSIONS  = ["v4", "v6"]
TRAFFIC_TYPES = ["voip", "web", "video", "email", "icmp", "bulk", "mixed"]

# ---- ESP flow features fed to the ML layer ----
# These are computable from packet metadata alone — never from payload contents.
FLOW_FEATURES = [
    "pkt_size_mean", "pkt_size_std", "pkt_size_p10", "pkt_size_p50", "pkt_size_p90",
    "iat_mean", "iat_std", "burstiness",
    "pps", "bytes_ratio_updown", "small_pkt_frac", "large_pkt_frac", "flow_dur_s",
]
