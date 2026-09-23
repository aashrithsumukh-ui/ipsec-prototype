"""Synthetic dataset generator — a stand-in for the strongSwan testbed.

WHY THIS EXISTS: the real system captures pcaps from a strongSwan/Docker lab.
That lab can't run in every environment, so this module produces labelled ESP
flow-feature vectors with the SAME schema the real extractor emits. Swap this
out for features.extract_from_pcap() once you have real captures — nothing
downstream changes.

Each traffic type has a characteristic 'shape' (packet size / timing / direction),
with deliberate overlap so the classification problem is real, not trivial.
"""
import numpy as np
import pandas as pd
from .schema import (FLOW_FEATURES, MODES, IKE_VERSIONS, ENC_ALGOS, INTEGRITY,
                     DH_GROUPS, PFS, IP_VERSIONS, TRAFFIC_TYPES)

# (size_mean, size_std, iat_mean_ms, iat_std_ms, pps, updown_ratio, burstiness)
_PROFILES = {
    "voip":  (210,  35,  20,   4,   50, 1.0, 0.15),   # small, very regular, symmetric
    "web":   (760, 480,  90,  140,  14, 0.18, 0.85),   # bursty, mixed, download-heavy
    "video": (1350, 210, 12,   9,   90, 0.08, 0.45),   # big, sustained, download-heavy
    "email": (540, 360,  60,  110,   9, 0.6, 0.70),    # short bursts, medium
    "icmp":  (98,   12, 1000, 60,    1, 1.0, 0.10),    # tiny, slow, regular
    "bulk":  (1440, 60,   6,   3,  120, 0.02, 0.30),   # max size, one direction
    "mixed": (720, 520,  45,  120,  40, 0.35, 0.75),   # blend
}

_CONFUSERS = {"voip": "icmp", "icmp": "voip", "web": "email", "email": "web",
              "video": "bulk", "bulk": "video", "mixed": "web"}

def _one_flow(rng, ttype):
    m, s, iat, iat_s, pps, updown, burst = _PROFILES[ttype]
    m     = max(64, rng.normal(m, m * 0.22))
    s     = max(5,  rng.normal(s, s * 0.30))
    sizes = rng.normal(m, s, 400).clip(64, 1500)
    iat_mean = max(0.5, rng.normal(iat, iat * 0.35))
    iat_std  = max(0.1, rng.normal(iat_s, iat_s * 0.2 + 0.1))
    dur = max(1.0, rng.normal(30, 8))
    return {
        "pkt_size_mean": sizes.mean(),
        "pkt_size_std":  sizes.std(),
        "pkt_size_p10":  np.percentile(sizes, 10),
        "pkt_size_p50":  np.percentile(sizes, 50),
        "pkt_size_p90":  np.percentile(sizes, 90),
        "iat_mean":      iat_mean,
        "iat_std":       iat_std,
        "burstiness":    float(np.clip(rng.normal(burst, 0.20), 0, 1)),
        "pps":           max(0.2, rng.normal(pps, pps * 0.30)),
        "bytes_ratio_updown": max(0.01, rng.normal(updown, updown * 0.15 + 0.02)),
        "small_pkt_frac": float((sizes < 300).mean()),
        "large_pkt_frac": float((sizes > 1000).mean()),
        "flow_dur_s":    dur,
        "pkt_count":     max(5, round(dur * pps)),
        "iat_cv":        float(iat_std / (iat_mean + 1e-6)),
        "size_cv":       float(sizes.std() / (sizes.mean() + 1e-6)),
        "iat_p10":       max(0.0, iat_mean - 1.2816 * iat_std),
        "iat_p90":       iat_mean + 1.2816 * iat_std,
    }

def generate(n_configs=140, sessions_per_config=4, seed=7):
    """Return a DataFrame: one row per session, with features + ground-truth config."""
    rng = np.random.default_rng(seed)
    rows = []
    for cfg_id in range(n_configs):
        cfg = {
            "config_id": cfg_id,
            "mode":     rng.choice(MODES),
            "ike_version": int(rng.choice(IKE_VERSIONS)),
            "enc_algo": rng.choice(ENC_ALGOS, p=[0.28, 0.30, 0.15, 0.15, 0.12]),
            "dh_group": int(rng.choice(DH_GROUPS, p=[0.08, 0.08, 0.30, 0.22, 0.18, 0.14])),
            "pfs":      rng.choice(PFS, p=[0.62, 0.38]),
            "ip":       rng.choice(IP_VERSIONS),
        }
        # integrity is coupled to cipher: GCM is AEAD -> 'none'
        if "gcm" in cfg["enc_algo"]:
            cfg["integrity"] = "none"
        else:
            cfg["integrity"] = rng.choice(["sha256", "sha384", "sha1", "md5"],
                                          p=[0.45, 0.2, 0.22, 0.13])
        for _ in range(sessions_per_config):
            ttype = rng.choice(TRAFFIC_TYPES)
            # ~15% of sessions: real capture ambiguity — label stays, but the
            # flow genuinely resembles a neighbouring type (irreducible error).
            shape_type = _CONFUSERS[ttype] if (rng.random() < 0.15) else ttype
            row = _one_flow(rng, shape_type)
            row.update(cfg)
            row["traffic_type"] = ttype
            rows.append(row)
    df = pd.DataFrame(rows)
    return df[["config_id"] + FLOW_FEATURES +
              ["mode", "ike_version", "enc_algo", "integrity", "dh_group",
               "pfs", "ip", "traffic_type"]]

if __name__ == "__main__":
    d = generate()
    print(d.shape)
    print(d["traffic_type"].value_counts().to_dict())
