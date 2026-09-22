# IPsecGuard AI — Prototype

AI-assisted IPsec VPN security assessment. Reads a capture, reports how secure
the deployment is, and tags every finding by how it was derived:

- **Observed** — read from plaintext `IKE_SA_INIT` (certain)
- **Inferred** — from encrypted-traffic metadata via ML (confidence %)

The system never decrypts payloads.

## Layout
```
ipsecguard/        core pipeline (data-source agnostic)
  schema.py          config space + ESP flow feature list (source of truth)
  synth.py           synthetic testbed stand-in (labelled flow features)
  features.py        REAL pcap -> ESP flow features   <- bridge from testbed
  parser.py          IKE_SA_INIT -> observed fields (tshark, scapy fallback)
  classifier.py      XGBoost traffic-type model (held-out config split)
  anomaly.py         Isolation Forest (trained on clean sessions only)
  scoring.py         NIST SP 800-77 rubric -> score, subscores, threat matrix
  findings.py        confidence-tagged finding model
  report.py          executive + technical reports
  analyze.py         one real pcap -> full tagged assessment
run_demo.py        end-to-end on synthetic data (proves the core)
testbed/           strongSwan + Docker lab that produces real captures
```

## Quick start (no VPN needed) — prove the core
```
pip install -r requirements.txt
python3 run_demo.py            # trains, scores a weak + strong session, writes outputs/analysis.json
```

## Real data — strongSwan + Docker testbed
Requires Docker + a Linux host (IPsec uses the host kernel's XFRM).

```
cd testbed
cp gateway/ipsec.secrets captures/         # PSK available to containers
docker compose up -d --build               # two gateways: moon (.10), sun (.20)
python3 sweep.py                           # subset sweep; --full for everything
                                           #   -> captures/*.pcap (named by ground truth)
python3 build_dataset.py                   # pcaps -> dataset.csv (same schema as synth)
python3 train_from_dataset.py             # trains the SAME models on real data
```

### How the testbed connects to the pipeline
`sweep.py` writes an `ipsec.conf` per configuration (mode / cipher / DH group /
PFS all map to strongSwan proposal fields), brings the tunnel up, runs one
labelled traffic profile through it (iperf3 UDP shapes VoIP/video, TCP for
bulk/web/email, ping for ICMP), and captures IKE+ESP to a pcap named with the
ground truth.

`build_dataset.py` then runs the pipeline's own `features.extract_flow_features`
and `parser.parse_ike` over each pcap and reads the label from the filename,
emitting `dataset.csv` with the exact columns `synth.generate()` produces. So
going from synthetic to real is a one-line change (see `train_from_dataset.py`).

To assess a single arbitrary capture with trained models:
```python
from ipsecguard.analyze import analyze_pcap
result = analyze_pcap("some.pcap", clf, anom, pfs_hint="on", mode_hint="tunnel")
print(result["risk_score"], result["exec_report"])
```

## Honest scope (know these before a judge asks)
- Only `IKE_SA_INIT` is plaintext. The ESP data cipher, tunnel/transport mode,
  and auth method are negotiated inside encrypted `IKE_AUTH` — so they are
  **inferred**, not observed. The parser deliberately does not claim them.
- One-traffic-type-per-tunnel is a lab simplification; the sweep includes a
  `mixed` profile because real tunnels multiplex. Treat single-label output as
  a composition estimate in production.
- Key lifetime and anti-replay window are largely local config, not on the wire;
  assess them from a config collector, not traffic alone.
