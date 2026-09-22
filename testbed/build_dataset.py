#!/usr/bin/env python3
"""Turn captured pcaps into the training table the pipeline expects.

This is the JOIN between the testbed and the ML: for every capture it runs the
SAME feature extractor + IKE parser the live analyzer uses, reads ground truth
from the filename, and writes one row. Output dataset.csv has identical columns
to synth.generate(), so training code needs a one-line change:

    # df = generate()                      # synthetic
    df = pd.read_csv("dataset.csv")        # real testbed data
"""
import os, sys, glob, re, hashlib
import pandas as pd
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ipsecguard.features import extract_flow_features
from ipsecguard.parser import parse_ike
from ipsecguard.schema import FLOW_FEATURES

PAT = re.compile(r"ikev(?P<ike>\d)_(?P<mode>tunnel|transport)_(?P<enc>[\w-]+?)_"
                 r"(?P<integ>sha256|sha384|sha1|md5|none)_dh(?P<dh>\d+)_"
                 r"pfs-(?P<pfs>on|off)_(?P<ttype>\w+)\.pcap")

def parse_truth(fn):
    m = PAT.search(os.path.basename(fn))
    if not m: return None
    d = m.groupdict(); d["ike"] = int(d["ike"]); d["dh"] = int(d["dh"]); return d

def main(cap_dir="captures", out="dataset.csv"):
    rows = []
    for pcap in sorted(glob.glob(os.path.join(cap_dir, "*.pcap"))):
        truth = parse_truth(pcap)
        if not truth:
            print("skip (unparseable name):", pcap); continue
        try:
            feats = extract_flow_features(pcap)     # ESP metadata (inferred inputs)
            observed = parse_ike(pcap)              # certain fields (validation)
        except Exception as e:
            print("skip (extract failed):", pcap, e); continue
        profile_key = f"{truth['ike']}|{truth['mode']}|{truth['enc']}|{truth['integ']}|{truth['dh']}|{truth['pfs']}"
        cid = int(hashlib.md5(profile_key.encode()).hexdigest()[:6], 16)
        row = {**feats,
               "config_id": cid,
               "mode": truth["mode"], "ike_version": truth["ike"],
               "enc_algo": truth["enc"], "integrity": truth["integ"],
               "dh_group": truth["dh"], "pfs": truth["pfs"], "ip": "v4",
               "traffic_type": truth["ttype"],
               "observed_enc": observed.get("enc_algo"),
               "observed_dh": observed.get("dh_group")}
        rows.append(row)
        print("ok:", os.path.basename(pcap), "->", truth["ttype"])
    if not rows:
        print("No usable captures. Run sweep.py first."); return
    df = pd.DataFrame(rows)
    cols = ["config_id"] + FLOW_FEATURES + ["mode","ike_version","enc_algo",
            "integrity","dh_group","pfs","ip","traffic_type",
            "observed_enc","observed_dh"]
    df[cols].to_csv(out, index=False)
    print(f"\nWrote {out}: {len(df)} sessions, {df.traffic_type.nunique()} traffic types")

if __name__ == "__main__":
    main()
