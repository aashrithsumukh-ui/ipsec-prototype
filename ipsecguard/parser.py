"""IKE handshake parser — the OBSERVED layer.

Reads genuinely-plaintext fields from IKE_SA_INIT (IKEv2) / Main Mode msgs 1-2
(IKEv1): IKE version, the IKE SA cipher/integrity/PRF, and the DH group. These
are certain — no inference.

IMPORTANT protocol boundary: the ESP data cipher, tunnel-vs-transport mode, and
auth method are negotiated inside ENCRYPTED IKE_AUTH / Quick Mode. They are NOT
observable here — they belong to the inferred layer. Do not add them.

Prefers tshark (rich ISAKMP dissector; present in the testbed image). Falls back
to scapy's ISAKMP layer for IKEv1 when tshark is absent.
"""
import json, shutil, subprocess

_TRANSFORM = {  # tshark isakmp transform type -> our field
    "1": "enc_algo", "3": "integrity", "4": "dh_group",
}

def parse_ike(pcap_path):
    if shutil.which("tshark"):
        try:
            return _via_tshark(pcap_path)
        except Exception:
            pass
    return _via_scapy(pcap_path)

def _via_tshark(pcap_path):
    # Pull IKE version + first proposal's transforms from the INIT exchange.
    cmd = ["tshark", "-r", pcap_path, "-Y",
           "isakmp && (isakmp.exchangetype==34 || isakmp.exchangetype==2)",
           "-T", "json"]
    raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    data = json.loads(raw or "[]")
    out = {"ike_version": None, "enc_algo": None, "integrity": None, "dh_group": None,
           "_source": "tshark"}
    for pkt in data:
        layers = pkt.get("_source", {}).get("layers", {})
        isa = layers.get("isakmp")
        if not isa:
            continue
        ver = isa.get("isakmp.version")
        out["ike_version"] = 2 if (ver and ver.startswith("2")) else 1
        # transforms carry the negotiated algorithms in cleartext
        blob = json.dumps(isa).lower()
        for name, tag in [("aes-gcm", "aes-gcm"), ("aes-cbc", "aes-cbc"),
                          ("3des", "3des-cbc")]:
            if name in blob:
                out["enc_algo"] = tag; break
        for name in ["sha2-256", "sha256", "sha1", "md5"]:
            if name in blob:
                out["integrity"] = name.replace("sha2-", "sha"); break
        for g in ["group 21", "group 20", "group 19", "group 14", "group 5", "group 2"]:
            if g in blob:
                out["dh_group"] = int(g.split()[-1]); break
        break
    return out

def _via_scapy(pcap_path):
    from scapy.all import rdpcap
    try:
        from scapy.layers.isakmp import ISAKMP
    except Exception:
        return {"ike_version": None, "enc_algo": None, "integrity": None,
                "dh_group": None, "_source": "unavailable"}
    pkts = rdpcap(pcap_path)
    out = {"ike_version": None, "enc_algo": None, "integrity": None,
           "dh_group": None, "_source": "scapy-isakmp"}
    for p in pkts:
        if p.haslayer(ISAKMP):
            out["ike_version"] = 1  # scapy ISAKMP layer is IKEv1
            break
    return out
