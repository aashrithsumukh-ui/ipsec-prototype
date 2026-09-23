"""End-to-end downgrade demo (no tshark, no live MITM)."""
import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.insert(0, os.path.dirname(__file__))
from downgrade_pcap import main as downgrade, first_proposal_cipher
from ipsecguard.scoring import assess

def summarize(pcap, label):
    cipher, strong = first_proposal_cipher(pcap)
    cipher = cipher or "unreadable"
    enc_map = {"AES-GCM-16":"aes256-gcm","AES-GCM-12":"aes256-gcm","AES-GCM-8":"aes256-gcm",
               "AES-CBC":"aes256-cbc","3DES":"3des-cbc"}
    observed = {"enc_algo": enc_map.get(cipher, "unknown"),
                "integrity": "none" if "GCM" in cipher else ("md5" if cipher=="3DES" else "sha256"),
                "dh_group": 20 if strong else 2, "ike_version": 2}
    inferred = {"traffic_type":"unknown","traffic_conf":0.0,"pfs":"on","mode":"tunnel","anomaly":False}
    r = assess(observed, inferred)
    print(f"\n=== {label} ===")
    print(f"  negotiated cipher : {cipher}  ({'STRONG' if strong else 'WEAK'})")
    print(f"  risk score        : {r['risk_score']}/100")
    print(f"  findings          : {len(r['findings'])}")
    for f in r["findings"]:
        print(f"     - [{f['severity']}] {f['title']}")
    return cipher, r["risk_score"]

def main(clean):
    tampered = clean.replace(".pcap","_DOWNGRADED.pcap")
    print("Applying downgrade attack to the captured IKE_SA_INIT handshake...")
    n = downgrade(clean, tampered)
    if n == 0:
        print("No strong proposal to strip — use a *gcm* capture with a multi-proposal handshake.")
        return
    c0,s0 = summarize(clean, "CLEAN (as captured)")
    c1,s1 = summarize(tampered, "AFTER DOWNGRADE ATTACK")
    print("\n" + "="*50)
    print(f"Attacker forced {c0} -> {c1};  risk {s0} -> {s1}.")
    print(f"Tampered capture: {tampered}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python3 demo_downgrade.py <clean_strong.pcap>"); sys.exit(1)
    main(sys.argv[1])
