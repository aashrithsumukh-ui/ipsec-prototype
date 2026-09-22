#!/usr/bin/env python3
"""Config-sweep orchestrator (mid-size default)."""
import argparse, itertools, subprocess, time, os

MOON, SUN = "ipg_moon", "ipg_sun"
DH_NAME = {2:"modp1024",5:"modp1536",14:"modp2048",19:"ecp256",20:"ecp384",21:"ecp521"}

TRAFFIC = {
    "icmp":  "ping -c 300 -i 0.02 10.10.0.20",
    "bulk":  "iperf3 -c 10.10.0.20 -t 12",
    "voip":  "iperf3 -c 10.10.0.20 -u -l 200  -b 80k -t 12",
    "video": "iperf3 -c 10.10.0.20 -u -l 1300 -b 4m  -t 12",
    "email": "bash -c 'for i in 1 2 3 4; do iperf3 -c 10.10.0.20 -n 2M; sleep 1; done'",
    "web":   "bash -c 'for i in $(seq 1 20); do iperf3 -c 10.10.0.20 -n 300K; sleep 0.3; done'",
    "mixed": "bash -c 'iperf3 -c 10.10.0.20 -u -l 200 -b 80k -t 12 & iperf3 -c 10.10.0.20 -t 12; wait'",
}

SECURITY_PROFILES = [
    (2, "tunnel",    "aes256-gcm", "none",   20, "on"),
    (2, "tunnel",    "aes256-gcm", "none",   19, "on"),
    (2, "tunnel",    "aes128-gcm", "none",   19, "on"),
    (2, "tunnel",    "aes256-cbc", "sha256", 14, "on"),
    (2, "tunnel",    "aes128-cbc", "sha256", 14, "off"),
    (2, "transport", "aes256-cbc", "sha1",   14, "off"),
    (1, "tunnel",    "3des-cbc",   "md5",    5,  "off"),
    (1, "transport", "3des-cbc",   "md5",    2,  "off"),
]

def dx(container, cmd, bg=False, check=True):
    full = ["docker","exec"] + (["-d"] if bg else []) + [container,"bash","-lc",cmd]
    return subprocess.run(full, capture_output=not bg, text=True, check=check)

def proposals(enc, integ, dh, pfs):
    g = DH_NAME[dh]
    if "gcm" in enc:
        bits = "128" if "128" in enc else "256"
        ike = f"aes{bits}gcm16-prfsha256-{g}"
        esp = f"aes{bits}gcm16" + (f"-{g}" if pfs=="on" else "")
    else:
        base = {"aes128-cbc":"aes128","aes256-cbc":"aes256","3des-cbc":"3des"}[enc]
        ike = f"{base}-{integ}-{g}"
        esp = f"{base}-{integ}" + (f"-{g}" if pfs=="on" else "")
    return ike, esp

def write_conf(container, ike_ver, mode, ike_prop, esp_prop, auto):
    tmpl = open("gateway/ipsec.conf.tmpl").read()
    conf = (tmpl.replace("{{IKE}}", f"ikev{ike_ver}").replace("{{MODE}}", mode)
                .replace("{{IKE_PROPOSAL}}", ike_prop+"!")
                .replace("{{ESP_PROPOSAL}}", esp_prop+"!").replace("{{AUTO}}", auto))
    dx(container, f"cat > /etc/ipsec.conf << 'END'\n{conf}\nEND")
    dx(container, "cat > /etc/ipsec.secrets << 'END'\n"
                  '10.10.0.10 10.10.0.20 : PSK "ipsecguard_lab_psk_change_me"\nEND')

def run_config(cfg):
    ike_v, mode, enc, integ, dh, pfs, ttype = cfg
    ike_prop, esp_prop = proposals(enc, integ, dh, pfs)
    name = f"ikev{ike_v}_{mode}_{enc}_{integ}_dh{dh}_pfs-{pfs}_{ttype}.pcap"
    print(f"  -> {name}")
    write_conf(SUN,  ike_v, mode, ike_prop, esp_prop, "add")
    write_conf(MOON, ike_v, mode, ike_prop, esp_prop, "start")
    dx(SUN,  "ipsec restart", check=False);  time.sleep(2)
    dx(MOON, "ipsec restart", check=False);  time.sleep(3)
    dx(SUN,  "iperf3 -s -D 2>/dev/null || true", check=False)
    dx(MOON, f"tcpdump -i eth0 -c 20000 -w /captures/{name} "
             f"'(esp or udp port 500 or udp port 4500) and host 10.10.0.20' "
             f">/dev/null 2>&1", bg=True)
    time.sleep(1)
    dx(MOON, "ipsec up lab", check=False); time.sleep(3)
    dx(MOON, TRAFFIC[ttype], check=False)
    time.sleep(1)
    dx(MOON, "pkill tcpdump", check=False)
    dx(MOON, "ipsec down lab", check=False)
    time.sleep(0.5)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--full", action="store_true")
    ap.add_argument("--quick", action="store_true")
    a = ap.parse_args()
    os.makedirs("captures", exist_ok=True)
    if a.full:
        space = itertools.product([1,2], ["tunnel","transport"],
            ["aes128-gcm","aes256-gcm","aes128-cbc","aes256-cbc","3des-cbc"],
            ["sha256","sha1","md5"], [2,5,14,19,20,21], ["on","off"], list(TRAFFIC))
        combos = [c for c in space if not ("gcm" in c[2] and c[3]!="sha256")]
    elif a.quick:
        combos = [(2,"tunnel","aes256-gcm","none",20,"on","voip"),
                  (1,"tunnel","3des-cbc","md5",5,"off","icmp")]
    else:
        combos = [p + (t,) for p in SECURITY_PROFILES for t in TRAFFIC]
    print(f"[sweep] {len(combos)} configs (~{len(combos)*30//60} min est.)")
    for i, cfg in enumerate(combos, 1):
        print(f"[{i}/{len(combos)}]", end="")
        try: run_config(cfg)
        except Exception as e: print("   ! failed:", e)
    print("[sweep] done -> ./captures/*.pcap")

if __name__ == "__main__":
    main()
