#!/usr/bin/env python3
"""Config sweep with repeats + netem variation."""
import argparse, subprocess, time, os

MOON, SUN = "ipg_moon", "ipg_sun"
DH_NAME = {2:"modp1024",5:"modp1536",14:"modp2048",19:"ecp256",20:"ecp384",21:"ecp521"}

TRAFFIC = {
    "icmp":  "ping -c 250 -i 0.02 10.10.0.20",
    "bulk":  "iperf3 -c 10.10.0.20 -t 10",
    "voip":  "iperf3 -c 10.10.0.20 -u -l 200  -b 80k -t 10",
    "video": "iperf3 -c 10.10.0.20 -u -l 1300 -b 4m  -t 10",
    "email": "bash -c 'for i in 1 2 3; do iperf3 -c 10.10.0.20 -n 2M; sleep 1; done'",
    "web":   "bash -c 'for i in $(seq 1 18); do iperf3 -c 10.10.0.20 -n 300K; sleep 0.3; done'",
    "mixed": "bash -c 'iperf3 -c 10.10.0.20 -u -l 200 -b 80k -t 10 & iperf3 -c 10.10.0.20 -t 10; wait'",
}
NETEM = ["delay 40ms 25ms distribution normal loss 1.5%",
         "delay 90ms 40ms loss 3%",
         "delay 60ms 30ms loss 2% reorder 15% 50%",
         "delay 120ms 50ms loss 4%",
         "delay 30ms 20ms loss 1% duplicate 1%"]

SECURITY_PROFILES = [
    (2,"tunnel","aes256-gcm","none",20,"on"), (2,"tunnel","aes256-gcm","none",19,"on"),
    (2,"tunnel","aes128-gcm","none",19,"on"), (2,"tunnel","aes256-cbc","sha256",14,"on"),
    (2,"tunnel","aes128-cbc","sha256",14,"off"),(2,"transport","aes256-cbc","sha1",14,"off"),
    (1,"tunnel","3des-cbc","md5",5,"off"), (1,"transport","3des-cbc","md5",2,"off"),
]

def dx(c, cmd, bg=False, check=True):
    full=["docker","exec"]+(["-d"] if bg else [])+[c,"bash","-lc",cmd]
    return subprocess.run(full, capture_output=not bg, text=True, check=check)

def proposals(enc, integ, dh, pfs):
    g=DH_NAME[dh]
    if "gcm" in enc:
        b="128" if "128" in enc else "256"
        return f"aes{b}gcm16-prfsha256-{g}", f"aes{b}gcm16"+(f"-{g}" if pfs=="on" else "")
    base={"aes128-cbc":"aes128","aes256-cbc":"aes256","3des-cbc":"3des"}[enc]
    return f"{base}-{integ}-{g}", f"{base}-{integ}"+(f"-{g}" if pfs=="on" else "")

def write_conf(c, ikev, mode, ikep, espp, auto):
    t=open("gateway/ipsec.conf.tmpl").read()
    conf=(t.replace("{{IKE}}",f"ikev{ikev}").replace("{{MODE}}",mode)
           .replace("{{IKE_PROPOSAL}}",ikep+"!").replace("{{ESP_PROPOSAL}}",espp+"!")
           .replace("{{AUTO}}",auto))
    dx(c,f"cat > /etc/ipsec.conf << 'END'\n{conf}\nEND")
    dx(c,"cat > /etc/ipsec.secrets << 'END'\n"
        '10.10.0.10 10.10.0.20 : PSK "ipsecguard_lab_psk_change_me"\nEND')

def run_config(cfg, r):
    ikev,mode,enc,integ,dh,pfs,ttype=cfg
    ikep,espp=proposals(enc,integ,dh,pfs)
    name=f"r{r}_ikev{ikev}_{mode}_{enc}_{integ}_dh{dh}_pfs-{pfs}_{ttype}.pcap"
    print(f"  -> {name}")
    write_conf(SUN,ikev,mode,ikep,espp,"add"); write_conf(MOON,ikev,mode,ikep,espp,"start")
    dx(SUN,"ipsec restart",check=False); time.sleep(2)
    dx(MOON,"ipsec restart",check=False); time.sleep(3)
    dx(SUN,"iperf3 -s -D 2>/dev/null || true",check=False)
    netem=NETEM[r % len(NETEM)]
    if netem: dx(MOON,f"tc qdisc replace dev eth0 root netem {netem}",check=False)
    dx(MOON,f"tcpdump -i eth0 -c 20000 -w /captures/{name} "
            f"'(esp or udp port 500 or udp port 4500) and host 10.10.0.20' >/dev/null 2>&1",bg=True)
    time.sleep(1)
    dx(MOON,"ipsec up lab",check=False); time.sleep(3)
    dx(MOON,TRAFFIC[ttype],check=False); time.sleep(1)
    dx(MOON,"pkill tcpdump",check=False)
    dx(MOON,"tc qdisc del dev eth0 root 2>/dev/null || true",check=False)
    dx(MOON,"ipsec down lab",check=False); time.sleep(0.5)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repeat",type=int,default=1)
    a=ap.parse_args()
    os.makedirs("captures",exist_ok=True)
    combos=[p+(t,) for p in SECURITY_PROFILES for t in TRAFFIC]
    total=len(combos)*a.repeat
    print(f"[sweep] {total} captures ({len(combos)} configs x {a.repeat} repeats, ~{total*22//60} min)")
    n=0
    for r in range(a.repeat):
        for cfg in combos:
            n+=1; print(f"[{n}/{total}]",end="")
            try: run_config(cfg,r)
            except Exception as e: print("  ! failed:",e)
    print("[sweep] done -> ./captures/*.pcap")

if __name__=="__main__": main()
