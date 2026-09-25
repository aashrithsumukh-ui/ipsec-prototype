#!/bin/bash
# IPsecGuard AI — FULL end-to-end run.
# deps -> tests -> testbed -> sweep -> dataset -> eval
#      -> downgrade attack -> FS proof -> dashboard
# Safe to re-run. Skips the ~60-min sweep if captures already exist.
set -e
cd "$(dirname "$0")"
B=$'\033[1m'; G=$'\033[32m'; Y=$'\033[33m'; C=$'\033[36m'; R=$'\033[0m'
sec(){ echo; echo "${B}${C}========== $1 ==========${R}"; }
sub(){ echo "${Y}-- $1${R}"; }

write_cfg(){  # $1=container $2=left $3=right $4=leftid $5=rightid $6=auto $7=extra-lines
  docker exec "$1" bash -c "cat > /etc/ipsec.conf << END
config setup
    charondebug=\"ike 1, knl 1, cfg 0\"

conn lab
    keyexchange=ikev2
    type=tunnel
    left=$2
    right=$3
    leftid=$4
    rightid=$5
    authby=secret
    ike=aes256gcm16-prfsha256-ecp384,3des-md5-modp1024!
    esp=aes256gcm16-ecp384,3des-md5!
    $7
    auto=$6
    keyingtries=3
    dpdaction=none
END" 2>/dev/null || true
  docker exec "$1" bash -c 'cat > /etc/ipsec.secrets << S
10.10.0.10 10.10.0.20 : PSK "ipsecguard_lab_psk_change_me"
S' 2>/dev/null || true
}

sec "0. Dependencies + Docker"
pip install --break-system-packages -q -r requirements.txt pytest 2>/dev/null || \
  pip install --break-system-packages -q fastapi "uvicorn[standard]" python-multipart pytest \
    xgboost scikit-learn pandas numpy scapy
sudo service docker start 2>/dev/null || true
echo "${G}ready${R}"

sec "1. Test suite"
python3 -m pytest test_*.py -q || { echo "${Y}tests failed — stopping${R}"; exit 1; }

sec "2. Start testbed containers"
cd testbed && docker compose up -d && sleep 4 && docker compose ps && cd ..

sec "3. Testbed sweep (real captures)"
if ls testbed/captures/*.pcap >/dev/null 2>&1; then
  echo "${G}captures exist ($(ls testbed/captures/*.pcap | wc -l)) — skipping ~60-min sweep${R}"
else
  echo "${Y}running sweep --repeat 3 (~60 min)...${R}"
  cd testbed && python3 sweep.py --repeat 3 && cd ..
fi

sec "4. Build dataset"
cd testbed && python3 build_dataset.py && cd ..

sec "5. Evaluate classifier (grouped k-fold CV)"
python3 evaluate.py testbed/dataset.csv

sec "6. Generate dashboard data from real captures"
python3 make_real_dashboard.py testbed/dataset.csv
python3 build_dashboard.py

sec "7. LIVE DEMO — Downgrade attack"
write_cfg ipg_moon 10.10.0.10 10.10.0.20 10.10.0.10 10.10.0.20 start ""
write_cfg ipg_sun  10.10.0.20 10.10.0.10 10.10.0.20 10.10.0.10 add ""
docker exec ipg_sun ipsec restart  >/dev/null 2>&1 || true
docker exec ipg_moon ipsec restart >/dev/null 2>&1 || true
sleep 3
sub "capturing a two-proposal handshake"
docker exec ipg_moon ipsec down lab >/dev/null 2>&1 || true
docker exec -d ipg_moon tcpdump -i eth0 -c 40 -w /captures/demo_handshake.pcap 'udp port 500 or udp port 4500' 2>/dev/null || true
sleep 1
docker exec ipg_moon ipsec up lab >/dev/null 2>&1 || true
sleep 4
docker exec ipg_moon pkill tcpdump 2>/dev/null || true
sudo chown "$USER" testbed/captures/demo_handshake.pcap 2>/dev/null || true
( cd testbed/attacker && python3 demo_downgrade.py ../../testbed/captures/demo_handshake.pcap ) \
  || echo "${Y}downgrade demo skipped (no valid handshake)${R}"

sec "8. LIVE DEMO — Forward-Secrecy Proof"
write_cfg ipg_moon 10.10.0.10 10.10.0.20 10.10.0.10 10.10.0.20 start $'ikelifetime=300s\n    lifetime=30s\n    margintime=5s'
write_cfg ipg_sun  10.10.0.20 10.10.0.10 10.10.0.20 10.10.0.10 add   $'ikelifetime=300s\n    lifetime=30s\n    margintime=5s'
docker exec ipg_sun ipsec restart  >/dev/null 2>&1 || true
docker exec ipg_moon ipsec restart >/dev/null 2>&1 || true
sleep 5
if docker exec ipg_moon ipsec statusall 2>/dev/null | grep -q ESTABLISHED; then
  python3 testbed/fsproof/fs_proof.py ipg_moon on || echo "${Y}FS proof incomplete${R}"
else
  echo "${Y}tunnel not up — run manually: python3 testbed/fsproof/fs_proof.py ipg_moon on${R}"
fi

sec "9. Launch dashboard"
echo "Server: ${B}http://localhost:8000${R}   (Ctrl+C to stop)"
( sleep 3; explorer.exe "http://localhost:8000" 2>/dev/null || true ) &
uvicorn app:app --port 8000
