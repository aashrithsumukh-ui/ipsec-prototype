#!/bin/bash
# IPsecGuard AI — full pipeline runner. Safe to re-run.
set -e
cd "$(dirname "$0")"
BOLD=$'\033[1m'; GRN=$'\033[32m'; YEL=$'\033[33m'; RST=$'\033[0m'
sec(){ echo; echo "${BOLD}=== $1 ===${RST}"; }

sec "0. Start Docker + containers"
sudo service docker start 2>/dev/null || true
cd testbed
docker compose up -d
sleep 3
docker compose ps
cd ..

sec "1. Testbed capture (sweep)"
if ls testbed/captures/*.pcap >/dev/null 2>&1; then
  echo "${GRN}captures already exist ($(ls testbed/captures/*.pcap | wc -l) files) — skipping sweep.${RST}"
  echo "  (to regenerate: rm testbed/captures/*.pcap and re-run, or run: cd testbed && python3 sweep.py --repeat 3)"
else
  echo "${YEL}no captures found — running sweep (~60 min for --repeat 3)...${RST}"
  cd testbed && python3 sweep.py --repeat 3 && cd ..
fi

sec "2. Build dataset from captures"
cd testbed && python3 build_dataset.py && cd ..

sec "3. Evaluate classifier (grouped k-fold CV)"
python3 evaluate.py testbed/dataset.csv

sec "4. Generate dashboard data from real captures"
python3 make_real_dashboard.py testbed/dataset.csv
python3 build_dashboard.py

sec "5. Downgrade attack demo"
if ls testbed/captures/*gcm*.pcap >/dev/null 2>&1 || [ -f testbed/captures/demo_handshake.pcap ]; then
  HS=testbed/captures/demo_handshake.pcap
  if [ ! -f "$HS" ]; then HS=$(ls testbed/captures/*gcm*.pcap | head -1); fi
  echo "using handshake: $HS"
  cd testbed/attacker && python3 demo_downgrade.py "../../$HS" && cd ../..
else
  echo "${YEL}no suitable capture for downgrade demo — skipping (see notes below).${RST}"
fi

sec "6. Forward-Secrecy Proof Engine"
if docker exec ipg_moon ipsec statusall 2>/dev/null | grep -q ESTABLISHED; then
  python3 testbed/fsproof/fs_proof.py ipg_moon on
else
  echo "${YEL}tunnel not established — bring it up first (see notes), then:${RST}"
  echo "  python3 testbed/fsproof/fs_proof.py ipg_moon on"
fi

sec "DONE"
echo "${GRN}Dashboard: run 'explorer.exe dashboard.html' or 'uvicorn app:app --port 8000'${RST}"
