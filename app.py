"""IPsecGuard AI — API backend (the 'live later' path).

Endpoints:
  GET  /api/analysis            -> the static demo bundle (what the dashboard embeds)
  POST /api/analyze  (pcap)     -> analyze an uploaded capture live, returns full result
  GET  /                        -> serves the dashboard

Run:  uvicorn app:app --reload --port 8000
Then open http://localhost:8000  (dashboard auto-uses the API when served here).
"""
import json, os, tempfile
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
import pandas as pd
from ipsecguard.synth import generate
from ipsecguard.classifier import TrafficClassifier
from ipsecguard.anomaly import AnomalyDetector
from ipsecguard.analyze import analyze_pcap

app = FastAPI(title="IPsecGuard AI")

# train once at startup: prefer real testbed data, fall back to synthetic
_real_csv = "testbed/dataset.csv"
if __import__("os").path.exists(_real_csv):
    _df = pd.read_csv(_real_csv)
    print(f"[app] training on REAL data: {len(_df)} sessions from {_real_csv}")
else:
    _df = generate(160, 5)
    print("[app] no real dataset found — training on synthetic data")
_clf = TrafficClassifier(); _metrics = _clf.fit_eval(_df)
_anom = AnomalyDetector().fit(_df)

@app.get("/api/analysis")
def analysis():
    with open("outputs/analysis.json") as f:
        return JSONResponse(json.load(f))

@app.post("/api/analyze")
async def analyze(pcap: UploadFile = File(...),
                  pfs_hint: str = "on", mode_hint: str = "tunnel"):
    if not pcap.filename.endswith((".pcap", ".pcapng", ".cap")):
        raise HTTPException(400, "Upload a .pcap/.pcapng capture")
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.write(await pcap.read()); tmp.close()
    try:
        r = analyze_pcap(tmp.name, _clf, _anom, pfs_hint=pfs_hint, mode_hint=mode_hint)
        r["model_metrics"] = _metrics
        return JSONResponse(r)
    except Exception as e:
        raise HTTPException(422, f"Could not analyze capture: {e}")
    finally:
        os.unlink(tmp.name)

@app.get("/", response_class=HTMLResponse)
def home():
    p = "dashboard.html"
    return open(p).read() if os.path.exists(p) else "<h1>Run build_dashboard.py first</h1>"
