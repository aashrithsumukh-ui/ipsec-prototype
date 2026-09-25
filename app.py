"""IPsecGuard AI — API backend with Live Simulation, Mode Detection, Validation, Benchmarking & Robust Error Handling.

Endpoints:
  GET  /api/analysis            -> static demo bundle
  GET  /api/validation          -> validation engine output (baseline vs attack)
  GET  /api/evaluation          -> benchmark evaluation results
  POST /api/simulate            -> simulate live traffic, mode detection & weakness assessment
  POST /api/analyze  (pcap)     -> analyze uploaded capture live with automatic mode detection & error handling
  GET  /validation              -> validation view
  GET  /                        -> main unified interactive dashboard
"""
import json, os, tempfile
from typing import Optional, Any, Dict, List
import numpy as np
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, field_validator
import pandas as pd

from ipsecguard.synth import generate, _one_flow
from ipsecguard.classifier import TrafficClassifier
from ipsecguard.anomaly import AnomalyDetector
from ipsecguard.analyze import analyze_pcap, safe_analyze_pcap
from ipsecguard.validation import compare_sessions
from ipsecguard.mode_detector import detect_ipsec_mode
from ipsecguard.scoring import assess
from ipsecguard.report import executive_md, technical_md, validation_report_md
from ipsecguard.errors import (
    ErrorCode,
    IPsecGuardError,
    PCAPValidationError,
    AnalysisPipelineError,
    InvalidInputParameterError,
    format_error_response,
)

app = FastAPI(title="IPsecGuard AI")

# Global Exception Handler for IPsecGuard Errors
@app.exception_handler(IPsecGuardError)
async def ipsecguard_exception_handler(request: Request, exc: IPsecGuardError):
    status_code = 400 if isinstance(exc, PCAPValidationError) or isinstance(exc, InvalidInputParameterError) else 500
    return JSONResponse(status_code=status_code, content=exc.to_dict())

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    err_list = []
    for err in exc.errors():
        err_list.append({
            "loc": [str(x) for x in err.get("loc", [])],
            "msg": str(err.get("msg", "")),
            "type": str(err.get("type", ""))
        })
    msg = err_list[0]["msg"] if err_list else "Invalid request body"
    return JSONResponse(
        status_code=422,
        content=format_error_response(
            message=f"Request validation error: {msg}",
            error_code=ErrorCode.INVALID_INPUT_PARAMETER,
            stage="input_validation",
            retryable=True,
            details=err_list
        )
    )

# Train once at startup: prefer real testbed data, fall back to synthetic
_real_csv = "testbed/dataset.csv"
if os.path.exists(_real_csv):
    _df = pd.read_csv(_real_csv)
    print(f"[app] training on REAL data: {len(_df)} sessions from {_real_csv}")
else:
    _df = generate(160, 5)
    print("[app] no real dataset found — training on synthetic data")

_clf = TrafficClassifier()
_metrics = _clf.fit_eval(_df)
_anom = AnomalyDetector().fit(_df)

VALID_ENCR_ALGOS = {"aes256-gcm", "aes128-gcm", "aes256-cbc", "3des-cbc", "des-cbc"}
VALID_INTEGRITIES = {"none", "sha256", "sha384", "sha1", "md5"}
VALID_DH_GROUPS = {1, 2, 5, 14, 15, 16, 19, 20, 21, 31}
VALID_MODES = {"tunnel", "transport"}

class SimulateRequest(BaseModel):
    traffic_type: str = "web"
    enc_algo: str = "aes256-gcm"
    integrity: str = "none"
    dh_group: int = 20
    pfs: str = "on"
    mode: str = "tunnel"
    apply_downgrade: bool = False

    @field_validator("enc_algo")
    @classmethod
    def validate_enc(cls, v: str) -> str:
        clean = v.lower().strip()
        if clean not in VALID_ENCR_ALGOS:
            raise ValueError(f"Unsupported encryption algorithm '{v}'. Allowed: {sorted(list(VALID_ENCR_ALGOS))}")
        return clean

    @field_validator("dh_group")
    @classmethod
    def validate_dh(cls, v: int) -> int:
        if v not in VALID_DH_GROUPS:
            raise ValueError(f"Unsupported DH Group '{v}'. Allowed: {sorted(list(VALID_DH_GROUPS))}")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        clean = v.lower().strip()
        if clean not in VALID_MODES:
            raise ValueError(f"Unsupported mode '{v}'. Allowed: {sorted(list(VALID_MODES))}")
        return clean

@app.get("/api/analysis")
def analysis():
    with open("outputs/analysis.json", encoding="utf-8") as f:
        return JSONResponse(json.load(f))

@app.get("/api/validation")
def validation():
    out_file = "outputs/attack_impact_validation.json"
    if os.path.exists(out_file):
        with open(out_file, encoding="utf-8") as f:
            return JSONResponse(json.load(f))
    with open("outputs/analysis.json", encoding="utf-8") as f:
        data = json.load(f)
    res = compare_sessions(data["sessions"]["strong"], data["sessions"]["weak"])
    return JSONResponse(res)

@app.get("/api/evaluation")
def evaluation():
    out_file = "outputs/evaluation_benchmark.json"
    if os.path.exists(out_file):
        with open(out_file, encoding="utf-8") as f:
            return JSONResponse(json.load(f))
    from ipsecguard.benchmarking import run_security_evaluation
    res = run_security_evaluation()
    return JSONResponse(res)

@app.post("/api/simulate")
def simulate_traffic(req: SimulateRequest):
    """Simulates a live IPsec traffic session and runs full automatic mode detection & security assessment."""
    rng = np.random.default_rng()
    ttype = req.traffic_type.lower()
    if ttype not in ["voip", "web", "video", "email", "icmp", "bulk", "mixed"]:
        ttype = "web"

    # 1. Generate live flow feature vector
    feats = _one_flow(rng, ttype)

    # 2. Integrity adjustment for AEAD
    integ = "none" if "gcm" in req.enc_algo.lower() else req.integrity

    observed = {
        "enc_algo": req.enc_algo,
        "integrity": integ,
        "dh_group": req.dh_group,
        "ike_version": 2 if req.dh_group >= 14 else 1
    }

    # 3. Automatic Mode Detection
    session_stub = {
        "inferred": {"mode": req.mode, "mode_conf": 0.90 if req.mode == "tunnel" else 0.85},
        "observed": observed,
        "flow_features": feats
    }
    mode_detection = detect_ipsec_mode(session_stub, fallback_hint=req.mode)

    # 4. Traffic Classification & Anomaly Detection
    pred_type, pred_conf = _clf.predict_one(feats)
    is_anom, anom_conf, _ = _anom.score_one({
        **feats,
        "enc_algo": req.enc_algo,
        "integrity": integ,
        "dh_group": req.dh_group,
        "pfs": req.pfs
    })

    inferred = {
        "traffic_type": pred_type,
        "traffic_conf": float(pred_conf),
        "pfs": req.pfs,
        "pfs_conf": 0.85 if req.pfs == "on" else 0.70,
        "mode": mode_detection["detected_mode"],
        "mode_conf": mode_detection["confidence"],
        "anomaly": is_anom,
        "anomaly_conf": float(anom_conf)
    }

    # 5. Security Assessment
    assessment = assess(observed, inferred)
    session_id = f"sim_{req.mode}_{req.enc_algo}_dh{req.dh_group}_pfs-{req.pfs}_{ttype}.pcap"
    assessment["session"] = session_id
    assessment["observed"] = observed
    assessment["inferred"] = inferred
    assessment["flow_features"] = feats
    assessment["mode_detection"] = mode_detection
    assessment["exec_report"] = executive_md(assessment, session_id)
    assessment["tech_report"] = technical_md(assessment, session_id, observed, inferred)

    # 6. If Downgrade comparison requested
    validation_result = None
    if req.apply_downgrade or req.enc_algo in ("3des-cbc", "des-cbc") or req.dh_group in (2, 5) or req.pfs == "off":
        strong_baseline = {
            "session": f"sim_baseline_tunnel_aes256-gcm_dh20_pfs-on_{ttype}.pcap",
            "observed": {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2},
            "inferred": {"traffic_type": ttype, "traffic_conf": 0.95, "pfs": "on", "mode": "tunnel", "anomaly": False}
        }
        validation_result = compare_sessions(strong_baseline, assessment)

    return JSONResponse({
        "status": "success",
        "simulation_parameters": req.model_dump(),
        "assessment": assessment,
        "validation": validation_result
    })

@app.post("/api/analyze")
async def analyze(
    pcap: UploadFile = File(...),
    pfs_hint: Optional[str] = Form(None),
    mode_hint: Optional[str] = Form(None)
):
    """Analyzes an uploaded PCAP with strict pre-flight validation and structured error reporting."""
    if not pcap.filename:
        return JSONResponse(
            status_code=400,
            content=format_error_response(
                message="No file uploaded. Please upload a valid .pcap or .pcapng file.",
                error_code=ErrorCode.PCAP_FILE_NOT_FOUND,
                stage="pcap_validation",
                retryable=True
            )
        )

    ext = pcap.filename.lower()
    if not ext.endswith((".pcap", ".pcapng", ".cap")):
        return JSONResponse(
            status_code=400,
            content=format_error_response(
                message=f"Unsupported file extension '{pcap.filename}'. Allowed formats: .pcap, .pcapng, .cap.",
                error_code=ErrorCode.PCAP_UNSUPPORTED_FORMAT,
                stage="pcap_validation",
                retryable=False,
                details={"filename": pcap.filename}
            )
        )

    content = await pcap.read()
    if len(content) == 0:
        return JSONResponse(
            status_code=400,
            content=format_error_response(
                message="Uploaded capture file is empty (0 bytes).",
                error_code=ErrorCode.PCAP_EMPTY_FILE,
                stage="pcap_validation",
                retryable=False,
                details={"filename": pcap.filename, "bytes_received": 0}
            )
        )

    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    try:
        tmp.write(content)
        tmp.flush()
        tmp.close()

        analysis_output = safe_analyze_pcap(
            tmp.name,
            _clf,
            _anom,
            pfs_hint=pfs_hint or "on",
            mode_hint=mode_hint or "tunnel"
        )

        if analysis_output.get("status") == "error":
            error_code = analysis_output.get("error_code")
            status_code = 400 if "PCAP" in error_code or "VALIDATION" in error_code else 422
            return JSONResponse(status_code=status_code, content=analysis_output)

        res_data = analysis_output["data"]
        res_data["model_metrics"] = _metrics
        return JSONResponse(res_data)

    finally:
        if os.path.exists(tmp.name):
            try:
                os.unlink(tmp.name)
            except Exception:
                pass

@app.get("/validation", response_class=HTMLResponse)
def validation_ui():
    p = "validation_page.html"
    return open(p, encoding="utf-8").read() if os.path.exists(p) else "<h1>Validation page not found</h1>"

@app.get("/", response_class=HTMLResponse)
def home():
    p = "dashboard.html"
    return open(p, encoding="utf-8").read() if os.path.exists(p) else "<h1>Run build_dashboard.py first</h1>"
