from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
import joblib
import json
import os
import re
from datetime import datetime

app = FastAPI()

# ===============================
# Load Models
# ===============================

xss_model = joblib.load("models/xss_model.joblib")
xss_vec = joblib.load("models/xss_vectorizer.joblib")

sqli_model = joblib.load("models/sqli_model.joblib")
sqli_vec = joblib.load("models/sqli_vectorizer.joblib")

global_model = joblib.load("models/global_model.joblib")
global_vec = joblib.load("models/global_vectorizer.joblib")

# ===============================
# Logging
# ===============================

QUARANTINE = "quarantine"
os.makedirs(QUARANTINE, exist_ok=True)

def log_event(status: str, reason: str, payload: str, request: Request, confidence=None):
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "status": status,
        "reason": reason,
        "engine": "Sentinel AI Edge",

        "client_ip": request.client.host if request.client else None,
        "method": request.method,
        "path": str(request.url.path),
        "query": str(request.url.query),
        "payload": payload,
        "user_agent": request.headers.get("user-agent"),

        "confidence": confidence
    }

    with open(os.path.join(QUARANTINE, "events.jsonl"), "a") as f:
        f.write(json.dumps(entry) + "\n")

# ===============================
# Request Schema
# ===============================

class PredictRequest(BaseModel):
    payload: str

# ===============================
# SQLi Blacklist
# ===============================

SQLI_BLACKLIST = [
    r"(?i)\bunion\b.*\bselect\b",
    r"(?i)'\s*--",
    r"(?i)\bor\b\s+\d+\s*=\s*\d+",
    r"(?i)\bor\b\s+1\s*=\s*1",
    r"(?i)'\s*or\s*'",
    r"(?i)--\s*$",
    r"(?i)'--",
    r"(?i)';--",
    r"(?i)\bdrop\b\s+\btable\b",
    r"(?i)\binformation_schema\b",
    r"(?i)\bbenchmark\(",
    r"(?i)\bsleep\("
]

def blacklist_sqli(payload: str) -> bool:
    return any(re.search(pattern, payload) for pattern in SQLI_BLACKLIST)

# ===============================
# ML Predictors
# ===============================

def predict_xss(payload: str):
    X = xss_vec.transform([payload])
    pred = xss_model.predict(X)[0]
    prob = (
        xss_model.predict_proba(X)[0][1]
        if hasattr(xss_model, "predict_proba")
        else None
    )
    return pred, prob


def predict_sqli(payload: str):
    X = sqli_vec.transform([payload])
    pred = sqli_model.predict(X)[0]
    prob = (
        sqli_model.predict_proba(X)[0][1]
        if hasattr(sqli_model, "predict_proba")
        else None
    )
    return pred, prob


def predict_global(payload: str):
    payload_clean = payload.lower().strip()
    X = global_vec.transform([payload_clean])

    pred = global_model.predict(X)[0]
    prob = (
        global_model.predict_proba(X)[0][1]
        if hasattr(global_model, "predict_proba")
        else None
    )
    return pred, prob

# ===============================
# ML Decision Endpoint
# ===============================

@app.post("/predict")
async def predict(data: PredictRequest, request: Request):
    from urllib.parse import unquote

    payload = unquote(data.payload.lower().strip())

    # 🔥 Added normalization fixes
    payload = payload.replace("+", " ")
    payload = payload.replace("0", " ")

    # ---------------------------
    # 0️⃣ SQLi Blacklist
    # ---------------------------
    if blacklist_sqli(payload):
        log_event("blocked", "sqli_blacklist", payload, request)
        raise HTTPException(status_code=403, detail="Blocked by SQLi blacklist")

    # ---------------------------
    # 1️⃣ Global anomaly detection
    # ---------------------------
    try:
        # Use query-only part if available
        payload_for_global = payload.split("?", 1)[1] if "?" in payload else payload
        g_pred, g_prob = predict_global(payload_for_global)
    except Exception as e:
        print("Global model error:", e)
        g_pred, g_prob = 0, None

    # lowered threshold
    if g_pred == 1 and (g_prob is None or g_prob > 0.55):
        log_event("blocked", "global_anomaly", payload, request, g_prob)
        raise HTTPException(status_code=403, detail="Blocked by Global ML")

    # ---------------------------
    # 2️⃣ XSS detection
    # ---------------------------
    try:
        x_pred, x_prob = predict_xss(payload)
    except Exception as e:
        print("XSS model error:", e)
        x_pred, x_prob = 0, None

    if x_pred == 1 and (x_prob is None or x_prob > 0.70):
        log_event("blocked", "xss_ml", payload, request, x_prob)
        raise HTTPException(status_code=403, detail="Blocked by XSS ML")

    # ---------------------------
    # 3️⃣ SQLi detection
    # ---------------------------
    try:
        s_pred, s_prob = predict_sqli(payload)
    except Exception as e:
        print("SQLi model error:", e)
        s_pred, s_prob = 0, None

    if s_pred == 1 and (s_prob is None or s_prob > 0.70):
        log_event("blocked", "sqli_ml", payload, request, s_prob)
        raise HTTPException(status_code=403, detail="Blocked by SQLi ML")

    # ---------------------------
    # ✅ Allow
    # ---------------------------
    log_event("allow", "clean", payload, request)

    return {"decision": "allow"}
