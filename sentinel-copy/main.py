from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from collections import Counter
import os
import json
import csv
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4

# Phishing classifier
try:
    import joblib
    import sys
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ml'))
    from phishing_features import extract_features, FEATURE_NAMES
    _PHISHING_MODEL = joblib.load(os.path.join('ml', 'models', 'phishing_model.joblib'))
    _threshold_path = os.path.join('ml', 'models', 'phishing_threshold.json')
    _PHISHING_THRESHOLD = json.load(open(_threshold_path))['threshold'] if os.path.exists(_threshold_path) else 0.50
    PHISHING_AVAILABLE = True
    print(f'[Sentinel] Phishing model loaded  (threshold={_PHISHING_THRESHOLD})')
except Exception as _e:
    PHISHING_AVAILABLE = False
    print(f'[Sentinel] Phishing model not available: {_e}')

app = FastAPI()

# ==========================================
# Mount static + templates
# ==========================================

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# ==========================================
# Paths
# ==========================================

LOG_FILE    = os.path.join("ml", "quarantine", "events.jsonl")
NGINX_LOG   = os.path.join("edge", "logs", "access.log")
# Stores the ISO timestamp of the last "Clear Logs" action.
# Entries in access.log BEFORE this stamp are hidden from the dashboard.
CLEAR_STAMP = os.path.join("ml", "quarantine", ".cleared_at")


def _get_cleared_at() -> str:
    """Return the ISO timestamp saved by the last clear action, or epoch-zero."""
    if os.path.exists(CLEAR_STAMP):
        try:
            return open(CLEAR_STAMP).read().strip()
        except Exception:
            pass
    return "1970-01-01T00:00:00"  # default: show everything


def load_nginx_logs():
    logs = []

    if not os.path.exists(NGINX_LOG):
        return logs

    cleared_at = _get_cleared_at()

    with open(NGINX_LOG, "r") as f:
        for line in f:
            parts = line.strip().split("|")

            if len(parts) < 6:
                continue

            ip         = parts[0]
            time       = parts[1]
            method     = parts[2]
            uri        = parts[3]
            status     = int(parts[4])
            user_agent = parts[5].lower()

            # Skip entries that predate the last "Clear Logs" action
            if time <= cleared_at:
                continue

            # Detect Bot (blocked by user-agent rule)
            if status == 403 and any(
                bot in user_agent
                for bot in ["curl", "wget", "sqlmap", "nikto", "nmap", "python", "httpie"]
            ):
                logs.append({
                    "ip":         ip,
                    "attack":     "Bot Detection",
                    "status":     status,
                    "confidence": None,
                    "time":       time
                })

    return logs

# ==========================================
# Load logs from ML engine
# ==========================================
def load_logs():
    logs = []

    if not os.path.exists(LOG_FILE):
        return logs

    with open(LOG_FILE, "r") as f:
        for line in f:
            try:
                entry = json.loads(line.strip())
            except:
                continue

            payload = entry.get("payload", "").lower()
            reason = entry.get("reason", "").lower()
            status = 200 if entry.get("status") == "allow" else 403

            # ==============================
            # Attack Classification Layer
            # ==============================

            if reason == "clean":
                attack = "Normal Traffic"

            # ----- XSS -----
            elif "<script>" in payload:
                attack = "XSS Attack"

            elif "%3cscript" in payload:
                attack = "Encoded XSS Attack"

            # ----- SQLi -----
            elif "or 1=1" in payload:
                attack = "SQL Injection (OR Based)"

            elif "union select" in payload:
                attack = "SQL Injection (UNION Based)"

            elif "--" in payload and "admin" in payload:
                attack = "SQL Injection (Comment Injection)"

            # ----- Path Traversal -----
            elif "../" in payload:
                attack = "Path Traversal Attack"

            # ----- Binary Anomaly -----
            elif "%00" in payload:
                attack = "Binary Payload Anomaly"

            # ----- Global ML Anomaly -----
            elif reason == "global_anomaly":
                attack = "Global ML Anomaly Detection"

            # ----- SQLi Blacklist fallback -----
            elif reason == "sqli_blacklist":
                attack = "SQL Injection (Blacklist)"

            # ----- XSS ML fallback -----
            elif reason == "xss_ml":
                attack = "Cross-Site Scripting (ML Detected)"

            else:
                attack = "Unknown Threat"

            logs.append({
                "ip": entry.get("client_ip"),
                "attack": attack,
                "status": status,
                "confidence": entry.get("confidence"),
                "time": entry.get("timestamp"),
                "payload": payload
            })
    # Merge ML logs + NGINX bot logs
    logs.extend(load_nginx_logs())
    # Sort newest first
    logs.sort(key=lambda x: x["time"], reverse=True)

    return logs

# ==========================================
# Blacklist Management (for future use)
# ==========================================    
BLACKLIST_FILE = "blacklist.json"
def load_blacklist():
    if not os.path.exists(BLACKLIST_FILE):
        return []
        
    with open(BLACKLIST_FILE, "r") as f:
        return json.load(f)

def save_blacklist(data):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(data, f)



# ==========================================
# Dashboard Page
# ==========================================

@app.get("/")
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


# ==========================================
# API: Logs
# ==========================================

@app.get("/api/logs")
async def api_logs():
    return load_logs()


# ==========================================
# API: Summary
# ==========================================

@app.get("/api/summary")
async def api_summary():
    data = load_logs()

    types = Counter([d["attack"] for d in data])
    status = Counter([d["status"] for d in data])
    ips = Counter([d["ip"] for d in data])

    score = round((status[403]) / len(data) * 100, 2) if data else 0

    return {
        "types": types,
        "status": status,
        "top_ips": ips.most_common(5),
        "score": score
    }


# ==========================================
# Export CSV
# ==========================================

@app.get("/export/csv")
async def export_csv(type: str = "ALL"):
    data = load_logs()

    if type != "ALL":
        data = [d for d in data if d["attack"] == type]

    path = "export.csv"

    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Attack", "Confidence", "Status", "Time"])

        for d in data:
            writer.writerow([
                d["ip"],
                d["attack"],
                d["confidence"],
                d["status"],
                d["time"]
            ])

    return FileResponse(path, filename="export.csv")

@app.get("/export/pdf")
async def export_pdf(type: str = "ALL"):

    data = load_logs()

    if type != "ALL":
        data = [d for d in data if d["attack"] == type]

    path = "export.pdf"

    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(
        Paragraph(
            f"Sentinel-AI Security Report - Filter: {type}",
            styles["Heading1"]
        )
    )

    table_data = [["IP", "Attack", "Confidence", "Status", "Time"]]

    for d in data:
        table_data.append([
            str(d["ip"]),
            str(d["attack"]),
            str(d["confidence"]),
            str(d["status"]),
            str(d["time"])
        ])

    table = Table(table_data)

    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.darkblue),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('GRID', (0,0), (-1,-1), 1, colors.black),
    ]))

    elements.append(table)
    doc.build(elements)

    return FileResponse(path, filename="security_report.pdf")

@app.get("/api/blacklist")
async def get_blacklist():
    return load_blacklist()


# ==========================================
# API: Clear All Logs
# ==========================================

@app.post("/api/clear-logs")
async def clear_logs():
    """
    Reset all dashboard counters to zero.

    Strategy:
      • events.jsonl  → physically emptied  (ML engine rewrites it fresh)
      • access.log    → NOT deleted; instead we stamp the current UTC time
                        so load_nginx_logs() ignores every older entry.
                        Future NGINX bot detections (timestamps > stamp) still show up.
    """
    from datetime import datetime, timezone

    now_iso = datetime.now(timezone.utc).isoformat()

    # 1. Wipe ML quarantine log
    if os.path.exists(LOG_FILE):
        open(LOG_FILE, "w").close()

    # 2. Write the "cleared at" timestamp — access.log stays intact
    os.makedirs(os.path.dirname(CLEAR_STAMP), exist_ok=True)
    with open(CLEAR_STAMP, "w") as f:
        f.write(now_iso)

    return {"status": "cleared", "cleared_at": now_iso}

from fastapi import HTTPException

@app.post("/api/block")
async def block_ip(request: Request):
    data = await request.json()
    ip = data.get("ip")

    if not ip:
        raise HTTPException(status_code=400, detail="IP required")

    bl = load_blacklist()

    if ip not in bl:
        bl.append(ip)
        save_blacklist(bl)

    return {"status": "blocked"}

@app.post("/api/unblock")
async def unblock_ip(request: Request):
    data = await request.json()
    ip = data.get("ip")

    bl = load_blacklist()
    bl = [x for x in bl if x != ip]

    save_blacklist(bl)

    return {"status": "unblocked"}


# ==========================================
# Phishing URL Classifier
# ==========================================

def _run_phishing_check(url: str) -> dict:
    """Core inference — returns dict with score, label and feature breakdown."""
    if not PHISHING_AVAILABLE:
        return {"error": "Phishing model not loaded", "url": url}

    feats = extract_features(url)
    prob  = float(_PHISHING_MODEL.predict_proba([feats])[0][1])
    label = "Phishing" if prob >= _PHISHING_THRESHOLD else "Legitimate"

    risk_level = (
        "Critical" if prob >= 0.85 else
        "High"     if prob >= 0.65 else
        "Medium"   if prob >= 0.40 else
        "Low"
    )

    # Build readable feature breakdown (only non-zero or interesting features)
    breakdown = {name: round(val, 4) for name, val in zip(FEATURE_NAMES, feats)}

    return {
        "url":        url,
        "label":      label,
        "risk_level": risk_level,
        "confidence": round(prob * 100, 2),  # percentage
        "threshold":  round(_PHISHING_THRESHOLD * 100, 2),
        "features":   breakdown,
    }


@app.post("/api/phishing/check")
async def phishing_check(request: Request):
    data = await request.json()
    url  = (data.get("url") or "").strip()
    if not url:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="url field is required")
    return _run_phishing_check(url)


@app.post("/api/phishing/batch")
async def phishing_batch(request: Request):
    data = await request.json()
    urls = data.get("urls") or []
    if not isinstance(urls, list) or len(urls) == 0:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="urls must be a non-empty list")
    urls = [u.strip() for u in urls[:20]]  # cap at 20
    return {"results": [_run_phishing_check(u) for u in urls]}


@app.get("/api/phishing/status")
async def phishing_status():
    return {
        "available":  PHISHING_AVAILABLE,
        "threshold":  _PHISHING_THRESHOLD if PHISHING_AVAILABLE else None,
        "model_path": os.path.join('ml', 'models', 'phishing_model.joblib'),
    }
