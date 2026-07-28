"""
Central Dashboard - Server (READ-ONLY viewer)
------------------------------------------------
Cloud-hosted FastAPI service that:
  1. Reads the latest JSON report per (site, hostname, module) directly
     from Oracle Cloud Object Storage (S3-compatible API) — it does NOT
     accept writes. PCs write straight to Oracle; see reporter.py.
  2. Serves a simple HTML dashboard showing a red/green status grid.

Why read-only: this app is meant to run on Render's free tier, which
sleeps after 15 min idle. If PCs POSTed reports directly to this app,
a sleeping dashboard could delay or drop incoming data. By having PCs
write directly to Oracle instead, ingestion never depends on whether
this viewer happens to be awake.

Deploy this on Render (free tier) or any host. See README.md.

Requirements:
    pip install fastapi uvicorn boto3

Environment variables required (read-only viewing):
    ORACLE_S3_ENDPOINT   e.g. https://<namespace>.compat.objectstorage.<region>.oraclecloud.com
    ORACLE_ACCESS_KEY    Customer Secret Key access key (READ-ONLY IAM user, see README)
    ORACLE_SECRET_KEY    Customer Secret Key secret
    ORACLE_BUCKET        Bucket name, e.g. sme-security-reports
    ORACLE_REGION        e.g. eu-frankfurt-1 (whatever region your bucket is in)

Environment variables required for remote commands (optional — leave unset
to run as a pure read-only viewer with no command buttons):
    ORACLE_COMMANDER_ACCESS_KEY   write-capable Customer Secret Key
    ORACLE_COMMANDER_SECRET_KEY   write-capable Customer Secret Key secret
    DASHBOARD_ADMIN_KEY           shared-secret password gating /api/command

Run locally for testing:
    uvicorn main:app --host 0.0.0.0 --port 8000
"""

import json
import os
import time
from pathlib import Path
from typing import Optional

import boto3
from botocore.config import Config
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

ORACLE_S3_ENDPOINT = os.environ.get("ORACLE_S3_ENDPOINT", "")
ORACLE_ACCESS_KEY = os.environ.get("ORACLE_ACCESS_KEY", "")       # read-only key
ORACLE_SECRET_KEY = os.environ.get("ORACLE_SECRET_KEY", "")
# Separate, more powerful credential used ONLY to write commands/ objects.
# Keep this one especially guarded — see README "Security notes".
ORACLE_COMMANDER_ACCESS_KEY = os.environ.get("ORACLE_COMMANDER_ACCESS_KEY", "")
ORACLE_COMMANDER_SECRET_KEY = os.environ.get("ORACLE_COMMANDER_SECRET_KEY", "")
ORACLE_BUCKET = os.environ.get("ORACLE_BUCKET", "")
ORACLE_REGION = os.environ.get("ORACLE_REGION", "us-ashburn-1")

# Shared secret gating who can issue remote commands from the dashboard.
# This is MVP-level auth (a single shared password), not a real login system —
# fine while it's just you operating this, but replace with real auth before
# handing portal access to clients or other staff.
DASHBOARD_ADMIN_KEY = os.environ.get("DASHBOARD_ADMIN_KEY", "")

REPORTS_PREFIX = "reports/"
DEVICES_PREFIX = "devices/"
LATEST_SUFFIX = "/latest.json"

_CACHE_TTL_SECS = 20
_cache = {"data": None, "fetched_at": 0.0}

app = FastAPI(title="SME Security Dashboard (Oracle-backed)")


def _make_client(access_key, secret_key):
    if not (ORACLE_S3_ENDPOINT and access_key and secret_key and ORACLE_BUCKET):
        return None
    return boto3.client(
        "s3",
        endpoint_url=ORACLE_S3_ENDPOINT,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name=ORACLE_REGION,
        config=Config(signature_version="s3v4"),
    )


def get_s3_client():
    """Read-only client, used for everything except issuing commands."""
    return _make_client(ORACLE_ACCESS_KEY, ORACLE_SECRET_KEY)


def get_commander_client():
    """Write-capable client, used only by the command-issuing endpoint."""
    return _make_client(ORACLE_COMMANDER_ACCESS_KEY, ORACLE_COMMANDER_SECRET_KEY)


def fetch_all_latest_reports() -> list:
    """List every reports/**/latest.json object and fetch its content."""
    client = get_s3_client()
    if client is None:
        return []

    machines = {}
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=ORACLE_BUCKET, Prefix=REPORTS_PREFIX):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if not key.endswith(LATEST_SUFFIX):
                continue
            # Key layout: reports/{site}/{hostname}/{module}/latest.json
            parts = key[len(REPORTS_PREFIX):].split("/")
            if len(parts) != 4:
                continue
            site_name, hostname, module, _ = parts

            try:
                body = client.get_object(Bucket=ORACLE_BUCKET, Key=key)["Body"].read()
                payload = json.loads(body)
            except Exception:
                continue

            mkey = (site_name, hostname)
            if mkey not in machines:
                machines[mkey] = {"site_name": site_name, "hostname": hostname, "modules": {}, "alerts": []}

            summary = payload.get("summary", {})
            machines[mkey]["modules"][module] = {
                "received_at": payload.get("sent_at") or obj["LastModified"].isoformat(),
                "summary": summary,
                "compliant": payload.get("compliant", None),
            }

            if module == "threat":
                detections = (payload.get("raw") or {}).get("detections", [])
                for d in detections:
                    machines[mkey]["alerts"].append({
                        "hostname": hostname,
                        "site_name": site_name,
                        "time": d.get("TimeCreated"),
                        "threat_name": d.get("ThreatName"),
                        "severity": d.get("Severity"),
                        "action": d.get("ActionName"),
                    })

    return list(machines.values())


def fetch_device_inventory() -> list:
    """List every devices/{site}/{hostname}.json object — includes offline machines."""
    client = get_s3_client()
    if client is None:
        return []

    devices = []
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=ORACLE_BUCKET, Prefix=DEVICES_PREFIX):
        for obj in page.get("Contents", []):
            try:
                body = client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read()
                devices.append(json.loads(body))
            except Exception:
                continue
    return devices


def get_cached_status() -> list:
    now = time.time()
    if _cache["data"] is not None and (now - _cache["fetched_at"]) < _CACHE_TTL_SECS:
        return _cache["data"]
    data = fetch_all_latest_reports()
    _cache["data"] = data
    _cache["fetched_at"] = now
    return data


# ---------------------------------------------------------------------------
# Dashboard data (JSON, for the HTML page to fetch)
# ---------------------------------------------------------------------------

@app.get("/api/status")
async def get_status():
    machines = get_cached_status()
    return JSONResponse(content={"machines": machines})


@app.get("/api/inventory")
async def get_inventory():
    """All known devices, including ones that haven't reported recently."""
    devices = fetch_device_inventory()
    return JSONResponse(content={"devices": devices})


# ---------------------------------------------------------------------------
# Remote command issuing (admin-gated)
# ---------------------------------------------------------------------------

ALLOWED_COMMANDS = {"force_audit", "enable_enforcement", "disable_enforcement"}


@app.post("/api/command")
async def issue_command(request: Request, x_admin_key: Optional[str] = Header(None)):
    if not DASHBOARD_ADMIN_KEY:
        raise HTTPException(status_code=503, detail="Remote commands are not configured on this server "
                                                      "(DASHBOARD_ADMIN_KEY not set).")
    if not x_admin_key or x_admin_key != DASHBOARD_ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-Admin-Key header")

    body = await request.json()
    site_name = body.get("site_name")
    hostname = body.get("hostname")
    command = body.get("command")

    if not site_name or not hostname or command not in ALLOWED_COMMANDS:
        raise HTTPException(status_code=400,
                             detail=f"Body must include site_name, hostname, and command in {sorted(ALLOWED_COMMANDS)}")

    client = get_commander_client()
    if client is None:
        raise HTTPException(status_code=503, detail="Commander credentials not configured on this server.")

    key = f"commands/{site_name}/{hostname}/pending.json"
    payload = {
        "command": command,
        "issued_at": __import__("datetime").datetime.utcnow().isoformat(timespec="milliseconds"),
    }
    try:
        client.put_object(Bucket=ORACLE_BUCKET, Key=key, Body=json.dumps(payload).encode("utf-8"),
                           ContentType="application/json")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Failed to write command: {e}")

    return {"status": "queued", "site_name": site_name, "hostname": hostname, "command": command}


# ---------------------------------------------------------------------------
# Dashboard HTML
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def dashboard_page():
    html_path = Path(__file__).parent / "dashboard.html"
    return html_path.read_text(encoding="utf-8")


@app.get("/health")
async def health():
    configured = bool(ORACLE_S3_ENDPOINT and ORACLE_ACCESS_KEY and ORACLE_SECRET_KEY and ORACLE_BUCKET)
    commander_configured = bool(ORACLE_COMMANDER_ACCESS_KEY and ORACLE_COMMANDER_SECRET_KEY and DASHBOARD_ADMIN_KEY)
    return {"status": "ok", "oracle_configured": configured, "remote_commands_configured": commander_configured}
