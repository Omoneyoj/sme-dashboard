"""
Central Dashboard - Server (READ-ONLY viewer + Remote Commander)
"""

import datetime
import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

import boto3
from botocore.config import Config
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

# Optional background exporter for SIEM
try:
    from siem_exporter import process_and_forward
except ImportError:
    process_and_forward = None

app = FastAPI(title="SME Security Dashboard (Oracle-backed)")

ORACLE_S3_ENDPOINT = os.environ.get("ORACLE_S3_ENDPOINT", "")
ORACLE_ACCESS_KEY = os.environ.get("ORACLE_ACCESS_KEY", "")
ORACLE_SECRET_KEY = os.environ.get("ORACLE_SECRET_KEY", "")
ORACLE_COMMANDER_ACCESS_KEY = os.environ.get("ORACLE_COMMANDER_ACCESS_KEY", "")
ORACLE_COMMANDER_SECRET_KEY = os.environ.get("ORACLE_COMMANDER_SECRET_KEY", "")
ORACLE_BUCKET = os.environ.get("ORACLE_BUCKET", "")
ORACLE_REGION = os.environ.get("ORACLE_REGION", "us-ashburn-1")
DASHBOARD_ADMIN_KEY = os.environ.get("DASHBOARD_ADMIN_KEY", "")

REPORTS_PREFIX = "reports/"
LOGS_PREFIX = "logs/"
DEVICES_PREFIX = "devices/"
LATEST_SUFFIX = "/latest.json"

ALLOWED_COMMANDS = {
    "force_audit",
    "enable_enforcement",
    "disable_enforcement",
    "isolate_host",
    "restore_network",
    "kill_process",  # accepted here, but command_executor.py doesn't act on it yet
}

_CACHE_TTL_SECS = 20
_status_cache = {"data": None, "fetched_at": 0.0}
_inventory_cache = {"data": None, "fetched_at": 0.0}


def get_s3_client(commander=False):
    key = ORACLE_COMMANDER_ACCESS_KEY if commander else ORACLE_ACCESS_KEY
    secret = ORACLE_COMMANDER_SECRET_KEY if commander else ORACLE_SECRET_KEY
    if not (ORACLE_S3_ENDPOINT and key and secret and ORACLE_BUCKET):
        return None
    return boto3.client(
        "s3",
        endpoint_url=ORACLE_S3_ENDPOINT,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
        region_name=ORACLE_REGION,
        config=Config(signature_version="s3v4"),
    )


def fetch_all_logs_from_bucket(prefix: str) -> list:
    """Helper to pull telemetry logs for Timeline tracing."""
    client = get_s3_client()
    if not client:
        return []
    logs = []
    paginator = client.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=ORACLE_BUCKET, Prefix=prefix):
        for obj in page.get("Contents", []):
            try:
                body = client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read()
                logs.append(json.loads(body))
            except Exception:
                continue
    return logs


def fetch_all_latest_reports() -> list:
    """List every reports/**/latest.json object and assemble per-machine,
    per-module status — this is what actually drives the Live Status tab
    and the Recent Alerts feed (threat module's detections)."""
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
                for d in (payload.get("raw") or {}).get("detections", []):
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
    """List every devices/{site}/{hostname}.json object — includes
    machines that haven't reported recently, not just currently-live ones."""
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


def _get_cached(cache: dict, fetch_fn):
    now = time.time()
    if cache["data"] is not None and (now - cache["fetched_at"]) < _CACHE_TTL_SECS:
        return cache["data"]
    data = fetch_fn()
    cache["data"] = data
    cache["fetched_at"] = now
    return data


# ---------------------------------------------------------------------------
# API Routes
# ---------------------------------------------------------------------------

@app.post("/api/alerts")
async def receive_alert(alert: dict, background_tasks: BackgroundTasks):
    """SIEM webhook ingestion point."""
    if process_and_forward:
        background_tasks.add_task(process_and_forward, alert)
    return {"status": "success", "message": "Alert queued"}


@app.get("/api/timeline/{hostname}")
async def get_endpoint_timeline(hostname: str, target_pid: Optional[int] = None) -> Dict:
    """Renders historical events chronologically."""
    raw_logs = fetch_all_logs_from_bucket(prefix=f"{LOGS_PREFIX}{hostname}")
    timeline_events = []

    for log in raw_logs:
        pid = log.get("pid") or log.get("ProcessId")
        parent_pid = log.get("parent_pid") or log.get("ParentProcessId")

        if target_pid and pid != target_pid and parent_pid != target_pid:
            continue

        timeline_events.append({
            "timestamp": log.get("timestamp"),
            "event_type": log.get("event_type", "Process Event"),
            "process_name": log.get("process_name") or log.get("Image", "Unknown"),
            "pid": pid,
            "parent_pid": parent_pid,
            "command_line": log.get("command_line") or log.get("CommandLine", ""),
            "user": log.get("user", "SYSTEM")
        })

    timeline_events.sort(key=lambda x: x.get("timestamp") or "")
    return {"hostname": hostname, "total_events": len(timeline_events), "timeline": timeline_events}


@app.get("/api/status")
async def get_status():
    machines = _get_cached(_status_cache, fetch_all_latest_reports)
    return JSONResponse(content={"machines": machines})


@app.get("/api/inventory")
async def get_inventory():
    devices = _get_cached(_inventory_cache, fetch_device_inventory)
    return JSONResponse(content={"devices": devices})


@app.post("/api/command")
async def issue_command(request: Request, x_admin_key: Optional[str] = Header(None)):
    if not DASHBOARD_ADMIN_KEY or x_admin_key != DASHBOARD_ADMIN_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")

    body = await request.json()
    site_name, hostname, command = body.get("site_name"), body.get("hostname"), body.get("command")

    if command not in ALLOWED_COMMANDS:
        raise HTTPException(status_code=400, detail="Command not allowed")

    client = get_s3_client(commander=True)
    if not client:
        raise HTTPException(status_code=503, detail="S3 Commander not configured")

    key = f"commands/{site_name}/{hostname}/pending.json"
    payload = {"command": command, "issued_at": datetime.datetime.utcnow().isoformat()}
    client.put_object(Bucket=ORACLE_BUCKET, Key=key, Body=json.dumps(payload).encode("utf-8"))

    return {"status": "queued", "hostname": hostname, "command": command}


@app.get("/health")
async def health():
    configured = bool(ORACLE_S3_ENDPOINT and ORACLE_ACCESS_KEY and ORACLE_SECRET_KEY and ORACLE_BUCKET)
    commander_configured = bool(ORACLE_COMMANDER_ACCESS_KEY and ORACLE_COMMANDER_SECRET_KEY and DASHBOARD_ADMIN_KEY)
    return {"status": "ok", "oracle_configured": configured, "remote_commands_configured": commander_configured}


@app.get("/", response_class=HTMLResponse)
async def dashboard_page():
    # Absolute path relative to this file, not the process's current working
    # directory — a bare "dashboard.html" only works if the server happens
    # to be launched with cwd set to this exact folder, which isn't
    # guaranteed across every hosting platform/deploy config.
    html_path = Path(__file__).parent / "dashboard.html"
    return html_path.read_text(encoding="utf-8")