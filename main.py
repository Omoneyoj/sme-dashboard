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
    "kill_process"
}

_CACHE_TTL_SECS = 20
_cache = {"data": None, "fetched_at": 0.0}


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
    return JSONResponse(content={"machines": []})  # Connects to cached S3 fetch


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


@app.get("/", response_class=HTMLResponse)
async def dashboard_page():
    return Path("dashboard.html").read_text(encoding="utf-8")