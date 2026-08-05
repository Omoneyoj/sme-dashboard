# -*- coding: utf-8 -*-
"""
Central Dashboard - Server
"""
import datetime
import json
import os
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import boto3
from botocore.config import Config
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

try:
    from siem_exporter import process_and_forward
except ImportError:
    process_and_forward = None

app = FastAPI(title="SME Security Dashboard")

ORACLE_S3_ENDPOINT            = os.environ.get("ORACLE_S3_ENDPOINT", "")
ORACLE_ACCESS_KEY             = os.environ.get("ORACLE_ACCESS_KEY", "")
ORACLE_SECRET_KEY             = os.environ.get("ORACLE_SECRET_KEY", "")
ORACLE_COMMANDER_ACCESS_KEY   = os.environ.get("ORACLE_COMMANDER_ACCESS_KEY", "")
ORACLE_COMMANDER_SECRET_KEY   = os.environ.get("ORACLE_COMMANDER_SECRET_KEY", "")
ORACLE_BUCKET                 = os.environ.get("ORACLE_BUCKET", "")
ORACLE_REGION                 = os.environ.get("ORACLE_REGION", "us-ashburn-1")
DASHBOARD_ADMIN_KEY           = os.environ.get("DASHBOARD_ADMIN_KEY", "")

REPORTS_PREFIX   = "reports/"
DEVICES_PREFIX   = "devices/"
ALERTS_PREFIX    = "alerts/"
ENFORCE_PREFIX   = "enforcement/"
LATEST_SUFFIX    = "/latest.json"

ALLOWED_COMMANDS = {
    "force_audit", "enable_enforcement", "disable_enforcement",
    "isolate_host", "restore_network", "kill_process", "apply_policy",
}

_CACHE: Dict[str, dict] = {}
_CACHE_TTL = 20


def _cache_get(key):
    entry = _CACHE.get(key)
    if entry and (time.time() - entry["t"]) < _CACHE_TTL:
        return entry["v"]
    return None


def _cache_set(key, val):
    _CACHE[key] = {"v": val, "t": time.time()}


def s3(commander=False):
    k = ORACLE_COMMANDER_ACCESS_KEY if commander else ORACLE_ACCESS_KEY
    s = ORACLE_COMMANDER_SECRET_KEY if commander else ORACLE_SECRET_KEY
    if not (ORACLE_S3_ENDPOINT and k and s and ORACLE_BUCKET):
        return None
    return boto3.client(
        "s3",
        endpoint_url=ORACLE_S3_ENDPOINT,
        aws_access_key_id=k,
        aws_secret_access_key=s,
        region_name=ORACLE_REGION,
        config=Config(
            signature_version="s3v4",
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
        ),
    )


def s3_get(client, key: str):
    try:
        return json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=key)["Body"].read())
    except Exception:
        return None


def s3_put(client, key: str, data: dict):
    client.put_object(
        Bucket=ORACLE_BUCKET, Key=key,
        Body=json.dumps(data).encode("utf-8"),
        ContentType="application/json",
    )


def list_prefix(client, prefix: str) -> list:
    out = []
    pager = client.get_paginator("list_objects_v2")
    for page in pager.paginate(Bucket=ORACLE_BUCKET, Prefix=prefix):
        out.extend(page.get("Contents", []))
    return out


# ---------------------------------------------------------------------------
# Status / reports
# ---------------------------------------------------------------------------

def fetch_status() -> list:
    cached = _cache_get("status")
    if cached is not None:
        return cached
    client = s3()
    if not client:
        return []
    machines = {}
    for obj in list_prefix(client, REPORTS_PREFIX):
        key = obj["Key"]
        if not key.endswith(LATEST_SUFFIX):
            continue
        parts = key[len(REPORTS_PREFIX):].split("/")
        if len(parts) != 4:
            continue
        site_name, hostname, module, _ = parts
        try:
            payload = json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=key)["Body"].read())
        except Exception:
            continue
        mk = (site_name, hostname)
        if mk not in machines:
            machines[mk] = {"site_name": site_name, "hostname": hostname, "modules": {}, "alerts": []}
        machines[mk]["modules"][module] = {
            "received_at": payload.get("sent_at") or obj["LastModified"].isoformat(),
            "summary":     payload.get("summary", {}),
            "compliant":   payload.get("compliant"),
        }
        if module == "threat":
            for d in (payload.get("raw") or {}).get("detections", []):
                machines[mk]["alerts"].append({
                    "hostname":    hostname,
                    "site_name":   site_name,
                    "time":        d.get("TimeCreated"),
                    "threat_name": d.get("ThreatName"),
                    "severity":    d.get("Severity"),
                    "action":      d.get("ActionName"),
                })
    result = list(machines.values())
    _cache_set("status", result)
    return result


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

def fetch_inventory() -> list:
    cached = _cache_get("inventory")
    if cached is not None:
        return cached
    client = s3()
    if not client:
        return []
    devices = []
    for obj in list_prefix(client, DEVICES_PREFIX):
        try:
            devices.append(json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read()))
        except Exception:
            continue
    _cache_set("inventory", devices)
    return devices


def fetch_device_detail(site_name: str, hostname: str) -> dict:
    client = s3()
    if not client:
        return {}

    # Base device record
    device = s3_get(client, f"{DEVICES_PREFIX}{site_name}/{hostname}.json") or {}

    # All module reports
    modules = {}
    for module in ["defender", "dns", "threat", "usb", "process_monitor"]:
        key = f"{REPORTS_PREFIX}{site_name}/{hostname}/{module}/latest.json"
        data = s3_get(client, key)
        if data:
            modules[module] = data

    # Installed applications (from defender report if available)
    apps = []
    if "defender" in modules:
        raw = modules["defender"].get("raw") or {}
        apps = raw.get("installed_apps", [])

    # Timeline from existing reports (usb + process_monitor + threat recent events)
    timeline = []
    for module in ["usb", "process_monitor"]:
        if module in modules:
            for evt in (modules[module].get("raw") or {}).get("recent_events", []):
                timeline.append({
                    "source": module,
                    "time":   evt.get("time"),
                    "action": evt.get("action", ""),
                    "path":   evt.get("path", ""),
                    "drive":  evt.get("drive", ""),
                    "pid":    evt.get("pid"),
                    "verdict":evt.get("verdict", ""),
                })
    if "threat" in modules:
        for d in (modules["threat"].get("raw") or {}).get("detections", []):
            timeline.append({
                "source":      "threat",
                "time":        d.get("TimeCreated"),
                "action":      d.get("ActionName", ""),
                "threat_name": d.get("ThreatName", ""),
                "severity":    d.get("Severity", ""),
                "path":        d.get("Path", ""),
            })
    timeline.sort(key=lambda x: x.get("time") or "")
    timeline = timeline[-200:]   # cap at last 200 events

    # Alerts for this device
    alerts = []
    for obj in list_prefix(client, f"{ALERTS_PREFIX}{site_name}/{hostname}/"):
        try:
            alerts.append(json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read()))
        except Exception:
            continue
    alerts.sort(key=lambda x: x.get("created_at") or "", reverse=True)

    return {
        "device":   device,
        "modules":  modules,
        "apps":     apps,
        "timeline": timeline,
        "alerts":   alerts,
    }


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def fetch_all_alerts() -> list:
    cached = _cache_get("alerts")
    if cached is not None:
        return cached
    client = s3()
    if not client:
        return []
    alerts = []
    for obj in list_prefix(client, ALERTS_PREFIX):
        try:
            alerts.append(json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read()))
        except Exception:
            continue
    alerts.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    _cache_set("alerts", alerts)
    return alerts


def _persist_alert(client, alert: dict):
    key = f"{ALERTS_PREFIX}{alert['site_name']}/{alert['hostname']}/{alert['id']}.json"
    s3_put(client, key, alert)


# ---------------------------------------------------------------------------
# Enforcement layers
# ---------------------------------------------------------------------------

def fetch_enforcement() -> dict:
    client = s3()
    if not client:
        return {"global": {}, "sites": {}, "machines": {}}
    return {
        "global":   s3_get(client, f"{ENFORCE_PREFIX}global/policy.json") or {},
        "sites":    _load_all_enforcement_sites(client),
        "machines": _load_all_enforcement_machines(client),
    }


def _load_all_enforcement_sites(client) -> dict:
    result = {}
    for obj in list_prefix(client, f"{ENFORCE_PREFIX}sites/"):
        try:
            data = json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read())
            site = obj["Key"].split("/")[-2]
            result[site] = data
        except Exception:
            pass
    return result


def _load_all_enforcement_machines(client) -> dict:
    result = {}
    for obj in list_prefix(client, f"{ENFORCE_PREFIX}machines/"):
        try:
            data = json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read())
            parts = obj["Key"].split("/")
            if len(parts) >= 5:
                result[f"{parts[-3]}/{parts[-2]}"] = data
        except Exception:
            pass
    return result


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def require_admin(x_admin_key: Optional[str]):
    if not DASHBOARD_ADMIN_KEY:
        raise HTTPException(503, "DASHBOARD_ADMIN_KEY not set on this server")
    if not x_admin_key or x_admin_key != DASHBOARD_ADMIN_KEY:
        raise HTTPException(401, "Invalid or missing X-Admin-Key header")


@app.get("/api/status")
async def get_status():
    return JSONResponse({"machines": fetch_status()})


@app.get("/api/inventory")
async def get_inventory():
    return JSONResponse({"devices": fetch_inventory()})


@app.get("/api/device/{site_name}/{hostname}")
async def get_device_detail(site_name: str, hostname: str):
    return JSONResponse(fetch_device_detail(site_name, hostname))


@app.get("/api/timeline/{site_name}/{hostname}")
async def get_timeline(site_name: str, hostname: str, pid: Optional[int] = None):
    detail = fetch_device_detail(site_name, hostname)
    events = detail.get("timeline", [])
    if pid:
        events = [e for e in events if e.get("pid") == pid]
    return JSONResponse({"hostname": hostname, "events": events})


@app.get("/api/alerts")
async def get_all_alerts(status: Optional[str] = None, site: Optional[str] = None,
                          hostname: Optional[str] = None, severity: Optional[str] = None):
    alerts = fetch_all_alerts()
    # Also pull live threat detections from status feed and auto-create alert records
    client = s3()
    existing_ids = {a["id"] for a in alerts}
    for m in fetch_status():
        for raw_alert in m.get("alerts", []):
            aid = f"auto-{m['site_name']}-{m['hostname']}-{(raw_alert.get('time') or '').replace(':', '-')}"
            if aid not in existing_ids and client:
                new_alert = {
                    "id":          aid,
                    "site_name":   m["site_name"],
                    "hostname":    m["hostname"],
                    "status":      "New",
                    "severity":    raw_alert.get("severity", "MEDIUM"),
                    "threat_name": raw_alert.get("threat_name", "Unknown"),
                    "action":      raw_alert.get("action", ""),
                    "created_at":  raw_alert.get("time") or datetime.datetime.utcnow().isoformat(),
                    "updated_at":  datetime.datetime.utcnow().isoformat(),
                    "notes":       "",
                }
                _persist_alert(client, new_alert)
                alerts.append(new_alert)
                existing_ids.add(aid)
    # Filter
    if status:
        alerts = [a for a in alerts if a.get("status") == status]
    if site:
        alerts = [a for a in alerts if a.get("site_name") == site]
    if hostname:
        alerts = [a for a in alerts if a.get("hostname") == hostname]
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").upper() == severity.upper()]
    return JSONResponse({"alerts": alerts})


@app.patch("/api/alerts/{alert_id}")
async def update_alert(alert_id: str, request: Request, x_admin_key: Optional[str] = Header(None)):
    require_admin(x_admin_key)
    body = await request.json()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    # Find the alert across all locations
    for obj in list_prefix(client, ALERTS_PREFIX):
        if obj["Key"].endswith(f"/{alert_id}.json"):
            alert = json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read())
            allowed_updates = {"status", "notes", "assigned_to"}
            for k in allowed_updates:
                if k in body:
                    alert[k] = body[k]
            alert["updated_at"] = datetime.datetime.utcnow().isoformat()
            s3_put(client, obj["Key"], alert)
            _CACHE.pop("alerts", None)
            return JSONResponse(alert)
    raise HTTPException(404, f"Alert {alert_id} not found")


# ---------------------------------------------------------------------------
# Enforcement policies
# ---------------------------------------------------------------------------

@app.get("/api/enforcement")
async def get_enforcement():
    return JSONResponse(fetch_enforcement())


@app.post("/api/enforcement/global")
async def set_global_enforcement(request: Request, x_admin_key: Optional[str] = Header(None)):
    require_admin(x_admin_key)
    policy = await request.json()
    policy["updated_at"] = datetime.datetime.utcnow().isoformat()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    s3_put(client, f"{ENFORCE_PREFIX}global/policy.json", policy)
    # Queue command for all known machines
    for device in fetch_inventory():
        _queue_enforcement_command(client, device["site_name"], device["hostname"], policy)
    return JSONResponse({"status": "ok", "scope": "global"})


@app.post("/api/enforcement/site/{site_name}")
async def set_site_enforcement(site_name: str, request: Request,
                                x_admin_key: Optional[str] = Header(None)):
    require_admin(x_admin_key)
    policy = await request.json()
    policy["updated_at"] = datetime.datetime.utcnow().isoformat()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    s3_put(client, f"{ENFORCE_PREFIX}sites/{site_name}/policy.json", policy)
    for device in fetch_inventory():
        if device["site_name"] == site_name:
            _queue_enforcement_command(client, site_name, device["hostname"], policy)
    return JSONResponse({"status": "ok", "scope": "site", "site": site_name})


@app.post("/api/enforcement/machine/{site_name}/{hostname}")
async def set_machine_enforcement(site_name: str, hostname: str, request: Request,
                                   x_admin_key: Optional[str] = Header(None)):
    require_admin(x_admin_key)
    policy = await request.json()
    policy["updated_at"] = datetime.datetime.utcnow().isoformat()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    s3_put(client, f"{ENFORCE_PREFIX}machines/{site_name}/{hostname}/policy.json", policy)
    _queue_enforcement_command(client, site_name, hostname, policy)
    return JSONResponse({"status": "ok", "scope": "machine", "hostname": hostname})


def _queue_enforcement_command(client, site_name, hostname, policy):
    """Queue a full apply_policy command so the machine receives all policy
    flags (DNS, USB blocking, auto-containment, exemptions), not just the
    enforce toggle. The command_executor.py handle_apply_policy() applies them."""
    key = f"commands/{site_name}/{hostname}/pending.json"
    payload = {
        "command":    "apply_policy",
        "policy":     policy,
        "issued_at":  datetime.datetime.utcnow().isoformat(),
    }
    try:
        s3_put(client, key, payload)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Remote commands
# ---------------------------------------------------------------------------

@app.post("/api/command")
async def issue_command(request: Request, x_admin_key: Optional[str] = Header(None)):
    require_admin(x_admin_key)
    body = await request.json()
    site_name = body.get("site_name")
    hostname   = body.get("hostname")
    command    = body.get("command")
    if command not in ALLOWED_COMMANDS:
        raise HTTPException(400, f"Command not in allowed list: {sorted(ALLOWED_COMMANDS)}")
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander credentials not configured on this server — "
                                  "set ORACLE_COMMANDER_ACCESS_KEY, ORACLE_COMMANDER_SECRET_KEY, "
                                  "and DASHBOARD_ADMIN_KEY as environment variables on Render.")
    key = f"commands/{site_name}/{hostname}/pending.json"
    s3_put(client, key, {"command": command, "issued_at": datetime.datetime.utcnow().isoformat()})
    return JSONResponse({"status": "queued", "hostname": hostname, "command": command})


@app.post("/api/alerts/webhook")
async def alert_webhook(request: Request, background_tasks: BackgroundTasks):
    alert = await request.json()
    if process_and_forward:
        background_tasks.add_task(process_and_forward, alert)
    return JSONResponse({"status": "success"})


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "oracle_configured": bool(ORACLE_S3_ENDPOINT and ORACLE_ACCESS_KEY and ORACLE_BUCKET),
        "commander_configured": bool(ORACLE_COMMANDER_ACCESS_KEY and ORACLE_COMMANDER_SECRET_KEY and DASHBOARD_ADMIN_KEY),
    }


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")
