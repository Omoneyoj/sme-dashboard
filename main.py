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
                    "id":          f"td-{hostname}-{(d.get('TimeCreated') or '').replace(':','-')}",
                    "hostname":    hostname,
                    "site_name":   site_name,
                    "source":      "defender",
                    "time":        d.get("TimeCreated"),
                    "detected_at": d.get("TimeCreated"),
                    "threat_name": d.get("ThreatName"),
                    "severity":    d.get("Severity"),
                    "action":      d.get("ActionName"),
                    # Enhanced parsing for Defender context
                    "process_name":d.get("ProcessName", ""),
                    "parent_name": d.get("ParentProcessName", ""),
                    "command_line":d.get("CommandLine", ""),
                    "file_path":   d.get("Path", ""),
                    "status":      "New",
                })
        if module == "playbook_alerts":
            for a in (payload.get("raw") or {}).get("alerts", []):
                machines[mk]["alerts"].append({
                    "id":          a.get("id", ""),
                    "hostname":    hostname,
                    "site_name":   site_name,
                    "source":      "playbook",
                    "time":        a.get("detected_at"),
                    "detected_at": a.get("detected_at"),
                    "threat_name": a.get("rule_name", "Playbook Rule Match"),
                    "severity":    a.get("severity", "MEDIUM"),
                    "action":      ", ".join(a.get("actions", [])),
                    "process_name":a.get("process_name", ""),
                    "command_line":a.get("command_line", ""),
                    "mitre_tactic":a.get("mitre_tactic", ""),
                    "status":      a.get("status", "New"),
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

    device = s3_get(client, f"{DEVICES_PREFIX}{site_name}/{hostname}.json") or {}

    ALL_MODULES = ["defender", "dns", "threat", "usb", "process_monitor",
                   "playbook_alerts", "timeline"]
    modules = {}
    for module in ALL_MODULES:
        key = f"{REPORTS_PREFIX}{site_name}/{hostname}/{module}/latest.json"
        data = s3_get(client, key)
        if data:
            modules[module] = data

    apps = []
    if "defender" in modules:
        raw = modules["defender"].get("raw") or {}
        apps = raw.get("installed_apps", [])

    timeline = []

    if "timeline" in modules:
        raw_tl = modules["timeline"].get("raw") or {}
        for evt in raw_tl.get("events", []):
            timeline.append({
                "source":      evt.get("event_type", "event"),
                "time":        evt.get("timestamp"),
                "event_type":  evt.get("event_type", ""),
                "process_name":evt.get("process_name", ""),
                "pid":         evt.get("pid"),
                "parent_name": evt.get("parent_path", ""),
                "command_line":evt.get("command_line", ""),
                "user":        evt.get("user", ""),
                "path":        evt.get("process_path") or evt.get("service_file", ""),
                "logon_type":  evt.get("logon_type", ""),
                "source_ip":   evt.get("source_ip", ""),
                "remote_address": evt.get("remote_address", ""),
                "remote_port":    evt.get("remote_port"),
                "local_address":  evt.get("local_address", ""),
                "threat_name":    evt.get("threat_name", ""),
                "severity":       evt.get("severity", ""),
                "action":         evt.get("action", ""),
            })

    if "usb" in modules:
        for evt in (modules["usb"].get("raw") or {}).get("recent_events", []):
            timeline.append({
                "source":      "usb",
                "time":        evt.get("time"),
                "event_type":  "usb_execution",
                "process_name":evt.get("path", "").split("\\")[-1],
                "pid":         evt.get("pid"),
                "path":        evt.get("path", ""),
                "drive":       evt.get("drive", ""),
                "action":      evt.get("action", ""),
            })

    if "process_monitor" in modules:
        for evt in (modules["process_monitor"].get("raw") or {}).get("recent_events", []):
            timeline.append({
                "source":      "process_monitor",
                "time":        evt.get("time"),
                "event_type":  "suspicious_process",
                "process_name":evt.get("path", "").split("\\")[-1],
                "pid":         evt.get("pid"),
                "path":        evt.get("path", ""),
                "verdict":     evt.get("verdict", ""),
                "action":      evt.get("action", ""),
            })

    if "threat" in modules:
        for d in (modules["threat"].get("raw") or {}).get("detections", []):
            timeline.append({
                "source":      "defender",
                "time":        d.get("TimeCreated"),
                "event_type":  "threat_detected",
                "threat_name": d.get("ThreatName", ""),
                "severity":    d.get("Severity", ""),
                "path":        d.get("Path", ""),
                "action":      d.get("ActionName", ""),
                # Enhanced parsing for Defender context
                "process_name":d.get("ProcessName", ""),
                "parent_name": d.get("ParentProcessName", ""),
                "command_line":d.get("CommandLine", ""),
            })

    if "playbook_alerts" in modules:
        for a in (modules["playbook_alerts"].get("raw") or {}).get("alerts", []):
            timeline.append({
                "source":      "playbook",
                "time":        a.get("detected_at"),
                "event_type":  "rule_match",
                "process_name":a.get("process_name", ""),
                "pid":         a.get("pid"),
                "command_line":a.get("command_line", ""),
                "threat_name": a.get("rule_name", ""),
                "severity":    a.get("severity", ""),
                "action":      ", ".join(a.get("actions", [])),
            })

    # Robust sorting: strictly evaluate key as string to prevent TypeErrors
    timeline.sort(key=lambda x: str(x.get("time") or ""))
    timeline = timeline[-500:]

    alerts = []
    for obj in list_prefix(client, f"{ALERTS_PREFIX}{site_name}/{hostname}/"):
        try:
            alerts.append(json.loads(
                client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read()))
        except Exception:
            continue
    alerts.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)

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
    alerts.sort(key=lambda x: str(x.get("created_at") or ""), reverse=True)
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
    write_client = s3(commander=True)
    read_client  = s3(commander=False)
    existing_ids = {a["id"] for a in alerts}

    for m in fetch_status():
        for raw_alert in m.get("alerts", []):
            src  = raw_alert.get("source", "unknown")
            ts   = (raw_alert.get("detected_at") or raw_alert.get("time") or "")
            aid  = raw_alert.get("id") or f"auto-{src}-{m['site_name']}-{m['hostname']}-{ts.replace(':', '-')}"
            if aid in existing_ids:
                continue
            new_alert = {
                "id":          aid,
                "site_name":   m["site_name"],
                "hostname":    m["hostname"],
                "source":      src,
                "status":      "New",
                "severity":    raw_alert.get("severity") or "MEDIUM",
                "threat_name": raw_alert.get("threat_name") or "Unknown Threat",
                "action":      raw_alert.get("action") or "",
                "process_name":raw_alert.get("process_name") or "",
                "command_line":raw_alert.get("command_line") or "",
                "mitre_tactic":raw_alert.get("mitre_tactic") or "",
                "detected_at": ts,
                "created_at":  datetime.datetime.utcnow().isoformat(timespec="milliseconds"),
                "updated_at":  datetime.datetime.utcnow().isoformat(timespec="milliseconds"),
                "notes":       "",
            }
            if write_client:
                _persist_alert(write_client, new_alert)
            alerts.append(new_alert)
            existing_ids.add(aid)
            _CACHE.pop("alerts", None)

    if status:
        alerts = [a for a in alerts if a.get("status") == status]
    if site:
        alerts = [a for a in alerts if a.get("site_name") == site]
    if hostname:
        alerts = [a for a in alerts if a.get("hostname") == hostname]
    if severity:
        alerts = [a for a in alerts if (a.get("severity") or "").upper() == severity.upper()]

    return JSONResponse({"alerts": alerts})


@app.patch("/api/alerts/{alert_id}")
async def update_alert(alert_id: str, request: Request, x_admin_key: Optional[str] = Header(None)):
    require_admin(x_admin_key)
    body = await request.json()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
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


@app.post("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: str, request: Request, x_admin_key: Optional[str] = Header(None)):
    require_admin(x_admin_key)
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
        
    for obj in list_prefix(client, ALERTS_PREFIX):
        if obj["Key"].endswith(f"/{alert_id}.json"):
            alert = json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read())
            alert["status"] = "Closed"
            alert["updated_at"] = datetime.datetime.utcnow().isoformat()
            s3_put(client, obj["Key"], alert)
            _CACHE.pop("alerts", None)
            return JSONResponse({"status": "resolved", "alert_id": alert_id})
            
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
        raise HTTPException(503, "Commander credentials not configured on this server")
    try:
        client.delete_object(Bucket=ORACLE_BUCKET,
                              Key=f"commands/{site_name}/{hostname}/last_result.json")
    except Exception:
        pass
    payload = {**body, "issued_at": datetime.datetime.utcnow().isoformat()}
    s3_put(client, f"commands/{site_name}/{hostname}/pending.json", payload)
    return JSONResponse({"status": "queued", "hostname": hostname, "command": command})


@app.get("/api/command_result/{site_name}/{hostname}")
async def get_command_result(site_name: str, hostname: str):
    client = s3()
    if not client:
        raise HTTPException(503, "Oracle not configured")
    result = s3_get(client, f"commands/{site_name}/{hostname}/last_result.json")
    if result is None:
        return JSONResponse({"status": "pending", "message": "No result yet."})
    return JSONResponse(result)


# ---------------------------------------------------------------------------
# Detection Rules Management
# ---------------------------------------------------------------------------

RULES_PREFIX   = "rules/"
ALLOWED_ACTIONS = [
    "alert_only", "kill_process", "isolate_host",
    "block_network", "collect_forensics",
]


def _rules_key(scope: str, site: str = None, hostname: str = None) -> str:
    if scope == "global":
        return f"{RULES_PREFIX}global/rules.json"
    if scope == "site":
        return f"{RULES_PREFIX}sites/{site}/rules.json"
    return f"{RULES_PREFIX}machines/{site}/{hostname}/rules.json"


def _load_rules(client, scope: str, site: str = None, hostname: str = None) -> list:
    data = s3_get(client, _rules_key(scope, site, hostname))
    return data.get("rules", []) if data else []


def _save_rules(client, rules: list, scope: str, site: str = None, hostname: str = None):
    s3_put(client, _rules_key(scope, site, hostname), {
        "rules":      rules,
        "updated_at": datetime.datetime.utcnow().isoformat(),
    })


def _merge_rules_for_machine(client, site: str, hostname: str) -> list:
    global_rules = {r["id"]: r for r in _load_rules(client, "global")}
    site_rules   = {r["id"]: r for r in _load_rules(client, "site",    site)}
    mach_rules   = {r["id"]: r for r in _load_rules(client, "machine", site, hostname)}
    merged = {**global_rules, **site_rules, **mach_rules}
    return list(merged.values())


def _push_rules_to_machine(client, site: str, hostname: str):
    merged = _merge_rules_for_machine(client, site, hostname)
    key = f"commands/{site}/{hostname}/pending.json"
    s3_put(client, key, {
        "command":    "update_rules",
        "rules":      merged,
        "issued_at":  datetime.datetime.utcnow().isoformat(),
    })


@app.get("/api/rules")
async def get_rules(scope: str = "global", site: Optional[str] = None,
                     hostname: Optional[str] = None):
    client = s3()
    if not client:
        raise HTTPException(503, "Oracle not configured")
    rules = _load_rules(client, scope, site, hostname)
    return JSONResponse({"rules": rules, "scope": scope})


@app.post("/api/rules")
async def create_rule(request: Request, x_admin_key: Optional[str] = Header(None),
                       scope: str = "global", site: Optional[str] = None,
                       hostname: Optional[str] = None):
    require_admin(x_admin_key)
    body = await request.json()
    actions = body.get("actions", [])
    bad = [a for a in actions if a not in ALLOWED_ACTIONS]
    if bad:
        raise HTTPException(400, f"Unknown actions: {bad}. Allowed: {ALLOWED_ACTIONS}")

    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")

    rules = _load_rules(client, scope, site, hostname)
    new_rule = {
        "id":           str(uuid.uuid4())[:8],
        "name":         body.get("name", "Unnamed Rule"),
        "description":  body.get("description", ""),
        "severity":     body.get("severity", "MEDIUM"),
        "mitre_tactic": body.get("mitre_tactic", ""),
        "enabled":      body.get("enabled", True),
        "conditions":   body.get("conditions", {}),
        "actions":      actions,
        "created_at":   datetime.datetime.utcnow().isoformat(),
        "updated_at":   datetime.datetime.utcnow().isoformat(),
    }
    rules.append(new_rule)
    _save_rules(client, rules, scope, site, hostname)
    _push_rules_to_affected_machines(client, scope, site, hostname)
    return JSONResponse(new_rule, status_code=201)


@app.put("/api/rules/{rule_id}")
async def update_rule(rule_id: str, request: Request,
                       x_admin_key: Optional[str] = Header(None),
                       scope: str = "global", site: Optional[str] = None,
                       hostname: Optional[str] = None):
    require_admin(x_admin_key)
    body = await request.json()
    actions = body.get("actions")
    if actions:
        bad = [a for a in actions if a not in ALLOWED_ACTIONS]
        if bad:
            raise HTTPException(400, f"Unknown actions: {bad}. Allowed: {ALLOWED_ACTIONS}")

    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")

    rules = _load_rules(client, scope, site, hostname)
    updated = None
    for r in rules:
        if r["id"] == rule_id:
            updatable = {"name","description","severity","mitre_tactic",
                         "enabled","conditions","actions"}
            for k in updatable:
                if k in body:
                    r[k] = body[k]
            r["updated_at"] = datetime.datetime.utcnow().isoformat()
            updated = r
            break
    if not updated:
        raise HTTPException(404, f"Rule {rule_id} not found in scope '{scope}'")

    _save_rules(client, rules, scope, site, hostname)
    _push_rules_to_affected_machines(client, scope, site, hostname)
    return JSONResponse(updated)


@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str,
                       x_admin_key: Optional[str] = Header(None),
                       scope: str = "global", site: Optional[str] = None,
                       hostname: Optional[str] = None):
    require_admin(x_admin_key)
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")

    rules = _load_rules(client, scope, site, hostname)
    before = len(rules)
    rules = [r for r in rules if r["id"] != rule_id]
    if len(rules) == before:
        raise HTTPException(404, f"Rule {rule_id} not found")

    _save_rules(client, rules, scope, site, hostname)
    _push_rules_to_affected_machines(client, scope, site, hostname)
    return JSONResponse({"status": "deleted", "rule_id": rule_id})


def _push_rules_to_affected_machines(client, scope: str,
                                      site: Optional[str], hostname: Optional[str]):
    devices = fetch_inventory()
    for d in devices:
        if scope == "global":
            _push_rules_to_machine(client, d["site_name"], d["hostname"])
        elif scope == "site" and d["site_name"] == site:
            _push_rules_to_machine(client, d["site_name"], d["hostname"])
        elif scope == "machine" and d["site_name"] == site and d["hostname"] == hostname:
            _push_rules_to_machine(client, d["site_name"], d["hostname"])


@app.post("/api/alerts/webhook")
async def alert_webhook(request: Request, background_tasks: BackgroundTasks):
    alert = await request.json()
    if process_and_forward:
        background_tasks.add_task(process_and_forward, alert)
    return JSONResponse({"status": "success"})


# Helper function to prevent timezone mismatch exceptions during metric evaluations
def _safe_parse_iso(date_str: str) -> Optional[datetime.datetime]:
    if not date_str:
        return None
    try:
        return datetime.datetime.fromisoformat(str(date_str).replace("Z", "+00:00"))
    except ValueError:
        return None


@app.get("/api/overview")
async def get_overview():
    settings    = _get_settings()
    offline_threshold_hours = settings.get("offline_threshold_hours", 1)
    offline_days_warning    = settings.get("offline_days_warning", 7)

    devices  = fetch_inventory()
    alerts   = fetch_all_alerts()
    machines = fetch_status()
    now      = datetime.datetime.utcnow()

    online   = []
    offline  = []
    long_offline = []

    for d in devices:
        last_seen_str = d.get("last_seen")
        if last_seen_str:
            try:
                ls = datetime.datetime.fromisoformat(last_seen_str.replace("Z", ""))
                age_hours = (now - ls).total_seconds() / 3600
                if age_hours <= offline_threshold_hours:
                    online.append(d)
                else:
                    offline.append(d)
                    if age_hours > offline_days_warning * 24:
                        long_offline.append({**d, "offline_days": round(age_hours / 24, 1)})
            except Exception:
                offline.append(d)
        else:
            offline.append(d)

    status_counts = {"New": 0, "Open": 0, "Closed": 0}
    for a in alerts:
        st = a.get("status", "New")
        status_counts[st] = status_counts.get(st, 0) + 1

    mttd_samples = []
    mttr_samples = []

    for a in alerts:
        detected = a.get("detected_at") or a.get("created_at") or a.get("time")
        updated  = a.get("updated_at")
        status   = a.get("status", "New")
        
        # Robust parsing utilizing the _safe_parse_iso helper
        dt_detected = _safe_parse_iso(detected)
        dt_updated  = _safe_parse_iso(updated)
        
        if not dt_detected or not dt_updated:
            continue
            
        try:
            delta_mins  = (dt_updated - dt_detected).total_seconds() / 60
            if delta_mins < 0:
                continue
            if status in ("Open", "Closed"):
                mttd_samples.append(delta_mins) 
            if status == "Closed":
                mttr_samples.append(delta_mins) 
        except Exception:
            continue

    def _avg(samples):
        return round(sum(samples) / len(samples), 1) if samples else None

    recent_alerts = sorted(
        [a for a in alerts if a.get("status") != "Closed"],
        key=lambda x: str(x.get("detected_at") or x.get("time") or ""),
        reverse=True
    )[:10]

    playbook_alert_count = sum(
        len([a for a in m.get("alerts", []) if a.get("source") == "playbook"])
        for m in machines
    )

    return JSONResponse({
        "devices": {
            "total":         len(devices),
            "online":        len(online),
            "offline":       len(offline),
            "long_offline":  long_offline,
            "threshold_hours":     offline_threshold_hours,
            "warning_days":        offline_days_warning,
        },
        "alerts": {
            "new":           status_counts.get("New", 0),
            "open":          status_counts.get("Open", 0),
            "closed":        status_counts.get("Closed", 0),
            "total":         len(alerts),
            "playbook":      playbook_alert_count,
        },
        "soc_performance": {
            "mttd_minutes":  _avg(mttd_samples),
            "mttr_minutes":  _avg(mttr_samples),
            "sample_count":  len(mttd_samples),
        },
        "recent_alerts":   recent_alerts,
    })


SETTINGS_KEY = "config/dashboard_settings.json"

def _get_settings() -> dict:
    client = s3()
    if not client:
        return {}
    return s3_get(client, SETTINGS_KEY) or {}


@app.get("/api/settings")
async def get_settings():
    return JSONResponse(_get_settings())


@app.put("/api/settings")
async def update_settings(request: Request, x_admin_key: Optional[str] = Header(None)):
    require_admin(x_admin_key)
    body = await request.json()
    allowed_keys = {
        "offline_threshold_hours",
        "offline_days_warning",
        "dashboard_title",
        "org_name",
    }
    settings = _get_settings()
    for k, v in body.items():
        if k in allowed_keys:
            settings[k] = v
    settings["updated_at"] = datetime.datetime.utcnow().isoformat()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander credentials not configured")
    s3_put(client, SETTINGS_KEY, settings)
    return JSONResponse(settings)


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