# -*- coding: utf-8 -*-
"""
Central Dashboard - Server
"""
import datetime
import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional


def _parse_utc(s: str) -> Optional[datetime.datetime]:
    """
    Parse any ISO timestamp to a timezone-NAIVE UTC datetime.

    Handles all formats found in the wild:
      - "2026-08-08T17:11:40.4871525+01:00"  (timezone offset, sub-microsecond)
      - "2026-08-08T17:11:40.487152Z"         (Z suffix)
      - "2026-08-08T17:11:40.487152"          (naive, assumed UTC)

    The MTTD/MTTR calculation previously raised TypeError when mixing
    timezone-aware (Defender TimeCreated) and naive (our updated_at) datetimes.
    Python silently caught the exception and skipped all samples, giving N/A.
    """
    if not s:
        return None
    try:
        # 1. Truncate sub-microsecond precision (Python max is 6 digits)
        s = re.sub(r'(\.\d{6})\d+', r'\1', s.strip())
        # 2. Normalise Z to +00:00 for uniform parsing
        s = s.replace('Z', '+00:00')
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            # Convert to UTC, then strip timezone info so all datetimes are naive
            utc_offset = dt.utcoffset()
            dt = dt.replace(tzinfo=None) - utc_offset
        return dt
    except Exception:
        return None

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
            raw = payload.get("raw") or {}
            # 1. Defender detections (Event IDs 1116/1117)
            for d in raw.get("detections", []):
                machines[mk]["alerts"].append({
                    "id":           f"td-{hostname}-{(d.get('TimeCreated') or '').replace(':','-')}",
                    "hostname":     hostname,
                    "site_name":    site_name,
                    "source":       "defender",
                    "time":         d.get("TimeCreated"),
                    "detected_at":  d.get("TimeCreated"),
                    "threat_name":  d.get("ThreatName"),
                    "severity":     d.get("Severity"),
                    "category":     d.get("Category"),
                    "action":       d.get("ActionName"),
                    "path":         d.get("Path"),
                    "process_name": d.get("ProcessName") or "",
                    "command_line": d.get("Path", "").replace("CmdLine:_", ""),
                    "user":         d.get("DetectionUser") or "",
                    "status":       "New",
                })
            # 2. Correlated rule matches — playbook rules that matched a
            #    Defender-blocked threat. These come from threat_reporter.py's
            #    correlate_with_playbooks() which re-evaluates each detection
            #    against the playbook engine, catching processes that were
            #    terminated before WMI fired.
            for cm in raw.get("correlated_rule_matches", []):
                machines[mk]["alerts"].append({
                    "id":           f"cr-{hostname}-{cm.get('detected_at','').replace(':','-')}-{cm.get('rule_name','').replace(' ','_')[:20]}",
                    "hostname":     hostname,
                    "site_name":    site_name,
                    "source":       "playbook_via_defender",
                    "time":         cm.get("detected_at"),
                    "detected_at":  cm.get("detected_at"),
                    "threat_name":  f"[Rule] {cm.get('rule_name')} (via Defender: {cm.get('defender_threat')})",
                    "severity":     cm.get("severity", "MEDIUM"),
                    "action":       "rule_matched",
                    "process_name": cm.get("process_name", ""),
                    "command_line": cm.get("command_line", ""),
                    "rule_name":    cm.get("rule_name", ""),
                    "defender_threat": cm.get("defender_threat", ""),
                    "status":       "New",
                })
        if module == "playbook_alerts":
            # Playbook-triggered alerts from process_monitor.py's rule engine
            # (process was seen by WMI — Defender did NOT pre-block it).
            for a in (payload.get("raw") or {}).get("alerts", []):
                machines[mk]["alerts"].append({
                    "id":           a.get("id", ""),
                    "hostname":     hostname,
                    "site_name":    site_name,
                    "source":       "playbook",
                    "time":         a.get("detected_at"),
                    "detected_at":  a.get("detected_at"),
                    "threat_name":  a.get("rule_name", "Playbook Rule Match"),
                    "severity":     a.get("severity", "MEDIUM"),
                    "action":       ", ".join(a.get("actions", [])),
                    "process_name": a.get("process_name", ""),
                    "command_line": a.get("command_line", ""),
                    "mitre_tactic": a.get("mitre_tactic", ""),
                    "rule_name":    a.get("rule_name", ""),
                    "status":       a.get("status", "New"),
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

    # All module reports — includes the new 'timeline' and 'playbook_alerts' modules
    ALL_MODULES = ["defender", "dns", "threat", "usb", "process_monitor",
                   "playbook_alerts", "timeline"]
    modules = {}
    for module in ALL_MODULES:
        key = f"{REPORTS_PREFIX}{site_name}/{hostname}/{module}/latest.json"
        data = s3_get(client, key)
        if data:
            modules[module] = data

    # ---- Installed applications ----
    # The orchestrator writes installed_apps at the TOP LEVEL of the report
    # dict (not inside 'raw'), because the reporter's build_payload wraps the
    # whole file as payload["raw"]. So to_dict() puts it in raw.installed_apps.
    apps = []
    if "defender" in modules:
        raw = modules["defender"].get("raw") or {}
        apps = raw.get("installed_apps", [])

    # ---- Timeline ----
    # Primary source: timeline_collector.py writes a 'timeline' module report
    # with a flat 'events' list covering process creation, logons, services,
    # network connections, and Defender actions from the Windows Event Log.
    # Fallback: USB and Process Monitor recent_events snapshots (older data).
    timeline = []

    # 1. Rich timeline from timeline_collector (preferred source)
    if "timeline" in modules:
        raw_tl = modules["timeline"].get("raw") or {}
        for evt in raw_tl.get("events", []):
            # Normalise timestamp key: timeline_collector uses 'timestamp'
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
                # Logon fields
                "logon_type":  evt.get("logon_type", ""),
                "source_ip":   evt.get("source_ip", ""),
                # Network fields
                "remote_address": evt.get("remote_address", ""),
                "remote_port":    evt.get("remote_port"),
                "local_address":  evt.get("local_address", ""),
                # Threat fields
                "threat_name":    evt.get("threat_name", ""),
                "severity":       evt.get("severity", ""),
                "action":         evt.get("action", ""),
            })

    # 2. USB drive events (fallback / complement)
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

    # 3. Process Monitor suspicious matches (complement)
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

    # 4. Defender threat detections
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
            })

    # 5. Playbook rule matches
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

    # Sort by time and cap
    timeline.sort(key=lambda x: x.get("time") or "")
    timeline = timeline[-500:]

    # ---- Device alerts (persisted to alerts/ prefix) ----
    alerts = []
    for obj in list_prefix(client, f"{ALERTS_PREFIX}{site_name}/{hostname}/"):
        try:
            alerts.append(json.loads(
                client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read()))
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
    # Pull live detections from the status feed and auto-persist any that
    # aren't already in the persistent alerts/ prefix. We use the COMMANDER
    # client here because the read-only client cannot write — using the
    # read-only client was the bug that caused alerts to appear in-memory
    # but never get saved to Oracle.
    write_client = s3(commander=True)    # write capable
    read_client  = s3(commander=False)   # read capable (for status feed)
    existing_ids = {a["id"] for a in alerts}

    for m in fetch_status():
        for raw_alert in m.get("alerts", []):
            # Build a stable ID from source + hostname + timestamp
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
            # Persist with the write-capable commander client
            if write_client:
                _persist_alert(write_client, new_alert)
            alerts.append(new_alert)
            existing_ids.add(aid)
            # Invalidate the alerts cache so the next call sees the new entry
            _CACHE.pop("alerts", None)

    # Apply filters
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


@app.get("/api/alerts/{alert_id}/context")
async def get_alert_context(alert_id: str, site_name: Optional[str] = None,
                             hostname: Optional[str] = None,
                             window_minutes: int = 10):
    """
    Returns full context for an alert detail modal:
      - The alert record itself
      - Timeline events within +/- window_minutes of the detection time
      - Any other alerts from the same machine in the same window
      - Matched playbook rule details (if source is playbook or playbook_via_defender)

    The alert_id may be a persisted ID (from the alerts/ Oracle prefix) or
    an auto-generated in-memory ID. We search both sources.
    """
    client = s3()
    if not client:
        raise HTTPException(503, "Oracle not configured")

    # 1. Find the alert — check persisted store first, then live status feed
    alert = None
    if site_name and hostname:
        key = f"{ALERTS_PREFIX}{site_name}/{hostname}/{alert_id}.json"
        alert = s3_get(client, key)

    if alert is None:
        # Search all machines in the live status feed
        for m in fetch_status():
            for a in m.get("alerts", []):
                if a.get("id") == alert_id:
                    alert = a
                    site_name = site_name or m["site_name"]
                    hostname  = hostname  or m["hostname"]
                    break
            if alert:
                break

    if alert is None:
        raise HTTPException(404, f"Alert {alert_id} not found")

    detected_ts = alert.get("detected_at") or alert.get("time") or ""
    dt_alert    = _parse_utc(detected_ts)
    window_ms   = window_minutes * 60 * 1000

    # 2. Related timeline events within the time window
    related_events = []
    if site_name and hostname and dt_alert:
        detail = fetch_device_detail(site_name, hostname)
        for evt in detail.get("timeline", []):
            dt_evt = _parse_utc(evt.get("time") or "")
            if dt_evt:
                diff_ms = abs((dt_evt - dt_alert).total_seconds() * 1000)
                if diff_ms <= window_ms:
                    related_events.append({**evt, "_delta_secs": round((dt_evt - dt_alert).total_seconds(), 1)})
        related_events.sort(key=lambda x: x.get("time") or "")

    # 3. Other alerts from the same machine in the same window
    sibling_alerts = []
    if site_name and hostname and dt_alert:
        for m in fetch_status():
            if m["site_name"] == site_name and m["hostname"] == hostname:
                for a in m.get("alerts", []):
                    if a.get("id") == alert_id:
                        continue
                    dt_a = _parse_utc(a.get("detected_at") or a.get("time") or "")
                    if dt_a:
                        diff_s = abs((dt_a - dt_alert).total_seconds())
                        if diff_s <= window_minutes * 60:
                            sibling_alerts.append(a)

    # 4. Playbook rule detail if this is a rule-triggered alert
    rule_detail = None
    rule_name   = alert.get("rule_name") or ""
    if rule_name:
        client2 = s3()
        if client2:
            global_rules = s3_get(client2, "rules/global/rules.json") or {}
            for r in global_rules.get("rules", []):
                if r.get("name") == rule_name or r.get("id") == rule_name:
                    rule_detail = r
                    break

    return JSONResponse({
        "alert":          alert,
        "related_events": related_events,
        "sibling_alerts": sibling_alerts,
        "rule_detail":    rule_detail,
        "window_minutes": window_minutes,
    })


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
    # Clear any stale previous result before queuing so the admin always
    # sees the result of THIS command, not a leftover from a prior one.
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
    """Poll this after issuing a command to get the execution result from
    the endpoint (written by command_executor.py within ~5 minutes)."""
    client = s3()
    if not client:
        raise HTTPException(503, "Oracle not configured")
    result = s3_get(client, f"commands/{site_name}/{hostname}/last_result.json")
    if result is None:
        return JSONResponse({"status": "pending", "message": "No result yet — command may still be executing."})
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
    """Global + site + machine rules merged. Machine overrides site overrides global."""
    global_rules = {r["id"]: r for r in _load_rules(client, "global")}
    site_rules   = {r["id"]: r for r in _load_rules(client, "site",    site)}
    mach_rules   = {r["id"]: r for r in _load_rules(client, "machine", site, hostname)}
    merged = {**global_rules, **site_rules, **mach_rules}
    return list(merged.values())


def _push_rules_to_machine(client, site: str, hostname: str):
    """Write merged rules as a pending update_rules command for the endpoint."""
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
    # Validate actions
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
    """After any rule change, push merged ruleset to all affected endpoints."""
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


@app.get("/api/overview")
async def get_overview():
    """
    Aggregate stats for the Overview landing page:
    - Device online/offline counts and offline-for-N-days breakdown
    - Alert counts by status
    - SOC performance: MTTD and MTTR derived from alert timestamps
    """
    settings    = _get_settings()
    offline_threshold_hours = settings.get("offline_threshold_hours", 1)
    offline_days_warning    = settings.get("offline_days_warning", 7)
    mttd_target_minutes     = int(settings.get("mttd_target_minutes", 30))
    mttr_target_minutes     = int(settings.get("mttr_target_minutes", 120))

    devices  = fetch_inventory()
    alerts   = fetch_all_alerts()
    machines = fetch_status()
    now      = datetime.datetime.utcnow()

    # Device counts
    online   = []
    offline  = []
    long_offline = []  # offline for more than offline_days_warning days

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

    # Alert counts by status
    status_counts = {"New": 0, "Open": 0, "Closed": 0}
    for a in alerts:
        st = a.get("status", "New")
        status_counts[st] = status_counts.get(st, 0) + 1

    # SOC performance — MTTD and MTTR
    # MTTD: time from detected_at to when status first changed to Open (created→opened)
    # MTTR: time from detected_at to when status changed to Closed (created→resolved)
    # We derive these from alert timestamps stored in Oracle.
    mttd_samples = []
    mttr_samples = []

    for a in alerts:
        detected = a.get("detected_at") or a.get("created_at") or a.get("time")
        updated  = a.get("updated_at")
        status   = a.get("status", "New")
        if not detected or not updated:
            continue
        # _parse_utc normalises ALL timestamps to naive UTC before subtraction.
        # Without this, Defender's "+01:00" timestamps vs our naive UTC
        # updated_at raised TypeError, caught silently, giving permanent N/A.
        dt_detected = _parse_utc(detected)
        dt_updated  = _parse_utc(updated)
        if not dt_detected or not dt_updated:
            continue
        delta_mins = (dt_updated - dt_detected).total_seconds() / 60
        if delta_mins < 0:
            continue
        if status in ("Open", "Closed"):
            mttd_samples.append(delta_mins)
        if status == "Closed":
            mttr_samples.append(delta_mins)

    def _avg(samples):
        return round(sum(samples) / len(samples), 1) if samples else None

    # Recent alerts for the overview feed (last 10)
    recent_alerts = sorted(
        [a for a in alerts if a.get("status") != "Closed"],
        key=lambda x: x.get("detected_at") or x.get("time") or "",
        reverse=True
    )[:10]

    # Playbook alert counts from status feed
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
            "mttd_minutes":        _avg(mttd_samples),
            "mttr_minutes":        _avg(mttr_samples),
            "sample_count":        len(mttd_samples),
            "mttd_target_minutes": mttd_target_minutes,
            "mttr_target_minutes": mttr_target_minutes,
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
    # Validate known settings
    allowed_keys = {
        "offline_threshold_hours",   # hours before a device is considered offline (default: 1)
        "offline_days_warning",      # days offline before flagged in overview (default: 7)
        "dashboard_title",
        "org_name",
        "mttd_target_minutes",       # admin-set MTTD target in minutes (default: 30)
        "mttr_target_minutes",       # admin-set MTTR target in minutes (default: 120)
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
