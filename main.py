# -*- coding: utf-8 -*-
"""
SME Security Dashboard — Server v2.0
Includes: Auth (PBKDF2+HMAC, roles), App Management, Bulk Alerts,
          Alert Correlation, AI Analysis (Claude API), layered Enforcement,
          Detection Rules, Timeline, Overview stats.
"""

import base64
import datetime
import hashlib
import hmac as _hmac
import json
import os
import re
import secrets
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

import boto3
from botocore.config import Config
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

try:
    from siem_exporter import process_and_forward
except ImportError:
    process_and_forward = None

app = FastAPI(title="SME Security Dashboard v2")

# ── Environment ──────────────────────────────────────────────────────────────
ORACLE_S3_ENDPOINT          = os.environ.get("ORACLE_S3_ENDPOINT", "")
ORACLE_ACCESS_KEY           = os.environ.get("ORACLE_ACCESS_KEY", "")
ORACLE_SECRET_KEY           = os.environ.get("ORACLE_SECRET_KEY", "")
ORACLE_COMMANDER_ACCESS_KEY = os.environ.get("ORACLE_COMMANDER_ACCESS_KEY", "")
ORACLE_COMMANDER_SECRET_KEY = os.environ.get("ORACLE_COMMANDER_SECRET_KEY", "")
ORACLE_BUCKET               = os.environ.get("ORACLE_BUCKET", "")
ORACLE_REGION               = os.environ.get("ORACLE_REGION", "us-ashburn-1")
DASHBOARD_ADMIN_KEY         = os.environ.get("DASHBOARD_ADMIN_KEY", "")
ANTHROPIC_API_KEY           = os.environ.get("ANTHROPIC_API_KEY", "")

# ── Key prefixes ──────────────────────────────────────────────────────────────
REPORTS_PREFIX  = "reports/"
DEVICES_PREFIX  = "devices/"
ALERTS_PREFIX   = "alerts/"
ENFORCE_PREFIX  = "enforcement/"
RULES_PREFIX    = "rules/"
AUTH_USERS_KEY  = "config/users.json"
AUTH_SECRET_KEY = "config/auth_secret.json"
APP_POLICY_KEY  = "config/app_policies.json"
SETTINGS_KEY    = "config/dashboard_settings.json"
AGENT_SCHEDULE_KEY = "config/agent_schedule.json"

ALLOWED_COMMANDS = {
    "force_audit", "force_report", "enable_enforcement", "disable_enforcement",
    "isolate_host", "restore_network", "kill_process", "apply_policy",
    "update_rules", "uninstall_app", "sanction_app",
}

# Defaults mirrored from agent.py's DEFAULT_SCHEDULE. Units are the
# human-friendly units shown in the dashboard UI (hours/minutes); the
# agent converts to seconds itself. Keep these two lists of keys in sync.
DEFAULT_AGENT_SCHEDULE = {
    "defender_dns_interval_hours":       24,
    "defender_dns_enabled":              True,
    "threat_interval_minutes":           5,
    "threat_enabled":                    True,
    "timeline_interval_minutes":         30,
    "timeline_lookback_hours":           24,
    "timeline_enabled":                  True,
    "reporter_interval_minutes":         15,
    "command_executor_interval_minutes": 5,
    "command_executor_enabled":          True,
    "usb_lockdown_enabled":              True,
    "process_monitor_enabled":           True,
}

# Sane floors so a fat-fingered dashboard value can't spin an endpoint
# agent's thread into a hot loop or hammer Oracle. Mirrors agent.py's
# _MIN_SECONDS but expressed in the same hour/minute units as the field.
AGENT_SCHEDULE_MIN = {
    "defender_dns_interval_hours":       1,
    "threat_interval_minutes":           1,
    "timeline_interval_minutes":         5,
    "timeline_lookback_hours":           1,
    "reporter_interval_minutes":         1,
    "command_executor_interval_minutes": 1,
}
ALLOWED_ACTIONS = [
    "alert_only", "kill_process", "isolate_host",
    "block_network", "collect_forensics",
]
LATEST_SUFFIX = "/latest.json"
TOKEN_EXPIRY  = 24 * 3600  # 24 h

_CACHE: Dict[str, dict] = {}
_CACHE_TTL = 20


# ── S3 helpers ────────────────────────────────────────────────────────────────
def s3(commander=False):
    k = ORACLE_COMMANDER_ACCESS_KEY if commander else ORACLE_ACCESS_KEY
    s = ORACLE_COMMANDER_SECRET_KEY if commander else ORACLE_SECRET_KEY
    if not (ORACLE_S3_ENDPOINT and k and s and ORACLE_BUCKET):
        return None
    return boto3.client(
        "s3", endpoint_url=ORACLE_S3_ENDPOINT,
        aws_access_key_id=k, aws_secret_access_key=s,
        region_name=ORACLE_REGION,
        config=Config(
            signature_version="s3v4",
            request_checksum_calculation="when_required",
            response_checksum_validation="when_required",
            connect_timeout=10, read_timeout=60,
            retries={"max_attempts": 2, "mode": "standard"},
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
        Body=json.dumps(data).encode("utf-8"), ContentType="application/json",
    )


def list_prefix(client, prefix: str) -> list:
    out = []
    try:
        pager = client.get_paginator("list_objects_v2")
        for page in pager.paginate(Bucket=ORACLE_BUCKET, Prefix=prefix):
            out.extend(page.get("Contents", []))
    except Exception:
        pass
    return out


def cache_get(key):
    e = _CACHE.get(key)
    return e["v"] if e and (time.time() - e["t"]) < _CACHE_TTL else None


def cache_set(key, val):
    _CACHE[key] = {"v": val, "t": time.time()}


def cache_bust(*keys):
    for k in keys:
        _CACHE.pop(k, None)


# ── Auth ──────────────────────────────────────────────────────────────────────
ROLE_PERMS = {
    "reader":  {"read"},
    "analyst": {"read", "alerts"},
    "admin":   {"read", "alerts", "users", "apps", "commands", "settings"},
}


def _hash_pw(password: str) -> str:
    salt = os.urandom(32)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + ":" + dk.hex()


def _check_pw(password: str, stored: str) -> bool:
    try:
        salt_hex, dk_hex = stored.split(":")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 200_000)
        return _hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False


def _get_secret() -> str:
    client = s3()
    if not client:
        return DASHBOARD_ADMIN_KEY or "insecure-fallback"
    data = s3_get(client, AUTH_SECRET_KEY) or {}
    if data.get("secret"):
        return data["secret"]
    sec = secrets.token_hex(32)
    s3_put(client, AUTH_SECRET_KEY, {"secret": sec})
    return sec


def _make_token(username: str, role: str) -> str:
    ts = str(int(time.time()))
    payload = f"{username}:{role}:{ts}"
    sig = _hmac.new(_get_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{payload}:{sig}".encode()).decode()


def _verify_token(token: str) -> Optional[dict]:
    try:
        raw = base64.b64decode(token.encode()).decode()
        payload, sig = raw.rsplit(":", 1)
        expected = _hmac.new(_get_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return None
        username, role, ts = payload.split(":")
        if int(time.time()) - int(ts) > TOKEN_EXPIRY:
            return None
        return {"username": username, "role": role, "perms": list(ROLE_PERMS.get(role, set()))}
    except Exception:
        return None


def _load_users() -> list:
    client = s3()
    if not client:
        return []
    data = s3_get(client, AUTH_USERS_KEY) or {}
    users = data.get("users", [])
    # Bootstrap: create default admin if no users exist
    if not users:
        default_pw = DASHBOARD_ADMIN_KEY or "Admin@1234!"
        users = [{"username": "admin", "role": "admin",
                   "password_hash": _hash_pw(default_pw),
                   "email": "", "created_at": datetime.datetime.utcnow().isoformat()}]
        s3_put(client, AUTH_USERS_KEY, {"users": users})
    return users


def _save_users(users: list):
    client = s3(commander=True)
    if client:
        s3_put(client, AUTH_USERS_KEY, {"users": users})


async def get_user(request: Request) -> Optional[dict]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return _verify_token(auth[7:])
    return None


def require_perm(perm: str):
    async def check(request: Request):
        user = await get_user(request)
        if not user:
            raise HTTPException(401, "Authentication required — please log in.")
        if perm not in user.get("perms", []):
            raise HTTPException(403, f"'{user['role']}' role cannot perform '{perm}'. Required: admin or analyst.")
        return user
    return check


# ── Status / reports ──────────────────────────────────────────────────────────
def fetch_status() -> list:
    cached = cache_get("status")
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
        raw = payload.get("raw") or {}
        if module == "threat":
            for d in raw.get("detections", []):
                machines[mk]["alerts"].append({
                    "id":           f"td-{hostname}-{(d.get('TimeCreated') or '').replace(':','-')}",
                    "hostname":     hostname, "site_name": site_name,
                    "source":       "defender", "time": d.get("TimeCreated"),
                    "detected_at":  d.get("TimeCreated"), "threat_name": d.get("ThreatName"),
                    "severity":     d.get("Severity"), "category":   d.get("Category"),
                    "action":       d.get("ActionName"), "path":       d.get("Path"),
                    "process_name": d.get("ProcessName") or "",
                    "command_line": (d.get("Path") or "").replace("CmdLine:_", ""),
                    "user":         d.get("DetectionUser") or "", "status": "New",
                })
            for cm in raw.get("correlated_rule_matches", []):
                machines[mk]["alerts"].append({
                    "id":           f"cr-{hostname}-{cm.get('detected_at','').replace(':','-')}-{cm.get('rule_name','')[:20].replace(' ','_')}",
                    "hostname":     hostname, "site_name": site_name,
                    "source":       "playbook_via_defender",
                    "time":         cm.get("detected_at"), "detected_at": cm.get("detected_at"),
                    "threat_name":  f"[Rule] {cm.get('rule_name')} (via Defender: {cm.get('defender_threat')})",
                    "severity":     cm.get("severity", "MEDIUM"), "action": "rule_matched",
                    "process_name": cm.get("process_name", ""),
                    "command_line": cm.get("command_line", ""),
                    "rule_name":    cm.get("rule_name", ""),
                    "defender_threat": cm.get("defender_threat", ""), "status": "New",
                })
        if module == "playbook_alerts":
            for a in raw.get("alerts", []):
                machines[mk]["alerts"].append({
                    "id":           a.get("id", ""), "hostname": hostname, "site_name": site_name,
                    "source":       "playbook", "time": a.get("detected_at"),
                    "detected_at":  a.get("detected_at"),
                    "threat_name":  a.get("rule_name", "Playbook Rule Match"),
                    "severity":     a.get("severity", "MEDIUM"),
                    "action":       ", ".join(a.get("actions", [])),
                    "process_name": a.get("process_name", ""),
                    "command_line": a.get("command_line", ""),
                    "mitre_tactic": a.get("mitre_tactic", ""),
                    "rule_name":    a.get("rule_name", ""), "status": a.get("status", "New"),
                })
    result = list(machines.values())
    cache_set("status", result)
    return result


def fetch_inventory() -> list:
    cached = cache_get("inventory")
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
            pass
    cache_set("inventory", devices)
    return devices


def _parse_utc(s: str) -> Optional[datetime.datetime]:
    if not s:
        return None
    try:
        s = re.sub(r'(\.\d{6})\d+', r'\1', s.strip()).replace('Z', '+00:00')
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            dt = dt.replace(tzinfo=None) - dt.utcoffset()
        return dt
    except Exception:
        return None


def fetch_all_alerts() -> list:
    cached = cache_get("alerts")
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
            pass
    alerts.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    cache_set("alerts", alerts)
    return alerts


def _persist_alert(client, alert: dict):
    key = f"{ALERTS_PREFIX}{alert['site_name']}/{alert['hostname']}/{alert['id']}.json"
    try:
        s3_put(client, key, alert)
    except Exception:
        pass


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
        # Merge sanction status
        policies = _get_app_policies()
        for app in apps:
            name = (app.get("name") or "").lower()
            app["sanctioned"] = policies.get(name, {}).get("sanctioned", True)
            app["policy_note"] = policies.get(name, {}).get("note", "")

    timeline = []
    if "timeline" in modules:
        for evt in (modules["timeline"].get("raw") or {}).get("events", []):
            timeline.append({
                "source":       evt.get("event_type", "event"),
                "time":         evt.get("timestamp"),
                "event_type":   evt.get("event_type", ""),
                "process_name": evt.get("process_name", ""),
                "pid":          evt.get("pid"),
                "parent_name":  evt.get("parent_path", ""),
                "command_line": evt.get("command_line", ""),
                "user":         evt.get("user", ""),
                "path":         evt.get("process_path") or evt.get("service_file", ""),
                "logon_type":   evt.get("logon_type", ""),
                "source_ip":    evt.get("source_ip", ""),
                "remote_address": evt.get("remote_address", ""),
                "remote_port":  evt.get("remote_port"),
                "threat_name":  evt.get("threat_name", ""),
                "severity":     evt.get("severity", ""),
                "action":       evt.get("action", ""),
            })
    for module in ["usb", "process_monitor"]:
        if module in modules:
            for evt in (modules[module].get("raw") or {}).get("recent_events", []):
                timeline.append({
                    "source": module, "time": evt.get("time"),
                    "event_type": "usb_execution" if module == "usb" else "suspicious_process",
                    "process_name": evt.get("path", "").split("\\")[-1],
                    "pid": evt.get("pid"), "path": evt.get("path", ""),
                    "drive": evt.get("drive", ""), "action": evt.get("action", ""),
                    "verdict": evt.get("verdict", ""),
                })
    if "threat" in modules:
        for d in (modules["threat"].get("raw") or {}).get("detections", []):
            timeline.append({
                "source": "defender", "time": d.get("TimeCreated"),
                "event_type": "threat_detected", "threat_name": d.get("ThreatName", ""),
                "severity": d.get("Severity", ""), "path": d.get("Path", ""),
                "action": d.get("ActionName", ""),
            })
    if "playbook_alerts" in modules:
        for a in (modules["playbook_alerts"].get("raw") or {}).get("alerts", []):
            timeline.append({
                "source": "playbook", "time": a.get("detected_at"),
                "event_type": "rule_match", "process_name": a.get("process_name", ""),
                "pid": a.get("pid"), "command_line": a.get("command_line", ""),
                "threat_name": a.get("rule_name", ""), "severity": a.get("severity", ""),
                "action": ", ".join(a.get("actions", [])),
            })
    timeline.sort(key=lambda x: x.get("time") or "")
    timeline = timeline[-500:]

    alerts = []
    for obj in list_prefix(client, f"{ALERTS_PREFIX}{site_name}/{hostname}/"):
        try:
            alerts.append(json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read()))
        except Exception:
            pass
    alerts.sort(key=lambda x: x.get("created_at") or "", reverse=True)

    return {"device": device, "modules": modules, "apps": apps, "timeline": timeline, "alerts": alerts}


def _get_settings() -> dict:
    client = s3()
    return (s3_get(client, SETTINGS_KEY) or {}) if client else {}


def _get_agent_schedule() -> dict:
    """Merges DEFAULT_AGENT_SCHEDULE with whatever the dashboard has saved
    to Oracle, so the response always contains every known key even before
    the dashboard has ever written an override. Endpoint agents read the
    raw Oracle object directly (see agent.py fetch_remote_schedule) rather
    than calling this API, so it stays available even if Render is asleep;
    this function only backs the dashboard UI's own view/edit of it."""
    client = s3()
    stored = (s3_get(client, AGENT_SCHEDULE_KEY) or {}) if client else {}
    merged = dict(DEFAULT_AGENT_SCHEDULE)
    merged.update({k: v for k, v in stored.items() if k in DEFAULT_AGENT_SCHEDULE})
    merged["updated_at"] = stored.get("updated_at")
    merged["updated_by"] = stored.get("updated_by")
    return merged


def _get_app_policies() -> dict:
    client = s3()
    if not client:
        return {}
    return (s3_get(client, APP_POLICY_KEY) or {}).get("policies", {})


# ── Alert correlation ─────────────────────────────────────────────────────────
def correlate_alerts(alerts: list, window_minutes: int = 30) -> list:
    """
    Group alerts into incidents based on time proximity and machine.
    Returns alerts with 'incident_id' and 'incident_size' fields added.
    Simple but effective: alerts on the same machine within window_minutes
    of each other are grouped into the same incident.
    """
    if not alerts:
        return alerts
    sorted_alerts = sorted(alerts, key=lambda x: x.get("detected_at") or x.get("created_at") or "")
    incidents = {}
    alert_to_incident = {}
    incident_counter = 0

    for i, alert in enumerate(sorted_alerts):
        t_curr = _parse_utc(alert.get("detected_at") or alert.get("created_at") or "")
        machine = f"{alert.get('site_name')}/{alert.get('hostname')}"
        assigned = False
        # Look backwards for an alert on the same machine within window
        for j in range(i - 1, max(i - 20, -1), -1):
            prev = sorted_alerts[j]
            if f"{prev.get('site_name')}/{prev.get('hostname')}" != machine:
                continue
            t_prev = _parse_utc(prev.get("detected_at") or prev.get("created_at") or "")
            if t_curr and t_prev and (t_curr - t_prev).total_seconds() <= window_minutes * 60:
                inc_id = alert_to_incident.get(j)
                if inc_id:
                    alert_to_incident[i] = inc_id
                    incidents[inc_id]["alerts"].append(i)
                    assigned = True
                    break
        if not assigned:
            incident_counter += 1
            inc_id = f"inc-{incident_counter:04d}"
            alert_to_incident[i] = inc_id
            incidents[inc_id] = {"id": inc_id, "alerts": [i]}

    result = []
    for i, alert in enumerate(sorted_alerts):
        inc_id = alert_to_incident.get(i, "")
        inc = incidents.get(inc_id, {})
        result.append({**alert, "incident_id": inc_id, "incident_size": len(inc.get("alerts", [1]))})
    return result


# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/auth/login")
async def login(request: Request):
    body = await request.json()
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")
    if not username or not password:
        raise HTTPException(400, "Username and password required")
    users = _load_users()
    user = next((u for u in users if u["username"].lower() == username), None)
    if not user or not _check_pw(password, user.get("password_hash", "")):
        raise HTTPException(401, "Invalid credentials")
    token = _make_token(user["username"], user["role"])
    return JSONResponse({
        "token":    token,
        "username": user["username"],
        "role":     user["role"],
        "perms":    list(ROLE_PERMS.get(user["role"], set())),
    })


@app.get("/api/auth/me")
async def get_me(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return JSONResponse(user)


@app.get("/api/users")
async def list_users(user=Depends(require_perm("users"))):
    users = _load_users()
    return JSONResponse({"users": [
        {k: v for k, v in u.items() if k != "password_hash"}
        for u in users
    ]})


@app.post("/api/users")
async def create_user(request: Request, user=Depends(require_perm("users"))):
    body = await request.json()
    username = body.get("username", "").strip().lower()
    password = body.get("password", "")
    role     = body.get("role", "reader")
    email    = body.get("email", "")
    if not username or not password:
        raise HTTPException(400, "Username and password required")
    if role not in ROLE_PERMS:
        raise HTTPException(400, f"Invalid role. Must be one of: {list(ROLE_PERMS)}")
    users = _load_users()
    if any(u["username"].lower() == username for u in users):
        raise HTTPException(409, f"User '{username}' already exists")
    new_user = {
        "username":      username, "role": role, "email": email,
        "password_hash": _hash_pw(password),
        "created_at":    datetime.datetime.utcnow().isoformat(),
        "created_by":    user["username"],
    }
    users.append(new_user)
    _save_users(users)
    return JSONResponse({k: v for k, v in new_user.items() if k != "password_hash"},
                        status_code=201)


@app.put("/api/users/{username}")
async def update_user(username: str, request: Request, user=Depends(require_perm("users"))):
    body  = await request.json()
    users = _load_users()
    target = next((u for u in users if u["username"].lower() == username.lower()), None)
    if not target:
        raise HTTPException(404, f"User '{username}' not found")
    if "role" in body:
        if body["role"] not in ROLE_PERMS:
            raise HTTPException(400, f"Invalid role")
        target["role"] = body["role"]
    if "email" in body:
        target["email"] = body["email"]
    if "password" in body and body["password"]:
        target["password_hash"] = _hash_pw(body["password"])
    target["updated_at"] = datetime.datetime.utcnow().isoformat()
    _save_users(users)
    return JSONResponse({k: v for k, v in target.items() if k != "password_hash"})


@app.delete("/api/users/{username}")
async def delete_user(username: str, user=Depends(require_perm("users"))):
    if username.lower() == user["username"].lower():
        raise HTTPException(400, "Cannot delete your own account")
    users = _load_users()
    before = len(users)
    users  = [u for u in users if u["username"].lower() != username.lower()]
    if len(users) == before:
        raise HTTPException(404, f"User '{username}' not found")
    _save_users(users)
    return JSONResponse({"status": "deleted", "username": username})


# ── Data endpoints ────────────────────────────────────────────────────────────
@app.get("/api/status")
async def get_status(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    return JSONResponse({"machines": fetch_status()})


@app.get("/api/inventory")
async def get_inventory(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    return JSONResponse({"devices": fetch_inventory()})


@app.get("/api/device/{site_name}/{hostname}")
async def get_device(site_name: str, hostname: str, request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    return JSONResponse(fetch_device_detail(site_name, hostname))


@app.get("/api/timeline/{site_name}/{hostname}")
async def get_timeline(site_name: str, hostname: str, request: Request, pid: Optional[int] = None):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    detail = fetch_device_detail(site_name, hostname)
    events = detail.get("timeline", [])
    if pid:
        events = [e for e in events if e.get("pid") == pid]
    return JSONResponse({"hostname": hostname, "events": events})


# ── Alerts ────────────────────────────────────────────────────────────────────
@app.get("/api/alerts")
async def get_all_alerts(request: Request, status: Optional[str] = None,
                          site: Optional[str] = None, hostname: Optional[str] = None,
                          severity: Optional[str] = None, source: Optional[str] = None,
                          correlate: bool = False):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")

    alerts = fetch_all_alerts()
    write_client = s3(commander=True)
    existing_ids = {a["id"] for a in alerts}

    for m in fetch_status():
        for raw_alert in m.get("alerts", []):
            src  = raw_alert.get("source", "unknown")
            ts   = raw_alert.get("detected_at") or raw_alert.get("time") or ""
            aid  = raw_alert.get("id") or f"auto-{src}-{m['site_name']}-{m['hostname']}-{ts.replace(':', '-')}"
            if aid in existing_ids:
                continue
            new_alert = {
                "id":          aid, "site_name": m["site_name"], "hostname": m["hostname"],
                "source":      src, "status": "New",
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
            cache_bust("alerts")

    if status:
        alerts = [a for a in alerts if a.get("status") == status]
    if site:
        alerts = [a for a in alerts if a.get("site_name") == site]
    if hostname:
        alerts = [a for a in alerts if a.get("hostname") == hostname]
    if severity:
        alerts = [a for a in alerts if (a.get("severity") or "").upper() == severity.upper()]
    if source:
        alerts = [a for a in alerts if a.get("source") == source]
    if correlate:
        alerts = correlate_alerts(alerts)
    return JSONResponse({"alerts": alerts})


@app.patch("/api/alerts/{alert_id}")
async def update_alert(alert_id: str, request: Request,
                        user=Depends(require_perm("alerts"))):
    body   = await request.json()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    for obj in list_prefix(client, ALERTS_PREFIX):
        if obj["Key"].endswith(f"/{alert_id}.json"):
            alert = json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read())
            for k in {"status", "notes", "assigned_to"}:
                if k in body:
                    alert[k] = body[k]
            alert["updated_at"] = datetime.datetime.utcnow().isoformat()
            alert["updated_by"] = user["username"]
            s3_put(client, obj["Key"], alert)
            cache_bust("alerts")
            return JSONResponse(alert)
    raise HTTPException(404, f"Alert {alert_id} not found")


@app.post("/api/alerts/bulk")
async def bulk_update_alerts(request: Request, user=Depends(require_perm("alerts"))):
    """Bulk status update for multiple alerts at once."""
    body      = await request.json()
    alert_ids = body.get("ids", [])
    new_status= body.get("status")
    notes     = body.get("notes", "")
    if not alert_ids or not new_status:
        raise HTTPException(400, "ids and status required")
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")

    updated = []
    id_set = set(alert_ids)
    for obj in list_prefix(client, ALERTS_PREFIX):
        # Extract alert ID from key: alerts/{site}/{host}/{id}.json
        key_parts = obj["Key"].split("/")
        alert_id  = key_parts[-1].replace(".json", "") if key_parts else ""
        if alert_id not in id_set:
            continue
        try:
            alert = json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=obj["Key"])["Body"].read())
            alert["status"]     = new_status
            alert["updated_at"] = datetime.datetime.utcnow().isoformat()
            alert["updated_by"] = user["username"]
            if notes:
                alert["notes"] = notes
            s3_put(client, obj["Key"], alert)
            updated.append(alert_id)
        except Exception:
            pass

    cache_bust("alerts")
    return JSONResponse({"updated": len(updated), "ids": updated})


@app.get("/api/alerts/{alert_id}/context")
async def get_alert_context(alert_id: str, request: Request,
                             site_name: Optional[str] = None,
                             hostname: Optional[str] = None,
                             window_minutes: int = 10):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    client = s3()
    if not client:
        raise HTTPException(503, "Oracle not configured")
    alert = None
    if site_name and hostname:
        alert = s3_get(client, f"{ALERTS_PREFIX}{site_name}/{hostname}/{alert_id}.json")
    if alert is None:
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
    dt_alert   = _parse_utc(alert.get("detected_at") or alert.get("time") or "")
    window_s   = window_minutes * 60
    related    = []
    siblings   = []
    rule_detail= None
    if site_name and hostname and dt_alert:
        detail = fetch_device_detail(site_name, hostname)
        for evt in detail.get("timeline", []):
            dt_evt = _parse_utc(evt.get("time") or "")
            if dt_evt:
                diff = (dt_evt - dt_alert).total_seconds()
                if abs(diff) <= window_s:
                    related.append({**evt, "_delta_secs": round(diff, 1)})
        related.sort(key=lambda x: x.get("time") or "")
        for m in fetch_status():
            if m["site_name"] == site_name and m["hostname"] == hostname:
                for a in m.get("alerts", []):
                    if a.get("id") == alert_id:
                        continue
                    dt_a = _parse_utc(a.get("detected_at") or a.get("time") or "")
                    if dt_a and abs((dt_a - dt_alert).total_seconds()) <= window_s:
                        siblings.append(a)
    if alert.get("rule_name") and client:
        gdata = s3_get(client, "rules/global/rules.json") or {}
        for r in gdata.get("rules", []):
            if r.get("name") == alert.get("rule_name"):
                rule_detail = r
                break
    return JSONResponse({"alert": alert, "related_events": related,
                          "sibling_alerts": siblings, "rule_detail": rule_detail,
                          "window_minutes": window_minutes})


# ── App Management ────────────────────────────────────────────────────────────
@app.get("/api/apps/inventory")
async def get_global_app_inventory(request: Request, risk: Optional[str] = None,
                                    sanctioned: Optional[bool] = None,
                                    search: Optional[str] = None):
    """Global app inventory across all devices."""
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    policies = _get_app_policies()
    all_apps = []
    seen     = set()
    for m in fetch_status():
        detail = fetch_device_detail(m["site_name"], m["hostname"])
        for app in detail.get("apps", []):
            name = (app.get("name") or "").lower()
            key  = f"{name}:{app.get('version','')}"
            entry = {
                **app,
                "hostname":   m["hostname"],
                "site_name":  m["site_name"],
                "sanctioned": policies.get(name, {}).get("sanctioned", True),
                "policy_note":policies.get(name, {}).get("note", ""),
            }
            all_apps.append(entry)
            seen.add(key)

    if risk:
        all_apps = [a for a in all_apps if (a.get("risk_level") or "").lower() == risk.lower()]
    if sanctioned is not None:
        all_apps = [a for a in all_apps if a.get("sanctioned") == sanctioned]
    if search:
        s = search.lower()
        all_apps = [a for a in all_apps
                    if s in (a.get("name") or "").lower() or
                       s in (a.get("vendor") or "").lower()]
    return JSONResponse({"apps": all_apps, "total": len(all_apps)})


@app.post("/api/apps/sanction")
async def sanction_app(request: Request, user=Depends(require_perm("apps"))):
    """Mark an app as sanctioned or unsanctioned (globally)."""
    body      = await request.json()
    app_name  = (body.get("app_name") or "").lower().strip()
    sanctioned= body.get("sanctioned", True)
    note      = body.get("note", "")
    if not app_name:
        raise HTTPException(400, "app_name required")
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    data = s3_get(client, APP_POLICY_KEY) or {"policies": {}}
    data["policies"] = data.get("policies") or {}
    data["policies"][app_name] = {
        "sanctioned":  sanctioned,
        "note":        note,
        "updated_at":  datetime.datetime.utcnow().isoformat(),
        "updated_by":  user["username"],
    }
    s3_put(client, APP_POLICY_KEY, data)
    # If unsanctioned, push a detection rule alert policy to all devices
    if not sanctioned:
        for device in fetch_inventory():
            key = f"commands/{device['site_name']}/{device['hostname']}/pending.json"
            try:
                s3_put(client, key, {
                    "command":  "sanction_app",
                    "app_name": app_name,
                    "sanctioned": False,
                    "issued_at": datetime.datetime.utcnow().isoformat(),
                })
            except Exception:
                pass
    return JSONResponse({"status": "ok", "app_name": app_name, "sanctioned": sanctioned})


@app.post("/api/apps/uninstall")
async def uninstall_app(request: Request, user=Depends(require_perm("apps"))):
    """Queue an uninstall command on a specific device."""
    body     = await request.json()
    site     = body.get("site_name")
    hostname = body.get("hostname")
    app_name = body.get("app_name")
    if not all([site, hostname, app_name]):
        raise HTTPException(400, "site_name, hostname, app_name required")
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    key = f"commands/{site}/{hostname}/pending.json"
    s3_put(client, key, {
        "command":    "uninstall_app",
        "app_name":   app_name,
        "issued_at":  datetime.datetime.utcnow().isoformat(),
        "issued_by":  user["username"],
    })
    return JSONResponse({"status": "queued", "hostname": hostname, "app_name": app_name})


@app.post("/api/apps/uninstall-bulk")
async def uninstall_apps_bulk(request: Request, user=Depends(require_perm("apps"))):
    """Uninstall all apps matching given criteria across specified devices."""
    body     = await request.json()
    site     = body.get("site_name")
    hostname = body.get("hostname")
    app_names= body.get("app_names", [])
    risk     = body.get("risk_level")
    if not app_names and not risk:
        raise HTTPException(400, "Provide app_names or risk_level filter")
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    queued = []
    devices = [d for d in fetch_inventory()
               if (not site or d["site_name"] == site)
               and (not hostname or d["hostname"] == hostname)]
    for device in devices:
        detail = fetch_device_detail(device["site_name"], device["hostname"])
        for app in detail.get("apps", []):
            name = app.get("name", "")
            if app_names and name not in app_names:
                continue
            if risk and (app.get("risk_level") or "").lower() != risk.lower():
                continue
            key = f"commands/{device['site_name']}/{device['hostname']}/pending.json"
            s3_put(client, key, {
                "command":   "uninstall_app",
                "app_name":  name,
                "issued_at": datetime.datetime.utcnow().isoformat(),
                "issued_by": user["username"],
            })
            queued.append({"hostname": device["hostname"], "app_name": name})
    return JSONResponse({"status": "queued", "count": len(queued), "items": queued})


# ── AI Analysis (Claude API) ──────────────────────────────────────────────────
@app.post("/api/ai/analyze-alert")
async def ai_analyze_alert(request: Request, user=Depends(require_perm("alerts"))):
    """
    Use Claude to generate an AI-powered incident analysis for an alert.
    Requires ANTHROPIC_API_KEY environment variable on Render.
    """
    if not ANTHROPIC_API_KEY:
        raise HTTPException(503, "ANTHROPIC_API_KEY not configured on this server. "
                                  "Add it as a Render environment variable to enable AI analysis.")
    body  = await request.json()
    alert = body.get("alert", {})
    related_events = body.get("related_events", [])

    prompt = f"""You are a cybersecurity analyst reviewing an endpoint detection alert from an SME security platform.

Alert Details:
- Threat/Rule: {alert.get('threat_name', 'Unknown')}
- Severity: {alert.get('severity', 'Unknown')}
- Source: {alert.get('source', 'Unknown')} (defender=Windows Defender, playbook=Detection Rule)
- Device: {alert.get('hostname', 'Unknown')} (Site: {alert.get('site_name', 'Unknown')})
- Detected: {alert.get('detected_at', 'Unknown')}
- Process: {alert.get('process_name', 'Unknown')}
- Command Line: {alert.get('command_line', 'N/A')[:500]}
- MITRE Tactic: {alert.get('mitre_tactic', 'Unknown')}

Related Events (chronological, ±10 min):
{chr(10).join(f"  [{e.get('_delta_secs',0):+.0f}s] {e.get('event_type','')} | {e.get('process_name','')} | {e.get('command_line','')[:120]}" for e in related_events[:10])}

Provide a concise security analysis in this exact JSON format:
{{
  "summary": "One-paragraph plain-English summary of what happened and the threat it represents",
  "severity_assessment": "Your assessment: Critical/High/Medium/Low and why",
  "mitre_techniques": ["T1234 - Technique Name", "..."],
  "attack_stage": "What stage of the attack kill chain this represents",
  "recommended_actions": ["Specific action 1", "Specific action 2", "..."],
  "indicators_to_check": ["File/process/network indicators to look for", "..."],
  "risk_to_business": "Specific risk to an SME pharmacy business"
}}
Return ONLY the JSON object, no markdown fences."""

    try:
        import urllib.request
        req_data = json.dumps({
            "model": "claude-sonnet-4-6",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/messages",
            data=req_data,
            headers={
                "Content-Type":      "application/json",
                "x-api-key":         ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            result = json.loads(resp.read())
        raw_text = result["content"][0]["text"]
        analysis = json.loads(raw_text)
        return JSONResponse({"analysis": analysis})
    except json.JSONDecodeError as e:
        return JSONResponse({"analysis": {"summary": raw_text, "error": "Could not parse structured response"}})
    except Exception as e:
        raise HTTPException(500, f"AI analysis failed: {e}")


# ── Enforcement, Rules, Commands (unchanged, carried forward) ─────────────────
@app.get("/api/enforcement")
async def get_enforcement(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    client = s3()
    if not client:
        return JSONResponse({"global": {}, "sites": {}, "machines": {}})
    return JSONResponse({
        "global":   s3_get(client, f"{ENFORCE_PREFIX}global/policy.json") or {},
        "sites":    {},
        "machines": {},
    })


@app.post("/api/enforcement/global")
async def set_global_enforcement(request: Request, user=Depends(require_perm("commands"))):
    policy = await request.json()
    policy["updated_at"] = datetime.datetime.utcnow().isoformat()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    s3_put(client, f"{ENFORCE_PREFIX}global/policy.json", policy)
    for device in fetch_inventory():
        s3_put(client, f"commands/{device['site_name']}/{device['hostname']}/pending.json",
               {"command": "apply_policy", "policy": policy,
                "issued_at": datetime.datetime.utcnow().isoformat()})
    return JSONResponse({"status": "ok", "scope": "global"})


@app.post("/api/enforcement/site/{site_name}")
async def set_site_enforcement(site_name: str, request: Request,
                                user=Depends(require_perm("commands"))):
    policy = await request.json()
    policy["updated_at"] = datetime.datetime.utcnow().isoformat()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    s3_put(client, f"{ENFORCE_PREFIX}sites/{site_name}/policy.json", policy)
    for device in fetch_inventory():
        if device["site_name"] == site_name:
            s3_put(client, f"commands/{device['site_name']}/{device['hostname']}/pending.json",
                   {"command": "apply_policy", "policy": policy,
                    "issued_at": datetime.datetime.utcnow().isoformat()})
    return JSONResponse({"status": "ok", "scope": "site", "site": site_name})


@app.post("/api/enforcement/machine/{site_name}/{hostname}")
async def set_machine_enforcement(site_name: str, hostname: str, request: Request,
                                   user=Depends(require_perm("commands"))):
    policy = await request.json()
    policy["updated_at"] = datetime.datetime.utcnow().isoformat()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    s3_put(client, f"{ENFORCE_PREFIX}machines/{site_name}/{hostname}/policy.json", policy)
    s3_put(client, f"commands/{site_name}/{hostname}/pending.json",
           {"command": "apply_policy", "policy": policy,
            "issued_at": datetime.datetime.utcnow().isoformat()})
    return JSONResponse({"status": "ok", "scope": "machine", "hostname": hostname})


@app.get("/api/rules")
async def get_rules(request: Request, scope: str = "global",
                     site: Optional[str] = None, hostname: Optional[str] = None):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    client = s3()
    if not client:
        return JSONResponse({"rules": [], "scope": scope})
    if scope == "global":
        key = f"{RULES_PREFIX}global/rules.json"
    elif scope == "site":
        key = f"{RULES_PREFIX}sites/{site}/rules.json"
    else:
        key = f"{RULES_PREFIX}machines/{site}/{hostname}/rules.json"
    data = s3_get(client, key) or {}
    return JSONResponse({"rules": data.get("rules", []), "scope": scope})


def _save_rules(client, rules, scope, site=None, hostname=None):
    if scope == "global":
        key = f"{RULES_PREFIX}global/rules.json"
    elif scope == "site":
        key = f"{RULES_PREFIX}sites/{site}/rules.json"
    else:
        key = f"{RULES_PREFIX}machines/{site}/{hostname}/rules.json"
    s3_put(client, key, {"rules": rules, "updated_at": datetime.datetime.utcnow().isoformat()})
    # Push to affected machines
    for device in fetch_inventory():
        if scope == "global" or \
           (scope == "site" and device["site_name"] == site) or \
           (scope == "machine" and device["site_name"] == site and device["hostname"] == hostname):
            try:
                merged_key = f"{RULES_PREFIX}global/rules.json"
                global_r = (s3_get(client, merged_key) or {}).get("rules", [])
                merged = {r["id"]: r for r in global_r}
                if scope != "global":
                    site_r = (s3_get(client, f"{RULES_PREFIX}sites/{device['site_name']}/rules.json") or {}).get("rules", [])
                    merged.update({r["id"]: r for r in site_r})
                s3_put(client, f"commands/{device['site_name']}/{device['hostname']}/pending.json",
                       {"command": "update_rules", "rules": list(merged.values()),
                        "issued_at": datetime.datetime.utcnow().isoformat()})
            except Exception:
                pass


@app.post("/api/rules")
async def create_rule(request: Request, user=Depends(require_perm("commands")),
                       scope: str = "global", site: Optional[str] = None,
                       hostname: Optional[str] = None):
    body = await request.json()
    bad  = [a for a in body.get("actions", []) if a not in ALLOWED_ACTIONS]
    if bad:
        raise HTTPException(400, f"Unknown actions: {bad}")
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    if scope == "global":
        key = f"{RULES_PREFIX}global/rules.json"
    elif scope == "site":
        key = f"{RULES_PREFIX}sites/{site}/rules.json"
    else:
        key = f"{RULES_PREFIX}machines/{site}/{hostname}/rules.json"
    rules = (s3_get(client, key) or {}).get("rules", [])
    new_rule = {
        "id":           str(uuid.uuid4())[:8],
        "name":         body.get("name", "Unnamed Rule"),
        "description":  body.get("description", ""),
        "severity":     body.get("severity", "MEDIUM"),
        "mitre_tactic": body.get("mitre_tactic", ""),
        "enabled":      body.get("enabled", True),
        "conditions":   body.get("conditions", {}),
        "actions":      body.get("actions", ["alert_only"]),
        "created_at":   datetime.datetime.utcnow().isoformat(),
        "updated_at":   datetime.datetime.utcnow().isoformat(),
        "created_by":   user["username"],
    }
    rules.append(new_rule)
    _save_rules(client, rules, scope, site, hostname)
    return JSONResponse(new_rule, status_code=201)


@app.put("/api/rules/{rule_id}")
async def update_rule(rule_id: str, request: Request,
                       user=Depends(require_perm("commands")),
                       scope: str = "global", site: Optional[str] = None,
                       hostname: Optional[str] = None):
    body = await request.json()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    if scope == "global":
        key = f"{RULES_PREFIX}global/rules.json"
    elif scope == "site":
        key = f"{RULES_PREFIX}sites/{site}/rules.json"
    else:
        key = f"{RULES_PREFIX}machines/{site}/{hostname}/rules.json"
    rules = (s3_get(client, key) or {}).get("rules", [])
    updated = None
    for r in rules:
        if r["id"] == rule_id:
            for k in {"name","description","severity","mitre_tactic","enabled","conditions","actions"}:
                if k in body:
                    r[k] = body[k]
            r["updated_at"] = datetime.datetime.utcnow().isoformat()
            updated = r
            break
    if not updated:
        raise HTTPException(404, f"Rule {rule_id} not found")
    _save_rules(client, rules, scope, site, hostname)
    return JSONResponse(updated)


@app.delete("/api/rules/{rule_id}")
async def delete_rule(rule_id: str, user=Depends(require_perm("commands")),
                       scope: str = "global", site: Optional[str] = None,
                       hostname: Optional[str] = None):
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    if scope == "global":
        key = f"{RULES_PREFIX}global/rules.json"
    elif scope == "site":
        key = f"{RULES_PREFIX}sites/{site}/rules.json"
    else:
        key = f"{RULES_PREFIX}machines/{site}/{hostname}/rules.json"
    rules = (s3_get(client, key) or {}).get("rules", [])
    before = len(rules)
    rules  = [r for r in rules if r["id"] != rule_id]
    if len(rules) == before:
        raise HTTPException(404, f"Rule {rule_id} not found")
    _save_rules(client, rules, scope, site, hostname)
    return JSONResponse({"status": "deleted", "rule_id": rule_id})


# ── Commands ──────────────────────────────────────────────────────────────────
@app.post("/api/command")
async def issue_command(request: Request, user=Depends(require_perm("commands"))):
    body     = await request.json()
    site     = body.get("site_name")
    hostname = body.get("hostname")
    command  = body.get("command")
    if command not in ALLOWED_COMMANDS:
        raise HTTPException(400, f"Command not in allowed list")
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander credentials not configured")
    try:
        client.delete_object(Bucket=ORACLE_BUCKET,
                              Key=f"commands/{site}/{hostname}/last_result.json")
    except Exception:
        pass
    payload = {**body, "issued_at": datetime.datetime.utcnow().isoformat(),
               "issued_by": user["username"]}
    s3_put(client, f"commands/{site}/{hostname}/pending.json", payload)
    return JSONResponse({"status": "queued", "hostname": hostname, "command": command})


@app.get("/api/command_result/{site_name}/{hostname}")
async def get_command_result(site_name: str, hostname: str, request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    client = s3()
    if not client:
        raise HTTPException(503, "Oracle not configured")
    result = s3_get(client, f"commands/{site_name}/{hostname}/last_result.json")
    if result is None:
        return JSONResponse({"status": "pending", "message": "No result yet"})
    return JSONResponse(result)


# ── Overview + Settings ───────────────────────────────────────────────────────
@app.get("/api/overview")
async def get_overview(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    settings = _get_settings()
    offline_threshold_hours = settings.get("offline_threshold_hours", 1)
    offline_days_warning    = settings.get("offline_days_warning", 7)
    mttd_target             = int(settings.get("mttd_target_minutes", 30))
    mttr_target             = int(settings.get("mttr_target_minutes", 120))

    devices  = fetch_inventory()
    alerts   = fetch_all_alerts()
    machines = fetch_status()
    now      = datetime.datetime.utcnow()

    online, offline, long_offline = [], [], []
    for d in devices:
        ls = _parse_utc(d.get("last_seen") or "")
        if ls and (now - ls).total_seconds() / 3600 <= offline_threshold_hours:
            online.append(d)
        else:
            age_h = (now - ls).total_seconds() / 3600 if ls else 9999
            offline.append(d)
            if age_h > offline_days_warning * 24:
                long_offline.append({**d, "offline_days": round(age_h / 24, 1)})

    status_counts = {"New": 0, "Open": 0, "Closed": 0}
    for a in alerts:
        status_counts[a.get("status", "New")] = status_counts.get(a.get("status", "New"), 0) + 1

    mttd_s, mttr_s = [], []
    for a in alerts:
        dt_d = _parse_utc(a.get("detected_at") or a.get("created_at") or "")
        dt_u = _parse_utc(a.get("updated_at") or "")
        if not dt_d or not dt_u:
            continue
        delta = (dt_u - dt_d).total_seconds() / 60
        if delta < 0:
            continue
        if a.get("status") in ("Open", "Closed"):
            mttd_s.append(delta)
        if a.get("status") == "Closed":
            mttr_s.append(delta)

    def _avg(x): return round(sum(x) / len(x), 1) if x else None

    # Severity trend: count by severity for recent alerts (last 30 days)
    cutoff = now - datetime.timedelta(days=30)
    sev_counts = {"Critical": 0, "Severe": 0, "High": 0, "Medium": 0, "Low": 0}
    for a in alerts:
        dt = _parse_utc(a.get("created_at") or "")
        if dt and dt > cutoff:
            sev = (a.get("severity") or "").title()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

    # Alerts per day (last 7 days)
    daily = {}
    for i in range(7):
        day = (now - datetime.timedelta(days=i)).strftime("%Y-%m-%d")
        daily[day] = 0
    for a in alerts:
        dt = _parse_utc(a.get("created_at") or "")
        if dt:
            day = dt.strftime("%Y-%m-%d")
            if day in daily:
                daily[day] += 1
    alerts_trend = [{"date": k, "count": v} for k, v in sorted(daily.items())]

    # Module compliance summary
    module_compliance = {}
    for m in machines:
        for mod, data in m.get("modules", {}).items():
            if mod not in module_compliance:
                module_compliance[mod] = {"compliant": 0, "non_compliant": 0}
            if data.get("compliant"):
                module_compliance[mod]["compliant"] += 1
            elif data.get("compliant") is False:
                module_compliance[mod]["non_compliant"] += 1

    recent_alerts = sorted(
        [a for a in alerts if a.get("status") != "Closed"],
        key=lambda x: x.get("detected_at") or x.get("created_at") or "", reverse=True
    )[:10]

    return JSONResponse({
        "devices":    {"total": len(devices), "online": len(online), "offline": len(offline),
                        "long_offline": long_offline, "warning_days": offline_days_warning,
                        "threshold_hours": offline_threshold_hours},
        "alerts":     {**status_counts, "total": len(alerts),
                        "severity_counts": sev_counts, "trend": alerts_trend},
        "soc":        {"mttd_minutes": _avg(mttd_s), "mttr_minutes": _avg(mttr_s),
                        "sample_count": len(mttd_s), "mttd_target": mttd_target,
                        "mttr_target": mttr_target},
        "modules":    module_compliance,
        "recent_alerts": recent_alerts,
    })


@app.get("/api/settings")
async def get_settings(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    return JSONResponse(_get_settings())


@app.put("/api/settings")
async def update_settings(request: Request, user=Depends(require_perm("settings"))):
    body = await request.json()
    allowed = {"offline_threshold_hours", "offline_days_warning", "org_name",
               "mttd_target_minutes", "mttr_target_minutes", "dashboard_title"}
    settings = _get_settings()
    for k, v in body.items():
        if k in allowed:
            settings[k] = v
    settings["updated_at"] = datetime.datetime.utcnow().isoformat()
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    s3_put(client, SETTINGS_KEY, settings)
    return JSONResponse(settings)


@app.get("/api/agent-schedule")
async def get_agent_schedule(request: Request):
    """Returns the current dashboard-configurable endpoint agent schedule
    (SME-DefenderAudit/DNSAudit/USBLockdown/ProcessMonitor/ThreatReporter/
    TimelineCollector/Reporter/CommandExecutor), merged with defaults for
    any key never explicitly saved."""
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    return JSONResponse(_get_agent_schedule())


@app.put("/api/agent-schedule")
async def update_agent_schedule(request: Request, user=Depends(require_perm("settings"))):
    """Saves the endpoint agent schedule to config/agent_schedule.json in
    Oracle. Every installed SMESecurityAgent service reads this object
    directly on its own cycle (see agent.py) and applies changed
    intervals/enable-toggles live, without a service restart."""
    body = await request.json()
    schedule = _get_agent_schedule()
    for k, v in body.items():
        if k not in DEFAULT_AGENT_SCHEDULE:
            continue
        if isinstance(DEFAULT_AGENT_SCHEDULE[k], bool):
            schedule[k] = bool(v)
        else:
            try:
                iv = int(v)
            except (TypeError, ValueError):
                raise HTTPException(400, f"'{k}' must be a whole number")
            floor = AGENT_SCHEDULE_MIN.get(k, 1)
            if iv < floor:
                raise HTTPException(400, f"'{k}' must be at least {floor}")
            schedule[k] = iv
    schedule["updated_at"] = datetime.datetime.utcnow().isoformat()
    schedule["updated_by"] = user["username"]
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    s3_put(client, AGENT_SCHEDULE_KEY, schedule)
    return JSONResponse(schedule)


@app.post("/api/alerts/webhook")
async def alert_webhook(request: Request, background_tasks: BackgroundTasks):
    alert = await request.json()
    if process_and_forward:
        background_tasks.add_task(process_and_forward, alert)
    return JSONResponse({"status": "success"})


@app.get("/health")
async def health():
    return {"status": "ok",
            "oracle": bool(ORACLE_S3_ENDPOINT and ORACLE_ACCESS_KEY and ORACLE_BUCKET),
            "commander": bool(ORACLE_COMMANDER_ACCESS_KEY and ORACLE_COMMANDER_SECRET_KEY),
            "ai": bool(ANTHROPIC_API_KEY)}


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")
