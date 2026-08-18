# -*- coding: utf-8 -*-
"""
SME Security Dashboard — Server v2.0
Includes: Auth (PBKDF2+HMAC, roles), App Management, Bulk Alerts,
          Alert Correlation, AI Analysis (Claude API), layered Enforcement,
          Detection Rules, Timeline, Overview stats.
"""

import asyncio
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
RETENTION_POLICY_KEY   = "config/retention_policy.json"
RETENTION_LAST_RUN_KEY = "config/retention_last_run.json"
AI_SETTINGS_KEY = "config/ai_settings.json"
ORGANIZATIONS_KEY = "config/organizations.json"

# Model choices surfaced in the Settings UI dropdown. Anthropic's current
# lineup as of this build — see https://docs.claude.com/en/docs/about-claude/models
# for the authoritative, up-to-date list; verify there before adding a new
# entry, since model strings change with each release and a stale one will
# just fail at call time with a clear API error.
AI_MODEL_CHOICES = [
    {"id": "claude-sonnet-5",              "label": "Claude Sonnet 5 (recommended — balanced quality/cost)"},
    {"id": "claude-opus-4-8",              "label": "Claude Opus 4.8 (most capable, higher cost)"},
    {"id": "claude-haiku-4-5-20251001",    "label": "Claude Haiku 4.5 (fastest, cheapest)"},
    {"id": "claude-fable-5",               "label": "Claude Fable 5 (frontier — Mythos-tier, may require Anthropic access)"},
]
DEFAULT_AI_SETTINGS = {"model": "claude-sonnet-5", "api_key": ""}

ALLOWED_COMMANDS = {
    "force_audit", "force_report", "force_update_check", "enable_enforcement", "disable_enforcement",
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

# ── Retention Policy ──────────────────────────────────────────────────────────
# One JSON object in Oracle (RETENTION_POLICY_KEY) drives retention on BOTH
# sides of the system:
#   - Cloud side (archive/ historical report snapshots, Closed alerts) is
#     swept by THIS dashboard backend (main.py — it's the only side holding
#     delete-capable "commander" Oracle credentials). See run_retention_sweep().
#   - Endpoint side (agent.log/usb_events.log/process_monitor.log rotation,
#     quarantined-file pruning) is applied locally by each SMESecurityAgent
#     service, which reads this same object directly from Oracle with its
#     own read-only credentials (same pattern as config/agent_schedule.json —
#     see agent.py fetch_remote_retention_policy()). The dashboard never
#     reaches into an endpoint's local disk; it can only tell the agent what
#     policy to self-enforce.
#
# Deleting data is destructive, so — mirroring this platform's existing
# "audit-only by default, enforcement requires explicit admin opt-in" rule —
# retention starts OFF (enabled: False) until an admin turns it on.
#
# "age_days" and "max_size_gb" are independent triggers: leave either blank
# (None/0) to disable it, set one, or set both — an object/file is eligible
# for the configured action the moment EITHER condition it has is met.
#
# Closed-only safety rail: cloud_alerts retention only ever touches alerts
# with status == "Closed" — New/Open alerts are never deleted or moved by
# this policy no matter how old they are or how much space they use.
#
# "move" is only meaningful for cloud targets (archive/ objects, Closed
# alerts) — they get copied to move_destination (any S3-compatible bucket:
# another Oracle bucket, AWS S3, or an on-prem MinIO/S3-compatible server)
# and only removed from the primary bucket after a successful copy.
# Endpoint targets (logs, quarantine) don't support "move" — there's no
# generically safe way to ship arbitrary destination credentials to every
# installed PC — so endpoint retention is always local rotate/delete,
# independently gated by delete_from_endpoint.
DEFAULT_RETENTION_POLICY = {
    "enabled":              False,
    "age_days":             None,   # e.g. 90 — objects/files older than this are eligible
    "max_size_gb":          None,   # e.g. 5 — oldest-first eligible once the target's total exceeds this
    "targets": {
        "cloud_reports":      True,   # archive/ — historical per-run report snapshots (NOT reports/latest.json, which is always current and never touched)
        "cloud_alerts":       True,   # alerts/ — Closed alerts only (see safety rail above)
        "endpoint_logs":      True,   # agent.log, usb_events.log, process_monitor.log on each PC
        "endpoint_quarantine": True,  # quarantined files under C:\ProgramData\CustomSec\Quarantine on each PC
    },
    "action":               "delete",  # "delete" | "move" — applies to cloud targets only, see above
    "delete_from_cloud":    True,      # master switch: touch cloud_reports/cloud_alerts at all
    "delete_from_endpoint": True,      # master switch: touch endpoint_logs/endpoint_quarantine at all
    "move_destination": {
        "endpoint":   "",  # e.g. https://<namespace>.compat.objectstorage.<region>.oraclecloud.com, or an on-prem MinIO URL
        "access_key": "",
        "secret_key": "",  # write-only: never returned by GET, see _get_retention_policy()
        "bucket":     "",
        "region":     "us-ashburn-1",
        "prefix":     "retained/",
    },
    "sweep_interval_hours": 24,  # how often the dashboard opportunistically re-runs the cloud sweep
}

# Update Management policy — layered the same way as everything above
# (OEM-global default at UPDATE_POLICY_KEY, optional per-site override at
# {stem}/sites/{site}.json), and read directly by each endpoint agent —
# see agent.py's UpdatePolicyStore / update_checker.py. Defender signature
# auto-update defaults ON (pure defense benefit, no compatibility risk);
# Windows Update and app auto-install both default OFF, matching this
# platform's "audit-only until explicit admin opt-in" rule for anything
# that can actually break a machine. Mirrors update_checker.py's own
# DEFAULT_POLICY exactly — keep the two in sync if either changes.
UPDATE_POLICY_KEY = "config/update_policy.json"
DEFAULT_UPDATE_POLICY = {
    "defender_signatures": {
        "enabled": True, "max_age_hours": 24, "auto_update": True,
    },
    "windows_updates": {
        "enabled": True, "auto_install": False,
        "categories": ["Critical", "Important"],   # severities eligible for auto_install — Feature/Upgrade updates are NEVER auto-installed regardless
        "maintenance_window": None,                # {"days": ["Sat","Sun"], "start": "02:00", "end": "05:00"} local time, or None = no restriction
        "auto_reboot": False,
    },
    "app_updates": {
        "enabled": True, "auto_update": False,
        "allow_list": [],   # winget package IDs explicitly approved for auto-update — nothing updates just because winget offers it
    },
}
ALLOWED_ACTIONS = [
    "alert_only", "kill_process", "isolate_host",
    "block_network", "collect_forensics",
]
LATEST_SUFFIX = "/latest.json"
TOKEN_EXPIRY  = 24 * 3600  # 24 h

_CACHE: Dict[str, dict] = {}
_CACHE_TTL = 20
_retention_sweep_running = False


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
    "reader":    {"read"},
    "analyst":   {"read", "alerts"},
    "admin":     {"read", "alerts", "users", "apps", "commands", "settings"},
    # OEM-level superadmin: every permission an "admin" has, PLUS "orgs" —
    # the ability to onboard/suspend organizations and create users (of any
    # role, including other oem_admins) in any of them. The single
    # structural difference from "admin" is site scope, not permissions:
    # an oem_admin's site_name is None, which _scope_site()/_enforce_site()
    # below treat as "no restriction" everywhere data or config is
    # filtered by site. A site-scoped "admin" has every permission an
    # oem_admin does EXCEPT "orgs", but every one of those permissions is
    # still confined to their own site_name by the same two helpers.
    "oem_admin": {"read", "alerts", "users", "apps", "commands", "settings", "orgs"},
}
# Roles that MUST belong to exactly one site (organization). oem_admin is
# the only role with site_name == None, meaning "every site."
SITE_SCOPED_ROLES = {"reader", "analyst", "admin"}


def _scope_site(user: dict) -> Optional[str]:
    """The single site_name a user's data/config access is confined to, or
    None for an oem_admin (unrestricted — sees and manages every site).
    This is the one function nearly every multi-tenant check in this file
    ultimately calls."""
    return None if user.get("role") == "oem_admin" else user.get("site_name")


def _enforce_site(user: dict, site_name: Optional[str], what: str = "this resource"):
    """Raises 403 if a site-scoped user is trying to touch a site that
    isn't their own. oem_admin always passes. A scoped user with no
    site_name at all (a misconfigured account) is denied by default —
    fail closed, never fail open on a missing scope."""
    scope = _scope_site(user)
    if scope is None:
        return
    if not site_name or site_name != scope:
        raise HTTPException(403, f"'{user['username']}' is restricted to site '{scope}' and cannot access {what} for '{site_name or '(unspecified)'}'")


def _filter_by_site(user: dict, items: list, key: str = "site_name") -> list:
    """Filters a list of dicts down to the caller's site; returns the list
    unchanged for an oem_admin."""
    scope = _scope_site(user)
    if scope is None:
        return items
    return [i for i in items if i.get(key) == scope]


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


def _make_token(username: str, role: str, site_name: Optional[str]) -> str:
    ts = str(int(time.time()))
    payload = f"{username}:{role}:{site_name or ''}:{ts}"
    sig = _hmac.new(_get_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.b64encode(f"{payload}:{sig}".encode()).decode()


def _verify_token(token: str) -> Optional[dict]:
    try:
        raw = base64.b64decode(token.encode()).decode()
        payload, sig = raw.rsplit(":", 1)
        expected = _hmac.new(_get_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not _hmac.compare_digest(sig, expected):
            return None
        username, role, site_name, ts = payload.split(":")
        if int(time.time()) - int(ts) > TOKEN_EXPIRY:
            return None
        return {"username": username, "role": role, "site_name": site_name or None,
                "perms": list(ROLE_PERMS.get(role, set()))}
    except Exception:
        return None


def _load_users() -> list:
    client = s3()
    if not client:
        return []
    data = s3_get(client, AUTH_USERS_KEY) or {}
    users = data.get("users", [])
    # Bootstrap: create the default OEM superadmin if no users exist yet.
    # site_name is intentionally None — this is the OEM's own account, not
    # tied to any one customer organization.
    if not users:
        default_pw = DASHBOARD_ADMIN_KEY or "Admin@1234!"
        users = [{"username": "admin", "role": "oem_admin", "site_name": None,
                   "password_hash": _hash_pw(default_pw),
                   "email": "", "created_at": datetime.datetime.utcnow().isoformat()}]
        s3_put(client, AUTH_USERS_KEY, {"users": users})
    return users


def _save_users(users: list):
    client = s3(commander=True)
    if client:
        s3_put(client, AUTH_USERS_KEY, {"users": users})


SITE_SLUG_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{1,63}$")


def _load_orgs() -> list:
    client = s3()
    if not client:
        return []
    return (s3_get(client, ORGANIZATIONS_KEY) or {}).get("organizations", [])


def _save_orgs(orgs: list):
    client = s3(commander=True)
    if client:
        s3_put(client, ORGANIZATIONS_KEY, {"organizations": orgs})


def _find_org(site_name: str) -> Optional[dict]:
    return next((o for o in _load_orgs() if o["site_name"] == site_name), None)


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
        if module == "enforcement":
            # Surfaced at the top level (not just modules.enforcement) since
            # the Enforcement page needs this for every machine in one
            # cheap /api/status call, not a per-device fetch_device_detail
            # round-trip. See agent.py task_defender_dns — this is the only
            # place the live agent_config.json enforce toggle gets reported
            # centrally.
            machines[mk]["enforce"] = raw.get("enforce")
            machines[mk]["enforce_checked_at"] = raw.get("timestamp")
        if module == "updates":
            # Same idea as enforcement above — the Updates page needs a
            # per-machine summary (signature age, WU pending/critical
            # count, pending reboot, app upgrades available) for every
            # device in one /api/status call. See update_checker.py for
            # the full nested detail this is extracted from; the complete
            # raw payload is still available via fetch_device_detail's
            # modules.updates.raw for the per-device drill-down.
            ds = raw.get("defender_signatures") or {}
            wu = raw.get("windows_updates") or {}
            au = raw.get("app_updates") or {}
            machines[mk]["updates_summary"] = {
                "checked_at": raw.get("timestamp"),
                "signature_age_hours":    ds.get("signature_age_hours"),
                "signature_compliant":    ds.get("compliant"),
                "wu_pending_count":       wu.get("pending_count"),
                "wu_critical_count":      wu.get("critical_pending_count"),
                "wu_pending_reboot":      wu.get("pending_reboot"),
                "app_upgrade_count":      au.get("upgrade_count"),
                "app_approved_pending":   au.get("approved_pending_count"),
            }
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


# ── Static Detection Knowledge Base ────────────────────────────────────────
# Gives EVERY alert a baseline Description, linked MITRE ATT&CK technique,
# and a Next Steps checklist the instant it's created — no AI dependency,
# no API cost, works even with ANTHROPIC_API_KEY unset. This is layer 1 of
# two; layer 2 (optional, see _auto_generate_ai_analysis below) adds a
# richer Claude-generated analysis on top when a key IS configured, but
# nothing in the platform should ever show an analyst a bare, unexplained
# alert just because that key is missing or the API call failed.
#
# Playbook rules (rules/*.json, user-authored) already carry a free-text
# mitre_tactic field like "T1003.006 - DCSync" — MITRE_ID_RE below pulls
# the technique ID out of that string, so any rule an admin writes gets
# real KB coverage automatically as long as they fill in a valid ID.
# Built-in Defender/AV detections don't carry MITRE natively, so
# DEFENDER_CATEGORY_TECHNIQUE maps Microsoft's threat Category names to a
# representative technique instead.
MITRE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")

MITRE_TECHNIQUES = {
    "T1003":     {"name": "OS Credential Dumping",                    "family": "credential_theft"},
    "T1003.006": {"name": "DCSync",                                    "family": "credential_theft"},
    "T1110":     {"name": "Brute Force",                               "family": "credential_access"},
    "T1110.001": {"name": "Password Guessing",                        "family": "credential_access"},
    "T1059":     {"name": "Command and Scripting Interpreter",        "family": "execution"},
    "T1059.001": {"name": "PowerShell",                               "family": "execution"},
    "T1204":     {"name": "User Execution",                           "family": "execution"},
    "T1204.002": {"name": "Malicious File",                           "family": "execution"},
    "T1203":     {"name": "Exploitation for Client Execution",        "family": "execution"},
    "T1055":     {"name": "Process Injection",                        "family": "defense_evasion"},
    "T1027":     {"name": "Obfuscated Files or Information",          "family": "defense_evasion"},
    "T1112":     {"name": "Modify Registry",                          "family": "defense_evasion"},
    "T1562":     {"name": "Impair Defenses",                          "family": "defense_evasion"},
    "T1562.001": {"name": "Disable or Modify Tools",                  "family": "defense_evasion"},
    "T1486":     {"name": "Data Encrypted for Impact",                "family": "ransomware"},
    "T1490":     {"name": "Inhibit System Recovery",                  "family": "ransomware"},
    "T1547":     {"name": "Boot or Logon Autostart Execution",        "family": "persistence"},
    "T1547.001": {"name": "Registry Run Keys / Startup Folder",       "family": "persistence"},
    "T1053":     {"name": "Scheduled Task/Job",                       "family": "persistence"},
    "T1053.005": {"name": "Scheduled Task",                           "family": "persistence"},
    "T1136":     {"name": "Create Account",                           "family": "persistence"},
    "T1098":     {"name": "Account Manipulation",                     "family": "persistence"},
    "T1078":     {"name": "Valid Accounts",                           "family": "initial_access"},
    "T1021":     {"name": "Remote Services",                          "family": "lateral_movement"},
    "T1021.001": {"name": "Remote Desktop Protocol",                  "family": "lateral_movement"},
    "T1210":     {"name": "Exploitation of Remote Services",          "family": "lateral_movement"},
    "T1071":     {"name": "Application Layer Protocol",               "family": "c2"},
    "T1071.001": {"name": "Web Protocols",                            "family": "c2"},
    "T1105":     {"name": "Ingress Tool Transfer",                    "family": "c2"},
    "T1074":     {"name": "Data Staged",                              "family": "exfiltration"},
    "T1041":     {"name": "Exfiltration Over C2 Channel",             "family": "exfiltration"},
    "T1052":     {"name": "Exfiltration Over Physical Medium",        "family": "exfiltration"},
    "T1052.001": {"name": "Exfiltration Over USB",                    "family": "exfiltration"},
    "T1005":     {"name": "Data from Local System",                  "family": "collection"},
    "T1057":     {"name": "Process Discovery",                        "family": "discovery"},
    "T1082":     {"name": "System Information Discovery",             "family": "discovery"},
    "T1018":     {"name": "Remote System Discovery",                  "family": "discovery"},
    "T1046":     {"name": "Network Service Discovery",                "family": "discovery"},
}

# Maps Microsoft Defender's ThreatName Category (case-insensitive substring
# match against category/threat_name) to a representative MITRE technique
# for detections that only ever come from the AV engine, not a playbook rule.
DEFENDER_CATEGORY_TECHNIQUE = {
    "ransom": "T1486", "trojandownloader": "T1105", "trojandropper": "T1105",
    "trojan": "T1204.002", "backdoor": "T1071", "hacktool": "T1059",
    "pws": "T1003", "exploit": "T1203", "worm": "T1210",
    "virtool": "T1027", "spyware": "T1005",
}

FAMILY_NEXT_STEPS = {
    "credential_theft": [
        "Reset the affected user's password and any local administrator passwords on this host.",
        "If this is a domain controller, double-reset the krbtgt account password (invalidates any forged Kerberos tickets).",
        "Review Windows Event ID 4662 (Directory Service Access) and 4624 (Logon) for the source account and host.",
        "Isolate the source host until credential exposure is ruled out.",
    ],
    "credential_access": [
        "Lock or reset the targeted account after repeated failures.",
        "Review the source IP/host for the failed attempts — block it if external and unexpected.",
        "Confirm an account lockout policy is in place.",
        "Check for a subsequent successful logon from the same source shortly after.",
    ],
    "ransomware": [
        "Isolate the affected host immediately to stop encryption from spreading to shares or other devices.",
        "Identify and preserve Volume Shadow Copies / backups before taking further action.",
        "Check other hosts on the same site for the same file or process signature.",
        "Do not pay or negotiate without involving legal/insurance guidance.",
    ],
    "persistence": [
        "Review the referenced registry key, scheduled task, or startup entry for legitimacy.",
        "Remove the persistence mechanism only after confirming it's malicious.",
        "Check for other persistence artifacts left by the same actor or tooling.",
        "Reset credentials for any account used to create the persistence.",
    ],
    "execution": [
        "Review the full command line for obfuscation, encoded payloads, or unusual flags.",
        "Confirm whether the parent process is a legitimate application (browser, email client, Office) or a delivery mechanism.",
        "Quarantine or block the executable if it's confirmed malicious.",
        "Check the Timeline tab for what ran immediately before and after this event.",
    ],
    "defense_evasion": [
        "Verify Windows Defender / AV is still enabled and hasn't been tampered with on this host.",
        "Check for unsigned or newly-dropped binaries alongside the flagged process.",
        "Review scheduled tasks and services created around the same time.",
        "Run a Force Audit on this device (Live Status) after remediation to confirm a clean state.",
    ],
    "c2": [
        "Block the destination IP/domain at the network or DNS level.",
        "Isolate the host to cut off command-and-control communication.",
        "Identify what data, if any, was transferred before detection.",
        "Check other hosts for connections to the same destination.",
    ],
    "exfiltration": [
        "Identify what data was accessed or copied before the event.",
        "If USB-related, review the USB Lockdown log for the device serial and files copied.",
        "Notify appropriate stakeholders per your data-breach policy.",
        "Revoke access for the account involved pending investigation.",
    ],
    "collection": [
        "Identify what data the process accessed before detection.",
        "Check for evidence of exfiltration (outbound connections, USB activity) around the same time.",
        "Notify stakeholders per your data-handling policy if sensitive data was involved.",
    ],
    "lateral_movement": [
        "Check whether the same credentials were used to access other hosts.",
        "Review firewall/RDP logs for the source and destination hosts.",
        "Restrict or disable the account used until confirmed legitimate.",
        "Segment or isolate the destination host if compromise is suspected.",
    ],
    "initial_access": [
        "Confirm whether this login/account use was expected (travel, new device, etc.).",
        "Enable or verify MFA for the account if not already required.",
        "Reset the account password if unauthorized use is suspected.",
        "Review recent activity for the account across all monitored hosts.",
    ],
    "discovery": [
        "Discovery activity alone is often a precursor — review what ran immediately afterward in the Timeline tab.",
        "Confirm whether the user/process performing discovery is expected admin activity.",
        "Watch this host closely for follow-on lateral-movement or execution alerts.",
    ],
}
GENERIC_NEXT_STEPS = [
    "Review the process, command line, and user involved in the Alert Details.",
    "Check the Timeline tab for related activity on this device around the same time.",
    "Escalate to Open if this needs investigation, or Close if confirmed benign.",
    "Consider a Force Audit on this device once remediated.",
]


def _mitre_lookup(tech_id: str) -> Optional[dict]:
    info = MITRE_TECHNIQUES.get(tech_id)
    if not info and "." in tech_id:
        info = MITRE_TECHNIQUES.get(tech_id.split(".")[0])
    return info


def enrich_alert(alert: dict) -> dict:
    """Layer 1: fills description / mitre_technique_id / mitre_technique_name
    / mitre_url / next_steps from the static knowledge base above. Called
    once when an alert is first created (see get_all_alerts); idempotent —
    if the alert already has these fields (from a prior enrichment, or an
    AI analysis that refined them) it's left untouched."""
    if alert.get("mitre_technique_id") is not None and alert.get("next_steps"):
        return alert

    tech_id = None
    m = MITRE_ID_RE.search(alert.get("mitre_tactic") or "")
    if m:
        tech_id = m.group(0)
    if not tech_id and (alert.get("source") or "").startswith("defender"):
        cat = (alert.get("category") or alert.get("threat_name") or "").lower()
        for key, tid in DEFENDER_CATEGORY_TECHNIQUE.items():
            if key in cat:
                tech_id = tid
                break

    info = _mitre_lookup(tech_id) if tech_id else None
    family = info["family"] if info else None
    steps = FAMILY_NEXT_STEPS.get(family, GENERIC_NEXT_STEPS)

    hostname = alert.get("hostname") or "this device"
    threat = alert.get("threat_name") or "a security event"
    process = alert.get("process_name")
    who = f" involving {process}" if process else ""
    tech_phrase = f" (MITRE {tech_id} - {info['name']})" if info else ""
    description = (f"{threat}{tech_phrase} was detected on {hostname}{who}. "
                   f"Severity: {alert.get('severity') or 'MEDIUM'}. Source: {alert.get('source') or 'unknown'}.")

    alert["description"]          = alert.get("description") or description
    alert["mitre_technique_id"]   = tech_id or ""
    alert["mitre_technique_name"] = info["name"] if info else ""
    alert["mitre_url"]            = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/" if tech_id else ""
    alert["next_steps"]           = alert.get("next_steps") or steps
    return alert


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
                   "playbook_alerts", "timeline", "enforcement", "updates"]
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
                "parent_pid":   evt.get("parent_pid"),
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


def _site_override_key(base_key: str, site_name: str) -> str:
    """Given an OEM-global config key like 'config/agent_schedule.json',
    returns the per-site override key 'config/agent_schedule/sites/{site}.json'.
    Used consistently by settings/agent-schedule/retention-policy so a
    site's override always lives right alongside its global default."""
    stem = base_key[:-5] if base_key.endswith(".json") else base_key
    return f"{stem}/sites/{site_name}.json"


def _get_settings(site_name: Optional[str] = None) -> dict:
    """OEM-global dashboard settings (org_name/offline thresholds/MTTD-MTTR
    targets), with an optional per-site override layered on top. Every
    field an org's admin hasn't explicitly overridden falls back to the
    OEM default, so a brand-new organization is fully configured from
    the moment it's onboarded."""
    client = s3()
    global_doc = (s3_get(client, SETTINGS_KEY) or {}) if client else {}
    merged = dict(global_doc)
    site_doc = {}
    if site_name and client:
        site_doc = s3_get(client, _site_override_key(SETTINGS_KEY, site_name)) or {}
        merged.update(site_doc)
    merged["is_site_override"] = bool(site_doc)
    return merged


def _get_agent_schedule(site_name: Optional[str] = None) -> dict:
    """Merges DEFAULT_AGENT_SCHEDULE with the OEM-global doc, then — if
    site_name is given — that site's own override doc on top of that, so
    the response always contains every known key even before anyone has
    saved anything. Endpoint agents read the raw Oracle objects directly
    (global always, plus their own site's override — see agent.py
    fetch_remote_schedule/fetch_remote_site_schedule) rather than calling
    this API, so it stays available even if Render is asleep; this
    function only backs the dashboard UI's own view/edit of it."""
    client = s3()
    global_doc = (s3_get(client, AGENT_SCHEDULE_KEY) or {}) if client else {}
    merged = dict(DEFAULT_AGENT_SCHEDULE)
    merged.update({k: v for k, v in global_doc.items() if k in DEFAULT_AGENT_SCHEDULE})
    site_doc = {}
    if site_name and client:
        site_doc = s3_get(client, _site_override_key(AGENT_SCHEDULE_KEY, site_name)) or {}
        merged.update({k: v for k, v in site_doc.items() if k in DEFAULT_AGENT_SCHEDULE})
    src = site_doc or global_doc
    merged["updated_at"] = src.get("updated_at")
    merged["updated_by"] = src.get("updated_by")
    merged["is_site_override"] = bool(site_doc)
    return merged


def _get_update_policy(site_name: Optional[str] = None) -> dict:
    """Merges DEFAULT_UPDATE_POLICY with the OEM-global doc, then — if
    site_name is given — that site's own override doc on top, one level
    deep per named section (defender_signatures/windows_updates/
    app_updates), same layering as everywhere else. Endpoint agents read
    the raw Oracle objects directly (see agent.py's UpdatePolicyStore);
    this function only backs the dashboard UI."""
    client = s3()
    global_doc = (s3_get(client, UPDATE_POLICY_KEY) or {}) if client else {}
    merged = json.loads(json.dumps(DEFAULT_UPDATE_POLICY))  # deep copy
    for section in ("defender_signatures", "windows_updates", "app_updates"):
        if isinstance(global_doc.get(section), dict):
            merged[section].update(global_doc[section])
    site_doc = {}
    if site_name and client:
        site_doc = s3_get(client, _site_override_key(UPDATE_POLICY_KEY, site_name)) or {}
        for section in ("defender_signatures", "windows_updates", "app_updates"):
            if isinstance(site_doc.get(section), dict):
                merged[section].update(site_doc[section])
    src = site_doc or global_doc
    merged["updated_at"] = src.get("updated_at")
    merged["updated_by"] = src.get("updated_by")
    merged["is_site_override"] = bool(site_doc)
    return merged


def _get_ai_settings(redact: bool = True) -> dict:
    """Merges DEFAULT_AI_SETTINGS with whatever's saved to Oracle. With
    redact=True (the GET-endpoint default) api_key is stripped and replaced
    with a has_api_key flag, same write-only/sticky pattern as the
    retention policy's move-destination secret — never sent back to the
    browser after being saved."""
    client = s3()
    stored = (s3_get(client, AI_SETTINGS_KEY) or {}) if client else {}
    merged = dict(DEFAULT_AI_SETTINGS)
    merged.update({k: v for k, v in stored.items() if k in DEFAULT_AI_SETTINGS})
    merged["updated_at"] = stored.get("updated_at")
    merged["updated_by"] = stored.get("updated_by")
    if redact:
        merged["has_api_key"] = bool(merged.get("api_key")) or bool(ANTHROPIC_API_KEY)
        merged["api_key"] = ""
    return merged


def _resolve_ai_config() -> tuple:
    """Returns (model, api_key) to actually use for a Claude API call. A
    key/model saved in Settings takes precedence over the ANTHROPIC_API_KEY
    Render environment variable, so an admin can configure or rotate the
    key from the dashboard without touching Render at all — but the env
    var still works as a zero-config default if nothing's been saved."""
    settings = _get_ai_settings(redact=False)
    model = (settings.get("model") or "").strip() or DEFAULT_AI_SETTINGS["model"]
    api_key = settings.get("api_key") or ANTHROPIC_API_KEY
    return model, api_key


def _merge_retention_doc(merged: dict, doc: dict):
    """Applies one retention-policy JSON doc (global or site override) onto
    an in-progress merged dict, in place — shared by both layers so
    _get_retention_policy's global-then-site pass uses identical logic."""
    for k, v in doc.items():
        if k == "targets" and isinstance(v, dict):
            merged["targets"].update({tk: bool(tv) for tk, tv in v.items() if tk in merged["targets"]})
        elif k == "move_destination" and isinstance(v, dict):
            merged["move_destination"].update({dk: dv for dk, dv in v.items() if dk in merged["move_destination"]})
        elif k in merged:
            merged[k] = v


def _get_retention_policy(redact: bool = True, site_name: Optional[str] = None) -> dict:
    """Merges DEFAULT_RETENTION_POLICY with the OEM-global doc, then — if
    site_name is given — that site's own override doc on top. With
    redact=True (the GET-endpoint default) the destination secret key is
    stripped and replaced with a has_secret flag so it's never sent back
    to the browser after being saved; internal callers (the sweep itself,
    PUT's merge-before-save) use redact=False to get the real value."""
    client = s3()
    global_doc = (s3_get(client, RETENTION_POLICY_KEY) or {}) if client else {}
    merged = json.loads(json.dumps(DEFAULT_RETENTION_POLICY))  # deep copy
    _merge_retention_doc(merged, global_doc)
    site_doc = {}
    if site_name and client:
        site_doc = s3_get(client, _site_override_key(RETENTION_POLICY_KEY, site_name)) or {}
        _merge_retention_doc(merged, site_doc)
    src = site_doc or global_doc
    merged["updated_at"] = src.get("updated_at")
    merged["updated_by"] = src.get("updated_by")
    merged["is_site_override"] = bool(site_doc)
    if redact:
        has_secret = bool(merged["move_destination"].get("secret_key"))
        merged["move_destination"]["secret_key"] = ""
        merged["move_destination"]["has_secret"] = has_secret
    return merged


def _get_retention_last_run(site_name: Optional[str] = None) -> Optional[dict]:
    client = s3()
    if not client:
        return None
    if site_name:
        return s3_get(client, _site_override_key(RETENTION_LAST_RUN_KEY, site_name))
    return s3_get(client, RETENTION_LAST_RUN_KEY)


def _s3_client_for(dest: dict):
    """Builds a boto3 client for an arbitrary S3-compatible retention
    move-destination (another Oracle bucket, AWS S3, or an on-prem
    MinIO/S3-compatible server) — anything with an endpoint URL and keys."""
    if not dest or not all(dest.get(k) for k in ("endpoint", "access_key", "secret_key", "bucket")):
        return None
    try:
        return boto3.client(
            "s3", endpoint_url=dest["endpoint"],
            aws_access_key_id=dest["access_key"], aws_secret_access_key=dest["secret_key"],
            region_name=dest.get("region") or "us-east-1",
            config=Config(signature_version="s3v4", connect_timeout=10, read_timeout=60,
                           retries={"max_attempts": 2, "mode": "standard"}),
        )
    except Exception:
        return None


def _retention_eligible(objs: list, cutoff: Optional[datetime.datetime], size_budget: Optional[int]) -> list:
    """objs: list of {"Key","Size","LastModified"} dicts (as returned by
    list_prefix). Returns the subset eligible for the retention action —
    the union of "older than cutoff" and, if the target's total size
    exceeds size_budget, the oldest objects needed to bring it back under
    budget. Oldest-first throughout."""
    objs = sorted(objs, key=lambda o: o["LastModified"])
    eligible_keys = set()
    eligible = []
    if cutoff:
        for o in objs:
            lm = o["LastModified"]
            lm = lm.replace(tzinfo=None) if lm.tzinfo else lm
            if lm < cutoff:
                eligible_keys.add(o["Key"])
                eligible.append(o)
    if size_budget:
        total = sum(o["Size"] for o in objs)
        if total > size_budget:
            running = total
            for o in objs:
                if running <= size_budget:
                    break
                if o["Key"] not in eligible_keys:
                    eligible_keys.add(o["Key"])
                    eligible.append(o)
                running -= o["Size"]
    return eligible


def _sweep_prefix(client, dest_client, dest_cfg: dict, prefix: str, cutoff, size_budget,
                   move: bool, stat: dict, cap: int = 2000):
    objs = list_prefix(client, prefix)
    stat["scanned"] = len(objs)
    eligible = _retention_eligible(objs, cutoff, size_budget)[:cap]
    stat["matched"] = len(eligible)
    dest_bucket = dest_cfg.get("bucket") if dest_cfg else None
    dest_prefix = (dest_cfg or {}).get("prefix", "")
    for o in eligible:
        key = o["Key"]
        try:
            if move and dest_client and dest_bucket:
                body = client.get_object(Bucket=ORACLE_BUCKET, Key=key)["Body"].read()
                dest_client.put_object(Bucket=dest_bucket, Key=f"{dest_prefix}{key}", Body=body)
                client.delete_object(Bucket=ORACLE_BUCKET, Key=key)
                stat["moved"] += 1
            else:
                client.delete_object(Bucket=ORACLE_BUCKET, Key=key)
                stat["deleted"] += 1
            stat["bytes_freed"] += o.get("Size", 0)
        except Exception:
            stat["errors"] += 1


def _sweep_alerts(client, dest_client, dest_cfg: dict, alerts_prefix: str, cutoff, size_budget,
                   move: bool, stat: dict, cap: int = 500):
    """Same eligibility logic as _sweep_prefix, but every candidate is
    fetched and MUST have status=='Closed' before it's touched — New/Open
    alerts are never deleted or moved by retention, regardless of age or
    size pressure. Capped lower than _sweep_prefix (500 vs 2000) because,
    unlike report objects, checking status requires an extra GET per
    candidate. alerts_prefix is ALERTS_PREFIX for an unscoped/legacy sweep,
    or 'alerts/{site_name}/' to sweep one organization only."""
    objs = list_prefix(client, alerts_prefix)
    stat["scanned"] = len(objs)
    candidates = _retention_eligible(objs, cutoff, size_budget)[:cap]
    dest_bucket = dest_cfg.get("bucket") if dest_cfg else None
    dest_prefix = (dest_cfg or {}).get("prefix", "")
    for o in candidates:
        key = o["Key"]
        try:
            alert = json.loads(client.get_object(Bucket=ORACLE_BUCKET, Key=key)["Body"].read())
        except Exception:
            stat["errors"] += 1
            continue
        if alert.get("status") != "Closed":
            continue
        try:
            if move and dest_client and dest_bucket:
                dest_client.put_object(Bucket=dest_bucket, Key=f"{dest_prefix}{key}",
                                        Body=json.dumps(alert).encode("utf-8"))
                client.delete_object(Bucket=ORACLE_BUCKET, Key=key)
                stat["moved"] += 1
            else:
                client.delete_object(Bucket=ORACLE_BUCKET, Key=key)
                stat["deleted"] += 1
            stat["matched"] += 1
            stat["bytes_freed"] += o.get("Size", 0)
        except Exception:
            stat["errors"] += 1
    cache_bust("alerts")


def _sweep_one_site(client, policy: dict, site_name: Optional[str]) -> dict:
    """Runs the cloud sweep for a single site's (or, if site_name is None,
    the flat legacy/unscoped) archive+alerts data using that layer's
    effective policy. Returns the summary dict; does NOT persist it —
    callers decide where (global key, per-site key, or both)."""
    if not policy.get("enabled"):
        return {"status": "skipped", "reason": "disabled"}
    targets = policy.get("targets", {})
    age_days = policy.get("age_days") or None
    max_size_gb = policy.get("max_size_gb") or None
    cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=age_days)) if age_days else None
    size_budget = int(max_size_gb * (1024 ** 3)) if max_size_gb else None
    action = policy.get("action", "delete")
    move = action == "move"
    dest_cfg = policy.get("move_destination") or {}
    dest_client = _s3_client_for(dest_cfg) if move else None
    if move and not dest_client:
        return {"status": "error", "reason": "Move action selected but move_destination is not fully configured"}

    archive_prefix = f"archive/{site_name}/" if site_name else "archive/"
    alerts_prefix  = f"{ALERTS_PREFIX}{site_name}/" if site_name else ALERTS_PREFIX

    summary = {"status": "completed"}
    if not policy.get("delete_from_cloud", True):
        summary["cloud"] = {"status": "skipped", "reason": "delete_from_cloud is off"}
        return summary
    if targets.get("cloud_reports"):
        stat = {"scanned": 0, "matched": 0, "deleted": 0, "moved": 0, "errors": 0, "bytes_freed": 0}
        _sweep_prefix(client, dest_client, dest_cfg, archive_prefix, cutoff, size_budget, move, stat)
        summary["cloud_reports"] = stat
    if targets.get("cloud_alerts"):
        stat = {"scanned": 0, "matched": 0, "deleted": 0, "moved": 0, "errors": 0, "bytes_freed": 0}
        _sweep_alerts(client, dest_client, dest_cfg, alerts_prefix, cutoff, size_budget, move, stat)
        summary["cloud_alerts"] = stat
    return summary


def run_retention_sweep(trigger: str = "manual", site_name: Optional[str] = None) -> dict:
    """Cloud-side half of the retention policy. Runs synchronously (callers
    dispatch it to a thread pool executor so it never blocks the event
    loop — see /api/retention-policy/run-now and _maybe_kick_retention_sweep).
    The endpoint-side half (log rotation, quarantine pruning) is applied
    independently by each agent — see agent.py apply_endpoint_retention().

    site_name=None sweeps EVERY registered organization, each using its
    own effective (OEM-global + site-override) policy — this is what the
    opportunistic auto-trigger and an OEM admin's unscoped 'Run Now' do.
    A specific site_name sweeps only that organization, using its
    effective policy — what a site-admin's 'Run Now' (always scoped to
    their own site) does. If no organizations are registered at all, this
    falls back to one flat, unscoped sweep against the OEM-global policy
    for backward compatibility with simpler single-tenant deployments."""
    client = s3(commander=True)
    if not client:
        return {"status": "error", "reason": "Commander not configured", "trigger": trigger}

    ran_at = datetime.datetime.utcnow().isoformat()
    if site_name:
        sites = [site_name]
    else:
        sites = [o["site_name"] for o in _load_orgs()]

    per_site = {}
    if not sites:
        policy = _get_retention_policy(redact=False)
        per_site["_unscoped"] = _sweep_one_site(client, policy, None)
    else:
        for s in sites:
            policy = _get_retention_policy(redact=False, site_name=s)
            per_site[s] = _sweep_one_site(client, policy, s)
            s3_put(client, _site_override_key(RETENTION_LAST_RUN_KEY, s),
                   {"trigger": trigger, "ran_at": ran_at, "summary": per_site[s]})

    result = {"status": "completed", "trigger": trigger, "ran_at": ran_at,
              "sites_swept": sites or ["_unscoped"], "summary": per_site}
    s3_put(client, RETENTION_LAST_RUN_KEY, result)
    return result


async def _maybe_kick_retention_sweep():
    """Opportunistic auto-trigger: since Render's free tier has no
    always-on cron/worker, this checks (cheaply, off the request's Oracle
    reads that already happen) whether it's been >= sweep_interval_hours
    since the last recorded sweep, and if so runs one (across every
    registered organization, each with its own effective policy) in a
    thread pool executor without blocking the caller. Called
    fire-and-forget from GET /api/overview — the most-visited page — so
    retention still runs on roughly the right cadence even with zero
    dedicated infrastructure. Uses the OEM-global policy's
    sweep_interval_hours/enabled as the master switch/cadence; a site with
    its own override can still tighten (or disable) retention for just
    itself, but can't override the OEM's decision to run sweeps at all —
    that's an OEM ops concern, not a per-site one, so a site can't silently
    stop everyone else's sweep from ever running."""
    global _retention_sweep_running
    if _retention_sweep_running:
        return
    policy = _get_retention_policy(redact=False)
    if not policy.get("enabled"):
        return
    last = _get_retention_last_run() or {}
    last_at = _parse_utc(last.get("ran_at") or "")
    interval_h = max(1, int(policy.get("sweep_interval_hours") or 24))
    if last_at and (datetime.datetime.utcnow() - last_at).total_seconds() < interval_h * 3600:
        return
    _retention_sweep_running = True
    try:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, run_retention_sweep, "auto", None)
    except Exception:
        pass
    finally:
        _retention_sweep_running = False


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
    site_name = user.get("site_name")
    if site_name:
        org = _find_org(site_name)
        if org and org.get("status") == "suspended":
            raise HTTPException(403, f"Organization '{org.get('display_name', site_name)}' is suspended. Contact your provider.")
    token = _make_token(user["username"], user["role"], site_name)
    return JSONResponse({
        "token":     token,
        "username":  user["username"],
        "role":      user["role"],
        "site_name": site_name,
        "perms":     list(ROLE_PERMS.get(user["role"], set())),
    })


@app.get("/api/auth/me")
async def get_me(request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    out = dict(user)
    if user.get("site_name"):
        org = _find_org(user["site_name"])
        out["org_display_name"] = org.get("display_name") if org else user["site_name"]
    return JSONResponse(out)


@app.get("/api/users")
async def list_users(user=Depends(require_perm("users"))):
    users = _filter_by_site(user, _load_users())
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

    caller_scope = _scope_site(user)
    if caller_scope is not None:
        # Site-scoped admin: can only create users IN their own site, and
        # can never grant oem_admin (that would be a privilege escalation
        # out of their own org entirely).
        if role == "oem_admin":
            raise HTTPException(403, "Only an OEM admin can create another OEM admin")
        site_name = caller_scope
    else:
        # oem_admin: site_name required for every role except oem_admin
        # itself; must be a real, registered organization.
        site_name = None if role == "oem_admin" else (body.get("site_name") or "").strip()
        if role != "oem_admin":
            if not site_name:
                raise HTTPException(400, "site_name is required for non-OEM-admin users")
            if not _find_org(site_name):
                raise HTTPException(400, f"'{site_name}' is not a registered organization — onboard it first")

    users = _load_users()
    if any(u["username"].lower() == username for u in users):
        raise HTTPException(409, f"User '{username}' already exists")
    new_user = {
        "username":      username, "role": role, "site_name": site_name, "email": email,
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
    _enforce_site(user, target.get("site_name"), what=f"user '{username}'")
    caller_scope = _scope_site(user)
    if "role" in body:
        if body["role"] not in ROLE_PERMS:
            raise HTTPException(400, f"Invalid role")
        if caller_scope is not None and body["role"] == "oem_admin":
            raise HTTPException(403, "Only an OEM admin can grant the OEM admin role")
        target["role"] = body["role"]
    if "site_name" in body and caller_scope is not None:
        raise HTTPException(403, "Site-scoped admins cannot move a user to a different organization")
    elif "site_name" in body:
        new_site = (body["site_name"] or "").strip() or None
        if new_site and not _find_org(new_site):
            raise HTTPException(400, f"'{new_site}' is not a registered organization")
        target["site_name"] = new_site
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
    target = next((u for u in users if u["username"].lower() == username.lower()), None)
    if not target:
        raise HTTPException(404, f"User '{username}' not found")
    _enforce_site(user, target.get("site_name"), what=f"user '{username}'")
    users = [u for u in users if u["username"].lower() != username.lower()]
    _save_users(users)
    return JSONResponse({"status": "deleted", "username": username})


# ── Organizations (OEM-only: onboarding/offboarding customer sites) ───────────
@app.get("/api/organizations")
async def list_organizations(user=Depends(require_perm("orgs"))):
    orgs = _load_orgs()
    devices = fetch_inventory()
    users = _load_users()
    for o in orgs:
        o["device_count"] = sum(1 for d in devices if d.get("site_name") == o["site_name"])
        o["user_count"]   = sum(1 for u in users if u.get("site_name") == o["site_name"])
    return JSONResponse({"organizations": orgs})


@app.post("/api/organizations")
async def create_organization(request: Request, user=Depends(require_perm("orgs"))):
    """Onboards a new customer organization: registers the site_name and,
    optionally, creates its first site-admin user in the same call so an
    OEM admin can hand over working credentials immediately."""
    body = await request.json()
    site_name = (body.get("site_name") or "").strip()
    display_name = (body.get("display_name") or "").strip() or site_name
    if not site_name or not SITE_SLUG_RE.match(site_name):
        raise HTTPException(400, "site_name must be 2-64 characters: letters, numbers, '-' or '_' only "
                                  "(this becomes part of the Oracle key prefix for this org's data)")
    orgs = _load_orgs()
    if any(o["site_name"] == site_name for o in orgs):
        raise HTTPException(409, f"Organization '{site_name}' already exists")
    org = {
        "site_name": site_name, "display_name": display_name, "status": "active",
        "created_at": datetime.datetime.utcnow().isoformat(), "created_by": user["username"],
    }
    orgs.append(org)
    _save_orgs(orgs)

    admin_user = None
    admin_username = (body.get("admin_username") or "").strip().lower()
    admin_password = body.get("admin_password") or ""
    if admin_username and admin_password:
        users = _load_users()
        if any(u["username"].lower() == admin_username for u in users):
            raise HTTPException(409, f"Organization created, but user '{admin_username}' already exists — "
                                      f"add an admin for it separately from Users")
        admin_user = {
            "username": admin_username, "role": "admin", "site_name": site_name,
            "email": (body.get("admin_email") or "").strip(),
            "password_hash": _hash_pw(admin_password),
            "created_at": datetime.datetime.utcnow().isoformat(), "created_by": user["username"],
        }
        users.append(admin_user)
        _save_users(users)

    return JSONResponse({
        "organization": org,
        "admin_user": ({k: v for k, v in admin_user.items() if k != "password_hash"} if admin_user else None),
    }, status_code=201)


@app.put("/api/organizations/{site_name}")
async def update_organization(site_name: str, request: Request, user=Depends(require_perm("orgs"))):
    body = await request.json()
    orgs = _load_orgs()
    org = next((o for o in orgs if o["site_name"] == site_name), None)
    if not org:
        raise HTTPException(404, f"Organization '{site_name}' not found")
    if "display_name" in body:
        org["display_name"] = (body["display_name"] or "").strip() or site_name
    if "status" in body:
        if body["status"] not in ("active", "suspended"):
            raise HTTPException(400, "status must be 'active' or 'suspended'")
        org["status"] = body["status"]
    org["updated_at"] = datetime.datetime.utcnow().isoformat()
    _save_orgs(orgs)
    return JSONResponse(org)


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
    return JSONResponse({"devices": _filter_by_site(user, fetch_inventory())})


@app.get("/api/device/{site_name}/{hostname}")
async def get_device(site_name: str, hostname: str, request: Request):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    _enforce_site(user, site_name, what="this device")
    return JSONResponse(fetch_device_detail(site_name, hostname))


@app.get("/api/timeline/{site_name}/{hostname}")
async def get_timeline(site_name: str, hostname: str, request: Request, pid: Optional[int] = None):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    _enforce_site(user, site_name, what="this device")
    detail = fetch_device_detail(site_name, hostname)
    events = detail.get("timeline", [])
    if pid:
        events = [e for e in events if e.get("pid") == pid]
    return JSONResponse({"hostname": hostname, "events": events})


def _alerts_prefix_for(user: dict) -> str:
    """ALERTS_PREFIX narrowed to the caller's site, so any endpoint that
    scans it (update/bulk-update below) can never even list — let alone
    read or write — another organization's alert objects."""
    scope = _scope_site(user)
    return f"{ALERTS_PREFIX}{scope}/" if scope else ALERTS_PREFIX


# ── Alerts ────────────────────────────────────────────────────────────────────
@app.get("/api/alerts")
async def get_all_alerts(request: Request, status: Optional[str] = None,
                          site: Optional[str] = None, hostname: Optional[str] = None,
                          severity: Optional[str] = None, source: Optional[str] = None,
                          correlate: bool = False):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")

    alerts = _filter_by_site(user, fetch_all_alerts())
    write_client = s3(commander=True)
    existing_ids = {a["id"] for a in alerts}

    # Only scan THIS user's own site(s) for not-yet-persisted alerts — an
    # oem_admin's page load shouldn't be the trigger that creates (and
    # background-AI-analyzes) alerts for every customer site at once, and
    # a site-scoped user should never cause writes for a site they can't
    # even see.
    for m in _filter_by_site(user, fetch_status()):
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
                "category":    raw_alert.get("category") or "",
                "action":      raw_alert.get("action") or "",
                "process_name":raw_alert.get("process_name") or "",
                "command_line":raw_alert.get("command_line") or "",
                "mitre_tactic":raw_alert.get("mitre_tactic") or "",
                "detected_at": ts,
                "created_at":  datetime.datetime.utcnow().isoformat(timespec="milliseconds"),
                "updated_at":  datetime.datetime.utcnow().isoformat(timespec="milliseconds"),
                "notes":       "",
            }
            # Layer 1: static knowledge base — description/MITRE link/next
            # steps, present immediately, no AI dependency.
            new_alert = enrich_alert(new_alert)
            if write_client:
                _persist_alert(write_client, new_alert)
            alerts.append(new_alert)
            existing_ids.add(aid)
            cache_bust("alerts")
            # Layer 2 (optional): if a key is configured (Settings or env
            # var), generate a richer analysis in the background and
            # persist it onto the alert once — never blocks this request.
            _, resolved_key = _resolve_ai_config()
            if resolved_key:
                asyncio.create_task(_auto_generate_ai_analysis(dict(new_alert)))

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
    for obj in list_prefix(client, _alerts_prefix_for(user)):
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
    for obj in list_prefix(client, _alerts_prefix_for(user)):
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


def _find_alert(alert_id: str, site_name: Optional[str] = None, hostname: Optional[str] = None):
    """Looks up one alert by id, optionally scoped to a site/hostname for a
    direct Oracle read (fast path); falls back to scanning fetch_status()
    (cached) if not scoped or not found directly. Returns
    (alert_or_None, site_name, hostname)."""
    client = s3()
    alert = None
    if site_name and hostname and client:
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
    return alert, site_name, hostname


def _build_process_chain(alert: dict, timeline_events: list, max_depth: int = 12) -> list:
    """Reconstructs the process ancestry chain (root ancestor -> ... -> the
    process that triggered this alert) from process_creation Timeline
    events on the same host — the same idea as Microsoft Defender's
    'Alert Story'. Best-effort: alert records here carry process_name and
    command_line but not a PID (Defender/playbook detections don't report
    one), so the anchor process_creation event is matched by process name
    (and command line, when both have one), preferring whichever candidate
    is closest in time to the alert. From that anchor, parent_pid links
    (captured by timeline_collector.py's 4688 collector) are followed
    upward through the host's FULL recent timeline — not just the
    ±window_minutes slice used for related_events, since a real ancestor
    like explorer.exe or winlogon.exe often started well before that
    window — until no matching parent is found or max_depth is hit.
    Returns root-first, anchor process last; [] if nothing could be
    matched (e.g. no process_creation events collected for this host)."""
    proc_events = [e for e in timeline_events
                   if e.get("event_type") == "process_creation" and e.get("pid") is not None]
    if not proc_events:
        return []
    target_name = (alert.get("process_name") or "").lower()
    if not target_name:
        return []
    candidates = [e for e in proc_events if (e.get("process_name") or "").lower() == target_name]
    if not candidates:
        return []

    dt_alert = _parse_utc(alert.get("detected_at") or alert.get("time") or "")
    target_cmd = (alert.get("command_line") or "").lower()

    def score(e):
        s = 0.0
        if target_cmd and target_cmd in (e.get("command_line") or "").lower():
            s += 100
        dt_e = _parse_utc(e.get("time") or "")
        if dt_alert and dt_e:
            s -= abs((dt_e - dt_alert).total_seconds())  # closer in time wins ties
        return s

    anchor = max(candidates, key=score)

    # Most-recent event per PID, since a PID can be reused within the
    # collection window and we want each hop to resolve to the process
    # instance that was actually alive around the anchor's time.
    by_pid: Dict[int, dict] = {}
    for e in proc_events:
        pid = e.get("pid")
        prev = by_pid.get(pid)
        if prev is None or (e.get("time") or "") > (prev.get("time") or ""):
            by_pid[pid] = e

    chain = [anchor]
    current = anchor
    seen_pids = {current.get("pid")}
    for _ in range(max_depth):
        ppid = current.get("parent_pid")
        if ppid is None or ppid in seen_pids:
            break
        parent = by_pid.get(ppid)
        if not parent:
            break
        chain.append(parent)
        seen_pids.add(ppid)
        current = parent
    chain.reverse()
    return chain


def _alert_investigation_context(alert: dict, site_name: Optional[str], hostname: Optional[str],
                                  window_minutes: int = 10) -> dict:
    """Shared correlation logic used by both GET /api/alerts/{id}/context
    (on-demand, for the modal) and _auto_generate_ai_analysis (background,
    right after an alert is created) — Timeline events within
    ±window_minutes, sibling alerts in the same window, the reconstructed
    process ancestry chain, and the matched playbook rule's full
    definition if this alert came from one."""
    client = s3()
    dt_alert = _parse_utc(alert.get("detected_at") or alert.get("time") or "")
    window_s = window_minutes * 60
    related, siblings, rule_detail, process_chain = [], [], None, []
    if site_name and hostname:
        detail = fetch_device_detail(site_name, hostname)
        timeline = detail.get("timeline", [])
        if dt_alert:
            for evt in timeline:
                dt_evt = _parse_utc(evt.get("time") or "")
                if dt_evt:
                    diff = (dt_evt - dt_alert).total_seconds()
                    if abs(diff) <= window_s:
                        related.append({**evt, "_delta_secs": round(diff, 1)})
            related.sort(key=lambda x: x.get("time") or "")
        process_chain = _build_process_chain(alert, timeline)
        for m in fetch_status():
            if m["site_name"] == site_name and m["hostname"] == hostname:
                for a in m.get("alerts", []):
                    if a.get("id") == alert.get("id"):
                        continue
                    dt_a = _parse_utc(a.get("detected_at") or a.get("time") or "")
                    if dt_a and dt_alert and abs((dt_a - dt_alert).total_seconds()) <= window_s:
                        siblings.append(a)
    if alert.get("rule_name") and client:
        gdata = s3_get(client, "rules/global/rules.json") or {}
        for r in gdata.get("rules", []):
            if r.get("name") == alert.get("rule_name"):
                rule_detail = r
                break
    return {"related_events": related, "sibling_alerts": siblings,
            "rule_detail": rule_detail, "process_chain": process_chain,
            "window_minutes": window_minutes}


@app.get("/api/alerts/{alert_id}/context")
async def get_alert_context(alert_id: str, request: Request,
                             site_name: Optional[str] = None,
                             hostname: Optional[str] = None,
                             window_minutes: int = 10):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    alert, site_name, hostname = _find_alert(alert_id, site_name, hostname)
    if alert is None:
        raise HTTPException(404, f"Alert {alert_id} not found")
    _enforce_site(user, alert.get("site_name") or site_name, what="this alert")
    ctx = _alert_investigation_context(alert, site_name, hostname, window_minutes)
    return JSONResponse({"alert": alert, **ctx})



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
    for m in _filter_by_site(user, fetch_status()):
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
    """Mark an app as sanctioned or unsanctioned. This is intentionally
    OEM-only: app_policies.json is a single flat, un-site-keyed doc (an
    app is sanctioned or it isn't, platform-wide), so letting a site-admin
    change it would silently change every OTHER organization's view of
    that app too. If per-site app policy is ever needed, this needs the
    same OEM-global+site-override layering as Settings/Schedule/Retention
    first — until then, only an oem_admin can call this."""
    if _scope_site(user) is not None:
        raise HTTPException(403, "Only an OEM admin can change app sanctioning (it applies platform-wide)")
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
    _enforce_site(user, site, what="this device")
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
    if site:
        _enforce_site(user, site, what="this site")
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    devices = [d for d in _filter_by_site(user, fetch_inventory())
               if (not site or d["site_name"] == site)
               and (not hostname or d["hostname"] == hostname)]
    queued = []
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


# ── AI Analysis (Claude API) — Layer 2, optional on top of the static KB ──────
def _build_analysis_prompt(alert: dict, related_events: list) -> str:
    return f"""You are a cybersecurity analyst reviewing an endpoint detection alert from an SME security platform.

Alert Details:
- Threat/Rule: {alert.get('threat_name', 'Unknown')}
- Severity: {alert.get('severity', 'Unknown')}
- Source: {alert.get('source', 'Unknown')} (defender=Windows Defender, playbook=Detection Rule)
- Device: {alert.get('hostname', 'Unknown')} (Site: {alert.get('site_name', 'Unknown')})
- Detected: {alert.get('detected_at', 'Unknown')}
- Process: {alert.get('process_name', 'Unknown')}
- Command Line: {(alert.get('command_line') or 'N/A')[:500]}
- MITRE Tactic: {alert.get('mitre_tactic', 'Unknown')}

Related Events (chronological, ±10 min):
{chr(10).join(f"  [{e.get('_delta_secs',0):+.0f}s] {e.get('event_type','')} | {e.get('process_name','')} | {(e.get('command_line') or '')[:120]}" for e in related_events[:10]) or '  (none)'}

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


def _call_claude_analysis(alert: dict, related_events: list, model: str, api_key: str) -> dict:
    """Blocking call to the Claude API — always run this via
    asyncio.get_event_loop().run_in_executor() / asyncio.to_thread(), never
    awaited directly, so it can't stall the event loop. model/api_key come
    from _resolve_ai_config() (Settings override, falling back to the
    ANTHROPIC_API_KEY env var) rather than being hardcoded, so an admin can
    change either from the dashboard without a redeploy. Raises on any
    failure; callers decide how to surface that (HTTPException for the
    manual endpoint, a quiet skip for the background auto-trigger)."""
    import urllib.request
    prompt = _build_analysis_prompt(alert, related_events)
    req_data = json.dumps({
        "model": model,
        "max_tokens": 1000,
        "messages": [{"role": "user", "content": prompt}],
    }).encode()
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=req_data,
        headers={
            "Content-Type":      "application/json",
            "x-api-key":         api_key,
            "anthropic-version": "2023-06-01",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result = json.loads(resp.read())
    raw_text = result["content"][0]["text"]
    return json.loads(raw_text)


async def _auto_generate_ai_analysis(alert: dict):
    """Fire-and-forget task kicked off right after a new alert is first
    persisted (see get_all_alerts). Runs the same analysis as the manual
    'Regenerate AI Analysis' button, but automatically and exactly once —
    the result is written back onto the alert object in Oracle so every
    analyst sees it immediately with zero button-clicks and zero repeat
    API cost. Never raises out of this task: a failure here should not be
    visible anywhere except the server log, since Layer 1 (enrich_alert)
    has already given the alert usable baseline detail regardless."""
    try:
        model, api_key = _resolve_ai_config()
        if not api_key:
            return
        ctx = _alert_investigation_context(alert, alert.get("site_name"), alert.get("hostname"))
        loop = asyncio.get_event_loop()
        analysis = await loop.run_in_executor(None, _call_claude_analysis, alert, ctx["related_events"], model, api_key)
        client = s3(commander=True)
        if not client:
            return
        current, site_name, hostname = _find_alert(alert["id"], alert.get("site_name"), alert.get("hostname"))
        if not current or not site_name or not hostname:
            return
        current["ai_analysis"] = analysis
        current["ai_analysis_generated_at"] = datetime.datetime.utcnow().isoformat()
        s3_put(client, f"{ALERTS_PREFIX}{site_name}/{hostname}/{current['id']}.json", current)
        cache_bust("alerts")
    except Exception as e:
        print(f"[ai] auto AI analysis failed for alert {alert.get('id')}: {e}")


@app.post("/api/ai/analyze-alert")
async def ai_analyze_alert(request: Request, user=Depends(require_perm("alerts"))):
    """Runs (or re-runs) Claude analysis for one alert BY ID and persists
    the result onto it — this is what the dashboard's 'Analyze with AI' /
    'Regenerate AI Analysis' button calls. Requires either an API key
    saved in Settings (AI Analysis card) or ANTHROPIC_API_KEY set on
    Render. For the fully automatic version that runs once when an alert
    is first created, see _auto_generate_ai_analysis above."""
    model, api_key = _resolve_ai_config()
    if not api_key:
        raise HTTPException(503, "No Anthropic API key configured. Add one under Settings > AI Analysis, "
                                  "or set ANTHROPIC_API_KEY as a Render environment variable.")
    body = await request.json()
    alert_id = body.get("alert_id")
    if not alert_id:
        raise HTTPException(400, "alert_id required")
    alert, site_name, hostname = _find_alert(alert_id, body.get("site_name"), body.get("hostname"))
    if alert is None:
        raise HTTPException(404, f"Alert {alert_id} not found")
    _enforce_site(user, alert.get("site_name") or site_name, what="this alert")
    ctx = _alert_investigation_context(alert, site_name, hostname)
    try:
        loop = asyncio.get_event_loop()
        analysis = await loop.run_in_executor(None, _call_claude_analysis, alert, ctx["related_events"], model, api_key)
    except json.JSONDecodeError:
        raise HTTPException(502, "AI analysis returned an unparseable response — try again")
    except Exception as e:
        raise HTTPException(500, f"AI analysis failed: {e}")

    client = s3(commander=True)
    if client and site_name and hostname:
        alert["ai_analysis"] = analysis
        alert["ai_analysis_generated_at"] = datetime.datetime.utcnow().isoformat()
        s3_put(client, f"{ALERTS_PREFIX}{site_name}/{hostname}/{alert['id']}.json", alert)
        cache_bust("alerts")
    return JSONResponse({"analysis": analysis, "alert": alert})


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


def _enforce_rules_scope(user: dict, scope: str, site: Optional[str], write: bool = False):
    """Global rules are OEM policy — only an oem_admin may create/edit/
    delete them (read is fine for everyone, so site-admins can see what
    baseline applies to them). Site/machine-scoped rules are restricted to
    the caller's own site, exactly like every other layered config."""
    caller_scope = _scope_site(user)
    if caller_scope is None:
        return
    if scope == "global":
        if write:
            raise HTTPException(403, "Only an OEM admin can modify global detection rules")
        return
    if site != caller_scope:
        raise HTTPException(403, f"'{user['username']}' is restricted to site '{caller_scope}'")


@app.get("/api/rules")
async def get_rules(request: Request, scope: str = "global",
                     site: Optional[str] = None, hostname: Optional[str] = None):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    _enforce_rules_scope(user, scope, site, write=False)
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
    _enforce_rules_scope(user, scope, site, write=True)
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
    _enforce_rules_scope(user, scope, site, write=True)
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
    _enforce_rules_scope(user, scope, site, write=True)
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
    _enforce_site(user, site, what="this device")
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
    _enforce_site(user, site_name, what="this device")
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
    asyncio.create_task(_maybe_kick_retention_sweep())
    settings = _get_settings(_scope_site(user))
    offline_threshold_hours = settings.get("offline_threshold_hours", 1)
    offline_days_warning    = settings.get("offline_days_warning", 7)
    mttd_target             = int(settings.get("mttd_target_minutes", 30))
    mttr_target             = int(settings.get("mttr_target_minutes", 120))

    devices  = _filter_by_site(user, fetch_inventory())
    alerts   = _filter_by_site(user, fetch_all_alerts())
    machines = _filter_by_site(user, fetch_status())
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


def _resolve_target_site(user: dict, query_site: Optional[str]) -> Optional[str]:
    """Resolves which layer a GET/PUT/DELETE of a layered config
    (settings / agent-schedule / retention-policy) should operate on.
    - oem_admin: whatever `site` query param says (None = the OEM-global
      layer itself).
    - site-scoped user: always their own site, regardless of any `site`
      query param supplied — this is what stops a site-admin from ever
      touching the OEM-global doc, or another org's override, just by
      passing a different ?site=... value."""
    scope = _scope_site(user)
    return query_site if scope is None else scope


@app.get("/api/settings")
async def get_settings(request: Request, site: Optional[str] = None):
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    return JSONResponse(_get_settings(_resolve_target_site(user, site)))


@app.put("/api/settings")
async def update_settings(request: Request, site: Optional[str] = None,
                           user=Depends(require_perm("settings"))):
    body = await request.json()
    allowed = {"offline_threshold_hours", "offline_days_warning", "org_name",
               "mttd_target_minutes", "mttr_target_minutes", "dashboard_title"}
    target = _resolve_target_site(user, site)
    if target and not _find_org(target):
        raise HTTPException(400, f"'{target}' is not a registered organization")
    key = SETTINGS_KEY if not target else _site_override_key(SETTINGS_KEY, target)
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    # Load the RAW doc at the key we're writing to (not the merged/
    # effective view) — otherwise changing one field would freeze every
    # inherited-from-OEM-global value into this site's override too,
    # breaking live inheritance for every field the site never touched.
    existing = s3_get(client, key) or {}
    for k, v in body.items():
        if k in allowed:
            existing[k] = v
    existing["updated_at"] = datetime.datetime.utcnow().isoformat()
    existing["updated_by"] = user["username"]
    s3_put(client, key, existing)
    return JSONResponse(_get_settings(target))


@app.delete("/api/settings")
async def clear_settings_override(site: Optional[str] = None, user=Depends(require_perm("settings"))):
    """Reverts a site back to the OEM-global dashboard settings by
    deleting its entire override doc. Not available at the OEM-global
    layer itself (there's nothing to fall back to from there)."""
    target = _resolve_target_site(user, site)
    if not target:
        raise HTTPException(400, "Nothing to clear at the OEM-global layer")
    client = s3(commander=True)
    if client:
        try:
            client.delete_object(Bucket=ORACLE_BUCKET, Key=_site_override_key(SETTINGS_KEY, target))
        except Exception:
            pass
    return JSONResponse(_get_settings(target))


@app.get("/api/agent-schedule")
async def get_agent_schedule(request: Request, site: Optional[str] = None):
    """Returns the current dashboard-configurable endpoint agent schedule
    (SME-DefenderAudit/DNSAudit/USBLockdown/ProcessMonitor/ThreatReporter/
    TimelineCollector/Reporter/CommandExecutor), merged with defaults for
    any key never explicitly saved, layered OEM-global then (if scoped, or
    ?site= given by an oem_admin) that site's own override."""
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    return JSONResponse(_get_agent_schedule(_resolve_target_site(user, site)))


@app.put("/api/agent-schedule")
async def update_agent_schedule(request: Request, site: Optional[str] = None,
                                 user=Depends(require_perm("settings"))):
    """Saves the endpoint agent schedule either to the OEM-global doc or
    to one site's override doc (see _resolve_target_site). Every installed
    SMESecurityAgent service reads BOTH objects directly on its own cycle
    (global always, plus its own site's override — see agent.py) and
    applies changed intervals/enable-toggles live, without a service
    restart, with the site override always winning per-field."""
    body = await request.json()
    target = _resolve_target_site(user, site)
    if target and not _find_org(target):
        raise HTTPException(400, f"'{target}' is not a registered organization")
    key = AGENT_SCHEDULE_KEY if not target else _site_override_key(AGENT_SCHEDULE_KEY, target)
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    existing = s3_get(client, key) or {}
    for k, v in body.items():
        if k not in DEFAULT_AGENT_SCHEDULE:
            continue
        if isinstance(DEFAULT_AGENT_SCHEDULE[k], bool):
            existing[k] = bool(v)
        else:
            try:
                iv = int(v)
            except (TypeError, ValueError):
                raise HTTPException(400, f"'{k}' must be a whole number")
            floor = AGENT_SCHEDULE_MIN.get(k, 1)
            if iv < floor:
                raise HTTPException(400, f"'{k}' must be at least {floor}")
            existing[k] = iv
    existing["updated_at"] = datetime.datetime.utcnow().isoformat()
    existing["updated_by"] = user["username"]
    s3_put(client, key, existing)
    return JSONResponse(_get_agent_schedule(target))


@app.delete("/api/agent-schedule")
async def clear_agent_schedule_override(site: Optional[str] = None, user=Depends(require_perm("settings"))):
    target = _resolve_target_site(user, site)
    if not target:
        raise HTTPException(400, "Nothing to clear at the OEM-global layer")
    client = s3(commander=True)
    if client:
        try:
            client.delete_object(Bucket=ORACLE_BUCKET, Key=_site_override_key(AGENT_SCHEDULE_KEY, target))
        except Exception:
            pass
    return JSONResponse(_get_agent_schedule(target))


@app.get("/api/update-policy")
async def get_update_policy(request: Request, site: Optional[str] = None):
    """Returns the effective (OEM-global + optional site-override) Update
    Management policy — Defender signature freshness, Windows Update
    auto-install, and winget app auto-update settings."""
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    return JSONResponse(_get_update_policy(_resolve_target_site(user, site)))


@app.put("/api/update-policy")
async def update_update_policy(request: Request, site: Optional[str] = None,
                                user=Depends(require_perm("settings"))):
    """Saves the update policy either to the OEM-global doc or to one
    site's override doc. Loads the RAW doc at the target key (not the
    merged effective view) so untouched fields keep inheriting live from
    the OEM-global default instead of being frozen into the site override
    — same pattern as settings/agent-schedule/retention-policy."""
    body = await request.json()
    target = _resolve_target_site(user, site)
    if target and not _find_org(target):
        raise HTTPException(400, f"'{target}' is not a registered organization")
    key = UPDATE_POLICY_KEY if not target else _site_override_key(UPDATE_POLICY_KEY, target)
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    current = s3_get(client, key) or {}
    for section in ("defender_signatures", "windows_updates", "app_updates"):
        if section not in body or not isinstance(body[section], dict):
            continue
        current.setdefault(section, {})
        incoming = body[section]
        if section == "defender_signatures":
            if "enabled" in incoming:
                current[section]["enabled"] = bool(incoming["enabled"])
            if "auto_update" in incoming:
                current[section]["auto_update"] = bool(incoming["auto_update"])
            if "max_age_hours" in incoming:
                try:
                    v = int(incoming["max_age_hours"])
                except (TypeError, ValueError):
                    raise HTTPException(400, "'defender_signatures.max_age_hours' must be a whole number")
                if v < 1:
                    raise HTTPException(400, "'defender_signatures.max_age_hours' must be at least 1")
                current[section]["max_age_hours"] = v
        elif section == "windows_updates":
            if "enabled" in incoming:
                current[section]["enabled"] = bool(incoming["enabled"])
            if "auto_install" in incoming:
                current[section]["auto_install"] = bool(incoming["auto_install"])
            if "auto_reboot" in incoming:
                current[section]["auto_reboot"] = bool(incoming["auto_reboot"])
            if "categories" in incoming:
                valid = {"Critical", "Important", "Moderate", "Low"}
                cats = [c for c in (incoming["categories"] or []) if c in valid]
                current[section]["categories"] = cats
            if "maintenance_window" in incoming:
                w = incoming["maintenance_window"]
                if w is None:
                    current[section]["maintenance_window"] = None
                elif isinstance(w, dict) and "start" in w and "end" in w:
                    current[section]["maintenance_window"] = {
                        "days": [d for d in (w.get("days") or []) if d in
                                 ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")],
                        "start": str(w["start"]), "end": str(w["end"]),
                    }
                else:
                    raise HTTPException(400, "'windows_updates.maintenance_window' must be null or "
                                              "{days, start, end}")
        elif section == "app_updates":
            if "enabled" in incoming:
                current[section]["enabled"] = bool(incoming["enabled"])
            if "auto_update" in incoming:
                current[section]["auto_update"] = bool(incoming["auto_update"])
            if "allow_list" in incoming:
                current[section]["allow_list"] = [str(x).strip() for x in (incoming["allow_list"] or []) if str(x).strip()]
    current["updated_at"] = datetime.datetime.utcnow().isoformat()
    current["updated_by"] = user["username"]
    s3_put(client, key, current)
    return JSONResponse(_get_update_policy(target))


@app.delete("/api/update-policy")
async def clear_update_policy_override(site: Optional[str] = None, user=Depends(require_perm("settings"))):
    target = _resolve_target_site(user, site)
    if not target:
        raise HTTPException(400, "Nothing to clear at the OEM-global layer")
    client = s3(commander=True)
    if client:
        try:
            client.delete_object(Bucket=ORACLE_BUCKET, Key=_site_override_key(UPDATE_POLICY_KEY, target))
        except Exception:
            pass
    return JSONResponse(_get_update_policy(target))


@app.get("/api/retention-policy")
async def get_retention_policy(request: Request, site: Optional[str] = None):
    """Returns the merged retention policy with the destination secret key
    redacted (see _get_retention_policy), layered OEM-global then (if
    scoped, or ?site= given by an oem_admin) that site's own override."""
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    target = _resolve_target_site(user, site)
    policy = _get_retention_policy(redact=True, site_name=target)
    policy["last_run"] = _get_retention_last_run(target)
    return JSONResponse(policy)


@app.put("/api/retention-policy")
async def update_retention_policy(request: Request, site: Optional[str] = None,
                                   user=Depends(require_perm("settings"))):
    """Saves the retention policy either to the OEM-global doc or to one
    site's override doc (see _resolve_target_site). Deletion is
    destructive, so every field is validated defensively and an omitted/
    blank destination secret_key means 'keep the existing one' rather
    than 'clear it' — this is a write-only field the browser never sees
    back from GET. Loads the RAW doc at the target key (not the merged
    effective view) so untouched fields keep inheriting live from the
    OEM-global default instead of being frozen into the site override."""
    body = await request.json()
    target = _resolve_target_site(user, site)
    if target and not _find_org(target):
        raise HTTPException(400, f"'{target}' is not a registered organization")
    key = RETENTION_POLICY_KEY if not target else _site_override_key(RETENTION_POLICY_KEY, target)
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    current = s3_get(client, key) or {}
    current.setdefault("targets", {})
    current.setdefault("move_destination", {})
    # For validation/defaulting convenience, work against the effective
    # (merged) view for anything not explicitly present in the raw doc,
    # but only ever WRITE the fields the request actually touches (plus
    # whatever was already explicitly set in this doc before).
    effective = _get_retention_policy(redact=False, site_name=target)

    if "enabled" in body:
        current["enabled"] = bool(body["enabled"])
    if "action" in body:
        if body["action"] not in ("delete", "move"):
            raise HTTPException(400, "'action' must be 'delete' or 'move'")
        current["action"] = body["action"]
    for flag in ("delete_from_cloud", "delete_from_endpoint"):
        if flag in body:
            current[flag] = bool(body[flag])

    for numeric_key in ("age_days", "max_size_gb"):
        if numeric_key in body:
            v = body[numeric_key]
            if v in (None, "", 0):
                current[numeric_key] = None
            else:
                try:
                    nv = float(v)
                except (TypeError, ValueError):
                    raise HTTPException(400, f"'{numeric_key}' must be a number")
                if nv <= 0:
                    raise HTTPException(400, f"'{numeric_key}' must be greater than 0 (or blank to disable)")
                current[numeric_key] = int(nv) if numeric_key == "age_days" else nv

    if "sweep_interval_hours" in body:
        try:
            iv = int(body["sweep_interval_hours"])
        except (TypeError, ValueError):
            raise HTTPException(400, "'sweep_interval_hours' must be a whole number")
        current["sweep_interval_hours"] = max(1, iv)

    if "targets" in body and isinstance(body["targets"], dict):
        for k, v in body["targets"].items():
            if k in effective["targets"]:
                current["targets"][k] = bool(v)

    if "move_destination" in body and isinstance(body["move_destination"], dict):
        d = body["move_destination"]
        for k in ("endpoint", "access_key", "bucket", "region", "prefix"):
            if k in d:
                current["move_destination"][k] = (d[k] or "").strip()
        # secret_key is write-only and sticky: only overwrite if a
        # non-blank value was actually submitted this time.
        if d.get("secret_key"):
            current["move_destination"]["secret_key"] = d["secret_key"]

    # Validate against the EFFECTIVE (post-merge) action/destination, since
    # a site override might only set 'action':'move' while still legally
    # inheriting the OEM-global move_destination.
    check_action = current.get("action", effective["action"])
    check_dest = dict(effective["move_destination"])
    check_dest.update(current.get("move_destination", {}))
    if check_action == "move" and not all(check_dest.get(k) for k in ("endpoint", "access_key", "bucket")) \
            and not check_dest.get("secret_key"):
        raise HTTPException(400, "Move destination needs at least endpoint, access key, secret key, and bucket "
                                  "(inherited from the OEM default counts)")

    current["updated_at"] = datetime.datetime.utcnow().isoformat()
    current["updated_by"] = user["username"]
    s3_put(client, key, current)
    out = _get_retention_policy(redact=True, site_name=target)
    return JSONResponse(out)


@app.delete("/api/retention-policy")
async def clear_retention_policy_override(site: Optional[str] = None, user=Depends(require_perm("settings"))):
    target = _resolve_target_site(user, site)
    if not target:
        raise HTTPException(400, "Nothing to clear at the OEM-global layer")
    client = s3(commander=True)
    if client:
        try:
            client.delete_object(Bucket=ORACLE_BUCKET, Key=_site_override_key(RETENTION_POLICY_KEY, target))
        except Exception:
            pass
    return JSONResponse(_get_retention_policy(redact=True, site_name=target))


@app.post("/api/retention-policy/run-now")
async def run_retention_policy_now(site: Optional[str] = None, user=Depends(require_perm("settings"))):
    """Runs the cloud-side sweep immediately and waits for the result
    (dispatched to a thread pool executor so it doesn't block the event
    loop). A site-scoped admin always sweeps only their own org; an OEM
    admin can pass ?site=X to sweep just one org, or omit it to sweep
    every registered org at once. The endpoint-side half runs on its own
    inside each agent and isn't triggerable from here — see agent.py."""
    global _retention_sweep_running
    if _retention_sweep_running:
        raise HTTPException(409, "A retention sweep is already running")
    target = _resolve_target_site(user, site)
    _retention_sweep_running = True
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, run_retention_sweep, "manual", target)
    finally:
        _retention_sweep_running = False
    cache_bust("alerts")
    return JSONResponse(result)


@app.get("/api/ai-settings")
async def get_ai_settings(request: Request):
    """Returns the AI model/key configuration with api_key redacted (see
    _get_ai_settings), plus the list of model choices the Settings UI
    should offer in its dropdown."""
    user = await get_user(request)
    if not user:
        raise HTTPException(401, "Authentication required")
    settings = _get_ai_settings(redact=True)
    settings["model_choices"] = AI_MODEL_CHOICES
    return JSONResponse(settings)


@app.put("/api/ai-settings")
async def update_ai_settings(request: Request, user=Depends(require_perm("settings"))):
    """Saves the model string and/or API key to Oracle. OEM-only: this is
    a single shared billing credential across every organization, not
    something a site-admin can delegate/override per-org (see the AI
    Analysis card's comment in dashboard.html for the same reasoning).
    api_key is write-only and sticky: an omitted or blank value means
    'keep the existing one', exactly like the retention policy's
    move-destination secret — the browser never sees a previously-saved
    key back."""
    if _scope_site(user) is not None:
        raise HTTPException(403, "Only an OEM admin can change the AI model/API key (it applies platform-wide)")
    body = await request.json()
    current = _get_ai_settings(redact=False)
    if "model" in body:
        model = (body["model"] or "").strip()
        if not model:
            raise HTTPException(400, "'model' cannot be blank")
        current["model"] = model
    if body.get("api_key"):
        current["api_key"] = body["api_key"].strip()
    current["updated_at"] = datetime.datetime.utcnow().isoformat()
    current["updated_by"] = user["username"]
    client = s3(commander=True)
    if not client:
        raise HTTPException(503, "Commander not configured")
    s3_put(client, AI_SETTINGS_KEY, current)
    out = _get_ai_settings(redact=True)
    out["model_choices"] = AI_MODEL_CHOICES
    return JSONResponse(out)


@app.post("/api/alerts/webhook")
async def alert_webhook(request: Request, background_tasks: BackgroundTasks):
    alert = await request.json()
    if process_and_forward:
        background_tasks.add_task(process_and_forward, alert)
    return JSONResponse({"status": "success"})


@app.get("/health")
async def health():
    _, resolved_key = _resolve_ai_config()
    return {"status": "ok",
            "oracle": bool(ORACLE_S3_ENDPOINT and ORACLE_ACCESS_KEY and ORACLE_BUCKET),
            "commander": bool(ORACLE_COMMANDER_ACCESS_KEY and ORACLE_COMMANDER_SECRET_KEY),
            "ai": bool(resolved_key)}


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")
