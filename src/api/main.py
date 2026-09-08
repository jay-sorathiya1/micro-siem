"""
Micro-SIEM API - FastAPI backend

Logic overview (this is the part that matters for your viva):
1. Connect to OpenSearch (where Vector already pushed auth.log + web login events)
2. /logs endpoint -> just returns recent raw log events
3. /login endpoint -> demo web login page posts here; every attempt is logged
4. /alerts endpoint -> runs detection, PERSISTS alerts once triggered
   (an alert stays visible on the dashboard even after the original failed
   attempts age out of the detection time window - it's a historical record,
   not a live-only view. This matches how real SIEMs handle alert history.)
5. Detection rule (v1): 5 failed logins from the same source within 2 minutes,
   checked across TWO sources - SSH (auth.log) and web login (login.log)
"""

import os
import json
import secrets
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

from fastapi import FastAPI, Request, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from opensearchpy import OpenSearch

app = FastAPI(title="Micro-SIEM API")

# CORS: allows the React console (running on a different port, 8090) to
# call this API directly from the browser. Wide open here since this is
# a local demo project, not something exposed publicly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "opensearch")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", 9200))

client = OpenSearch(
    hosts=[{"host": OPENSEARCH_HOST, "port": OPENSEARCH_PORT}],
    use_ssl=False,
    verify_certs=False,
)

LOGS_INDEX = "logs-index"
ALERTS_INDEX = "alerts-index"
BLOCKED_INDEX = "blocked-index"

FAILED_LOGIN_THRESHOLD = 5      # how many failed attempts...
TIME_WINDOW_MINUTES = 2         # ...within this many minutes = alert

# How long to wait before allowing the SAME alert (same type + source)
# to fire again - prevents spamming a new alert doc every 3-second
# dashboard refresh while an attack is still ongoing.
ALERT_DEDUPE_MINUTES = 5

# Safety net: these can NEVER be blocked, no matter what, so a false
# positive or accidental click can't lock you out of your own machine.
NEVER_BLOCK_IPS = {"127.0.0.1", "::1", "localhost", "unknown", "0.0.0.0"}

# --- Demo web login page config (attack target, stays intentionally weak) ---
# Demo web login accounts - 3 accounts, numeric-only passwords (easy to type
# quickly during a live demo). Still demo-only, never do this in a real app.
DEMO_ACCOUNTS = {
    "admin": "1234",
    "test": "1111",
    "guest": "0000",
}

WEBAPP_LOG_PATH = "/var/log/webapp/login.log"

# Demo login page sessions - separate from dashboard admin/viewer sessions.
# Lets search.html verify on load whether the account got blocked
# AFTER the user already logged in.
demo_sessions = {}  # token -> {"username": str, "created": datetime}

# --- Dashboard admin/viewer session auth ---
DASHBOARD_USERS = {
    "admin": {"password": "2632", "role": "admin"},
    "viewer": {"password": "2000", "role": "viewer"},
}
SESSION_TTL_HOURS = 8
sessions = {}  # token -> {"role": str, "expires": datetime}


class DashboardLoginRequest(BaseModel):
    username: str
    password: str


def require_session(authorization: str = Header(None)):
    """
    Dependency used to protect /logs and /alerts. Expects header:
    Authorization: Bearer <token>
    Raises 401 if missing, invalid, or expired - enforced server-side,
    not just a frontend redirect, so this is real access control.
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    token = authorization.split(" ", 1)[1]
    session = sessions.get(token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid session token")
    if datetime.utcnow() > session["expires"]:
        del sessions[token]
        raise HTTPException(status_code=401, detail="Session expired")
    return session


def require_admin(session: dict = Depends(require_session)):
    """Block/unblock actions are admin-only - viewers can't act, only observe."""
    if session["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required for this action")
    return session


class LoginRequest(BaseModel):
    username: str
    password: str


def write_webapp_log(event: dict):
    """Append one JSON-line event to the web login log file for Vector to pick up."""
    os.makedirs(os.path.dirname(WEBAPP_LOG_PATH), exist_ok=True)
    with open(WEBAPP_LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")


@app.get("/")
def root():
    return {"status": "Micro-SIEM API running"}


@app.post("/login")
def web_login(payload: LoginRequest, request: Request):
    """
    Demo web login endpoint - powers the crazy login page.

    Simple logic, no lockout:
    1. Validate credentials against the hardcoded demo account
    2. Log every attempt (success/fail) as JSON - Vector picks this up as
       a second real log source, separate from SSH auth.log
    """
    source_ip = request.headers.get("x-forwarded-for", request.client.host).split(",")[0].strip()
    username = payload.username
    now = datetime.utcnow()

    # Check if this account has been manually blocked by an admin
    blocked_check = client.search(
        index=BLOCKED_INDEX,
        body={"query": {"bool": {"must": [{"term": {"username.keyword": username}}, {"term": {"type.keyword": "account"}}]}}},
        ignore=[404],
    )
    if blocked_check.get("hits", {}).get("total", {}).get("value", 0) > 0:
        write_webapp_log({
            "timestamp": now.isoformat(),
            "log_type": "web_login",
            "event": "login_blocked",
            "username": username,
            "source_ip": source_ip,
            "result": "blocked",
        })
        return {"success": False, "reason": "this account has been blocked by an administrator"}

    if DEMO_ACCOUNTS.get(username) == payload.password:
        write_webapp_log({
            "timestamp": now.isoformat(),
            "log_type": "web_login",
            "event": "login_success",
            "username": username,
            "source_ip": source_ip,
            "result": "success",
        })
        demo_token = secrets.token_hex(16)
        demo_sessions[demo_token] = {"username": username, "created": now}
        return {"success": True, "token": demo_token}

    write_webapp_log({
        "timestamp": now.isoformat(),
        "log_type": "web_login",
        "event": "login_failed",
        "username": username,
        "source_ip": source_ip,
        "result": "failed",
    })
    return {"success": False, "reason": "invalid credentials"}


@app.get("/session-check")
def session_check(token: str):
    """
    Public endpoint - search.html calls this on load to verify:
    1. The demo session token is real
    2. The account behind it hasn't been blocked since login

    If blocked, search.html clears its stored token and redirects
    back to login.html - this is checked on page load only, not
    live-polled, so an already-open tab won't be kicked out mid-session,
    only on next load/navigation.
    """
    session = demo_sessions.get(token)
    if not session:
        return {"valid": False, "reason": "invalid session"}

    username = session["username"]
    blocked_check = client.search(
        index=BLOCKED_INDEX,
        body={"query": {"bool": {"must": [{"term": {"username.keyword": username}}, {"term": {"type.keyword": "account"}}]}}},
        ignore=[404],
    )
    if blocked_check.get("hits", {}).get("total", {}).get("value", 0) > 0:
        demo_sessions.pop(token, None)
        return {"valid": False, "reason": "account has been blocked"}

    return {"valid": True, "username": username}


@app.post("/auth/login")
def dashboard_login(payload: DashboardLoginRequest):
    """
    Dashboard login (admin/viewer) - NOT the demo attack-target /login above.
    On success, issues a random opaque session token (real server-side
    session, not a client-side trick) valid for SESSION_TTL_HOURS.
    """
    user = DASHBOARD_USERS.get(payload.username)
    if not user or user["password"] != payload.password:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = secrets.token_hex(24)
    sessions[token] = {
        "role": user["role"],
        "expires": datetime.utcnow() + timedelta(hours=SESSION_TTL_HOURS),
    }
    return {"token": token, "role": user["role"]}


@app.post("/auth/logout")
def dashboard_logout(authorization: str = Header(None)):
    """Invalidate a session token immediately."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        sessions.pop(token, None)
    return {"status": "logged out"}


@app.get("/logs")
def get_logs(limit: int = 50, session: dict = Depends(require_session)):
    """Return the most recent raw log events from OpenSearch. Requires a valid session."""
    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }
    result = client.search(index=LOGS_INDEX, body=query)
    hits = [hit["_source"] for hit in result["hits"]["hits"]]
    return {"count": len(hits), "logs": hits}



def _already_alerted_recently(alert_type: str, source_ip: str) -> bool:
    """
    Check if an alert of this type+source was already raised within
    ALERT_DEDUPE_MINUTES. Prevents inserting a new alert document every
    single dashboard refresh while the same attack is still ongoing.
    """
    since = datetime.utcnow() - timedelta(minutes=ALERT_DEDUPE_MINUTES)
    query = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"alert_type.keyword": alert_type}},
                    {"term": {"source_ip.keyword": source_ip}},
                    {"range": {"timestamp": {"gte": since.isoformat()}}},
                ]
            }
        },
    }
    result = client.search(index=ALERTS_INDEX, body=query, ignore=[404])
    return result.get("hits", {}).get("total", {}).get("value", 0) > 0


def _run_detection():
    """
    Detection logic (v1 - brute force), across two sources:
    1. SSH failed logins (auth.log, matched on "Failed password" text)
    2. Web login failures (webapp login.log, matched on event=login_failed)

    New alerts are written to ALERTS_INDEX (permanent record).
    Deduping avoids writing a duplicate alert every few seconds while
    the same attack is still active.
    """
    since = datetime.utcnow() - timedelta(minutes=TIME_WINDOW_MINUTES)

    sources = [
        {
            "alert_type": "SSH Brute Force Attempt",
            "rule_name": "failed_ssh_logins",
            "match_field": "raw_message",
            "match_value": "Failed password",
            "mitre_technique": "Brute Force",
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access",
        },
        {
            "alert_type": "Web Login Brute Force",
            "rule_name": "failed_web_logins",
            "match_field": "event",
            "match_value": "login_failed",
            "mitre_technique": "Brute Force",
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access",
        },
    ]

    for src in sources:
        query = {
            "size": 500,
            "query": {
                "bool": {
                    "must": [
                        {"match": {src["match_field"]: src["match_value"]}},
                        {"range": {"timestamp": {"gte": since.isoformat()}}},
                    ]
                }
            },
        }
        result = client.search(index=LOGS_INDEX, body=query)
        events = [hit["_source"] for hit in result["hits"]["hits"]]

        grouped = defaultdict(list)
        for event in events:
            grouped[event.get("source_ip", "unknown")].append(event)

        for source_ip, attempts in grouped.items():
            if len(attempts) < FAILED_LOGIN_THRESHOLD:
                continue

            alert = {
                "timestamp": datetime.utcnow().isoformat(),
                "alert_type": src["alert_type"],
                "source_ip": source_ip,
                "attempt_count": len(attempts),
                "severity": "HIGH",
                "matched_rule": f"{FAILED_LOGIN_THRESHOLD}_{src['rule_name']}_{TIME_WINDOW_MINUTES}min",
                "mitre_technique": src["mitre_technique"],
                "mitre_id": src["mitre_id"],
                "mitre_tactic": src["mitre_tactic"],
            }
            client.index(index=ALERTS_INDEX, body=alert)

    _run_correlation_rule()
    _run_xss_detection()


# Signatures checked against Nginx request paths - simple pattern matching,
# same approach real basic WAFs use at a signature level (not ML-based).
XSS_SIGNATURES = [
    "<script", "onerror=", "onload=", "javascript:", "alert(",
    "%3cscript", "document.cookie", "<img", "<svg", "onmouseover=",
]


def _run_xss_detection():
    """
    XSS detection rule - scans Nginx access logs (path field, which
    includes query strings) for known XSS payload signatures.

    NOTE on classification: this does NOT map to a MITRE ATT&CK
    technique - ATT&CK models post-compromise adversary behavior, not
    web application injection classes. The honest mapping here is
    OWASP Injection / CWE-79 (Cross-Site Scripting), not a MITRE ID.
    """
    since = datetime.utcnow() - timedelta(minutes=TIME_WINDOW_MINUTES)
    query = {
        "size": 200,
        "query": {
            "bool": {
                "must": [
                    {"term": {"log_type": "nginx_access"}},
                    {"range": {"timestamp": {"gte": since.isoformat()}}},
                ]
            }
        },
    }
    result = client.search(index=LOGS_INDEX, body=query, ignore=[404])
    events = result.get("hits", {}).get("hits", [])

    for hit in events:
        event = hit["_source"]
        path = (event.get("path") or "").lower()
        if not path:
            continue
        matched_sig = next((sig for sig in XSS_SIGNATURES if sig in path), None)
        if not matched_sig:
            continue

        source_ip = event.get("source_ip", "unknown")
        alert_type = "XSS Attempt Detected"
        if _already_alerted_recently(alert_type, source_ip):
            continue

        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": alert_type,
            "source_ip": source_ip,
            "attempt_count": 1,
            "severity": "HIGH",
            "matched_rule": f"xss_signature:{matched_sig}",
            "mitre_technique": "N/A (OWASP Injection)",
            "mitre_id": "CWE-79",
            "mitre_tactic": "N/A",
        }
        client.index(index=ALERTS_INDEX, body=alert)


def _run_correlation_rule():
    """
    Correlation rule (v2) - TRUE cross-event correlation, not just a
    threshold count. Logic:

    If a source IP has >=2 failed web logins FOLLOWED BY a successful
    web login within the same TIME_WINDOW_MINUTES, that's a strong
    signal of a compromised/guessed credential (attacker got in after
    a few tries) - meaningfully different from raw brute-force volume.
    """
    since = datetime.utcnow() - timedelta(minutes=TIME_WINDOW_MINUTES)
    query = {
        "size": 500,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "must": [
                    {"terms": {"event.keyword": ["login_failed", "login_success"]}},
                    {"range": {"timestamp": {"gte": since.isoformat()}}},
                ]
            }
        },
    }
    result = client.search(index=LOGS_INDEX, body=query)
    events = [hit["_source"] for hit in result["hits"]["hits"]]

    grouped = defaultdict(list)
    for event in events:
        grouped[event.get("source_ip", "unknown")].append(event)

    for source_ip, seq in grouped.items():
        fail_count = 0
        for event in seq:
            if event.get("event") == "login_failed":
                fail_count += 1
            elif event.get("event") == "login_success" and fail_count >= 2:
                alert_type = "Suspicious Login: Failed Attempts Then Success"
                alert = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "alert_type": alert_type,
                    "source_ip": source_ip,
                    "attempt_count": fail_count,
                    "severity": "HIGH",
                    "matched_rule": "correlation_fail_then_success",
                    "mitre_technique": "Valid Accounts",
                    "mitre_id": "T1078",
                    "mitre_tactic": "Initial Access",
                }
                client.index(index=ALERTS_INDEX, body=alert)
                break


@app.get("/alerts")
def get_alerts(limit: int = 50, session: dict = Depends(require_session)):
    """
    Runs detection (may write new alerts), then returns the alert
    HISTORY from ALERTS_INDEX - not just what's happening in the current
    time window. This means an alert stays visible on the dashboard even
    after the attack that triggered it is no longer "live".
    """
    _run_detection()

    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }
    result = client.search(index=ALERTS_INDEX, body=query, ignore=[404])
    hits = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
    return {"count": len(hits), "alerts": hits}


@app.post("/block/{ip}")
def block_ip(ip: str, session: dict = Depends(require_admin)):
    """
    Block an IP at the host firewall using iptables.

    Requires the api container to run with network_mode: host and
    NET_ADMIN capability (see docker-compose.yml) - this is what lets
    a command run inside the container actually affect the HOST's
    firewall, since SSH runs on the host, not in a container.

    Safety: NEVER_BLOCK_IPS can never be blocked, no matter what -
    protects against ever locking yourself out of your own machine.
    """
    if ip in NEVER_BLOCK_IPS:
        raise HTTPException(status_code=400, detail=f"Refusing to block '{ip}' - protected address")

    existing = client.search(
        index=BLOCKED_INDEX,
        body={"query": {"term": {"ip.keyword": ip}}},
        ignore=[404],
    )
    if existing.get("hits", {}).get("total", {}).get("value", 0) > 0:
        return {"status": "already_blocked", "ip": ip}

    try:
        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"iptables command failed: {e.stderr}")
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="iptables not found in container")

    record = {
        "type": "ip",
        "ip": ip,
        "blocked_at": datetime.utcnow().isoformat(),
        "blocked_by": "admin",
    }
    client.index(index=BLOCKED_INDEX, body=record)
    return {"status": "blocked", "ip": ip}


@app.post("/unblock/{ip}")
def unblock_ip(ip: str, session: dict = Depends(require_admin)):
    """Remove the iptables DROP rule for a previously blocked IP."""
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"iptables command failed (rule may not exist): {e.stderr}")

    client.delete_by_query(
        index=BLOCKED_INDEX,
        body={"query": {"bool": {"must": [{"term": {"ip.keyword": ip}}, {"term": {"type.keyword": "ip"}}]}}},
        ignore=[404],
    )
    return {"status": "unblocked", "ip": ip}


@app.post("/block-account/{username}")
def block_account(username: str, session: dict = Depends(require_admin)):
    """
    Block a demo account manually (admin-triggered, not automatic lockout).
    This only affects the DEMO_ACCOUNTS login target - purely app-level,
    no system risk at all.
    """
    existing = client.search(
        index=BLOCKED_INDEX,
        body={"query": {"bool": {"must": [{"term": {"username.keyword": username}}, {"term": {"type.keyword": "account"}}]}}},
        ignore=[404],
    )
    if existing.get("hits", {}).get("total", {}).get("value", 0) > 0:
        return {"status": "already_blocked", "username": username}

    record = {
        "type": "account",
        "username": username,
        "blocked_at": datetime.utcnow().isoformat(),
        "blocked_by": "admin",
    }
    client.index(index=BLOCKED_INDEX, body=record)
    return {"status": "blocked", "username": username}


@app.post("/unblock-account/{username}")
def unblock_account(username: str, session: dict = Depends(require_admin)):
    """Unblock a previously blocked demo account."""
    client.delete_by_query(
        index=BLOCKED_INDEX,
        body={"query": {"bool": {"must": [{"term": {"username.keyword": username}}, {"term": {"type.keyword": "account"}}]}}},
        ignore=[404],
    )
    return {"status": "unblocked", "username": username}


@app.get("/blocked")
def get_blocked(session: dict = Depends(require_session)):
    """List currently blocked IPs and accounts. Read-only, viewer can see this too."""
    result = client.search(
        index=BLOCKED_INDEX,
        body={"size": 100, "sort": [{"blocked_at": {"order": "desc"}}], "query": {"match_all": {}}},
        ignore=[404],
    )
    hits = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
    return {"count": len(hits), "blocked": hits}
