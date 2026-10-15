"""
Micro-SIEM API - FastAPI backend

Logic overview (this is the part that matters for your viva):
1. Connect to OpenSearch (where Vector already pushed web login + Nginx events)
2. /logs endpoint -> just returns recent raw log events
3. /login endpoint -> demo web login page posts here; every attempt is logged
4. Detection runs in a BACKGROUND LOOP every few seconds, whether or not a
   dashboard is open, and PERSISTS alerts once triggered. /alerts only reads
   the alert history (an alert stays visible after the original attempts age
   out of the detection window - it's a historical record, like real SIEMs).
5. Detection rules:
   - Brute force: 5 failed web logins against the SAME username from the same
     source within 2 minutes
   - Password spraying: failed logins against 3+ different usernames from
     the same source within 5 minutes
   - Correlation: failed attempts followed by a success from the same source
   - XSS: known payload signatures in (URL-decoded) Nginx request paths
"""

import os
import json
import socket
import asyncio
import logging
import secrets
import subprocess
import ipaddress
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from collections import defaultdict
from urllib.parse import unquote_plus

from fastapi import FastAPI, Request, HTTPException, Header, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from opensearchpy import OpenSearch, helpers
from opensearchpy.exceptions import ConflictError, NotFoundError

logger = logging.getLogger("micro-siem")

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

FAILED_LOGIN_THRESHOLD = 5      # how many failed attempts on one username...
TIME_WINDOW_MINUTES = 2         # ...within this many minutes = alert

# Password spraying: few attempts per account but across MANY accounts, so
# it stays under the brute-force threshold. Spraying is deliberately slow,
# hence a wider window than brute force.
SPRAY_USERNAME_THRESHOLD = 3    # distinct usernames failed from one IP...
SPRAY_WINDOW_MINUTES = 5        # ...within this many minutes = alert

# How long to wait before allowing the SAME alert (same type + source)
# to fire again - prevents writing a new alert doc on every detection run
# while an attack is still ongoing.
ALERT_DEDUPE_MINUTES = 5

# Login events the brute-force and spraying rules count as password guesses.
# An attempt on a blocked account is refused before the password is even
# checked, but it is still an attacker guessing - without login_blocked here,
# hammering a blocked account would raise no alert at all.
GUESS_EVENTS = ("login_failed", "login_blocked")

# Detection runs on its own every few seconds (see _detection_loop), so an
# attack is caught even when nobody has a dashboard open.
DETECTION_INTERVAL_SECONDS = 5

# Aggregations return buckets instead of raw events, so a big attack is
# counted in full rather than capped at a fixed number of fetched events.
AGG_BUCKET_LIMIT = 1000

# Upper bound for the ?limit= parameter on /logs and /alerts (OpenSearch
# rejects anything past its 10,000-result window with a 500).
MAX_RESULTS = 1000

# Only these peers may tell us the real client IP via X-Real-IP: our own
# Nginx containers reach the API from the Docker bridge range, and local
# tools from loopback. Anyone else is calling port 8000 directly, so their
# forwarding headers are ignored and the TCP peer address is used instead.
# (The Nginx containers do the same check for X-Forwarded-For with
# set_real_ip_from, so a remote attacker can't spoof their IP.)
DOCKER_NETWORKS = [ipaddress.ip_network("172.16.0.0/12")]
TRUSTED_PROXY_NETWORKS = DOCKER_NETWORKS + [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
]

# IP and account blocking are switched off for now (planned for a future
# version). While False, the block/unblock endpoints refuse every request,
# so no iptables rule is ever run and no account gets locked.
BLOCKING_ENABLED = False

# INPUT covers traffic to the host itself (e.g. the API on :8000).
# DOCKER-USER covers traffic Docker forwards to published container ports
# (8080, 8090) - that never passes through INPUT, so both are needed.
FIREWALL_CHAINS = ["INPUT", "DOCKER-USER"]


def _require_blocking_enabled():
    if not BLOCKING_ENABLED:
        raise HTTPException(status_code=503, detail="Blocking is disabled - coming in a future version")

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
demo_sessions = {}  # token -> {"username": str, "expires": datetime}

# --- Dashboard admin/viewer session auth ---
# Passwords come from the environment (docker-compose reads them from the
# git-ignored .env file), so they are not committed to the repository.
# A missing password means that account simply cannot log in.
DASHBOARD_USERS = {
    "admin": {"password": os.getenv("DASHBOARD_ADMIN_PASSWORD"), "role": "admin"},
    "viewer": {"password": os.getenv("DASHBOARD_VIEWER_PASSWORD"), "role": "viewer"},
}
SESSION_TTL_HOURS = 8
sessions = {}  # token -> {"role": str, "expires": datetime}

# Dashboard login rate limit: after this many failures from one IP within
# the window, further attempts are refused with 429 until the window passes.
DASHBOARD_LOGIN_MAX_FAILURES = 5
DASHBOARD_LOGIN_WINDOW_MINUTES = 5
dashboard_login_failures = defaultdict(list)  # ip -> [datetime of each failure]


def _valid_ip(value: str):
    """Return the normalised IP string, or None if value isn't an IP address."""
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


def _in_networks(ip: str, networks) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr.version == net.version and addr in net for net in networks)


def get_client_ip(request: Request) -> str:
    """
    Real client IP for logging and detection.

    X-Real-IP is only trusted when the request comes from our own Nginx
    (Docker bridge range) or loopback, and only if it is a valid IP address.
    Otherwise the TCP peer address is used - so a client can't put fake IPs
    or HTML into the logs by sending its own headers.
    """
    peer = request.client.host if request.client else "unknown"
    if _in_networks(peer, TRUSTED_PROXY_NETWORKS):
        forwarded = _valid_ip(request.headers.get("x-real-ip", ""))
        if forwarded:
            return forwarded
    return _valid_ip(peer) or "unknown"


def _prune_sessions():
    """Drop expired dashboard and demo sessions so the dicts don't grow forever."""
    now = datetime.utcnow()
    for store in (sessions, demo_sessions):
        for token in [t for t, s in store.items() if now > s["expires"]]:
            del store[token]


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


def _account_blocked(username: str) -> bool:
    result = client.search(
        index=BLOCKED_INDEX,
        body={"query": {"bool": {"must": [{"term": {"username.keyword": username}}, {"term": {"type.keyword": "account"}}]}}},
        ignore=[404],
    )
    return result.get("hits", {}).get("total", {}).get("value", 0) > 0


async def _detection_loop():
    """Run every detection rule every DETECTION_INTERVAL_SECONDS, forever."""
    while True:
        try:
            await asyncio.to_thread(_run_detection)
        except Exception:
            # e.g. OpenSearch still starting up - just try again next round
            logger.exception("Detection run failed")
        await asyncio.sleep(DETECTION_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if BLOCKING_ENABLED:
        try:
            await asyncio.to_thread(_restore_firewall_rules)
        except Exception:
            logger.exception("Could not restore firewall rules from blocked-index")
    task = asyncio.create_task(_detection_loop())
    yield
    task.cancel()


app = FastAPI(title="Micro-SIEM API", lifespan=lifespan)

# CORS: the dashboards now call the API through their own Nginx (/api/),
# so they don't need this - it's kept so a dashboard pointed straight at
# :8000 via window.MICRO_SIEM_API_URL still works. Every data endpoint
# needs a Bearer token anyway, which other sites can't read.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


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
       a real log source, alongside the Nginx access log
    """
    source_ip = get_client_ip(request)
    username = payload.username
    now = datetime.utcnow()

    # Check if this account has been manually blocked by an admin
    if _account_blocked(username):
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
        _prune_sessions()
        demo_token = secrets.token_hex(16)
        demo_sessions[demo_token] = {"username": username, "expires": now + timedelta(hours=SESSION_TTL_HOURS)}
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
    1. The demo session token is real and not expired
    2. The account behind it hasn't been blocked since login

    If blocked, search.html clears its stored token and redirects
    back to login.html - this is checked on page load only, not
    live-polled, so an already-open tab won't be kicked out mid-session,
    only on next load/navigation.
    """
    session = demo_sessions.get(token)
    if not session:
        return {"valid": False, "reason": "invalid session"}
    if datetime.utcnow() > session["expires"]:
        demo_sessions.pop(token, None)
        return {"valid": False, "reason": "session expired"}

    username = session["username"]
    if _account_blocked(username):
        demo_sessions.pop(token, None)
        return {"valid": False, "reason": "account has been blocked"}

    return {"valid": True, "username": username}


@app.post("/auth/login")
def dashboard_login(payload: DashboardLoginRequest, request: Request):
    """
    Dashboard login (admin/viewer) - NOT the demo attack-target /login above.
    On success, issues a random opaque session token (real server-side
    session, not a client-side trick) valid for SESSION_TTL_HOURS.

    Every attempt is logged (log_type "dashboard_login") so the SIEM also
    records attacks on itself, and an IP is rate-limited after
    DASHBOARD_LOGIN_MAX_FAILURES failures in DASHBOARD_LOGIN_WINDOW_MINUTES.
    """
    source_ip = get_client_ip(request)
    now = datetime.utcnow()
    log_event = {
        "timestamp": now.isoformat(),
        "log_type": "dashboard_login",
        "username": payload.username,
        "source_ip": source_ip,
    }

    window_start = now - timedelta(minutes=DASHBOARD_LOGIN_WINDOW_MINUTES)
    recent = [t for t in dashboard_login_failures[source_ip] if t > window_start]
    dashboard_login_failures[source_ip] = recent
    if len(recent) >= DASHBOARD_LOGIN_MAX_FAILURES:
        write_webapp_log({**log_event, "event": "dashboard_login_rate_limited", "result": "blocked"})
        raise HTTPException(status_code=429, detail="Too many failed attempts - try again in a few minutes")

    user = DASHBOARD_USERS.get(payload.username)
    password_ok = bool(user and user["password"]) and secrets.compare_digest(
        user["password"].encode(), payload.password.encode()
    )
    if not password_ok:
        dashboard_login_failures[source_ip].append(now)
        write_webapp_log({**log_event, "event": "dashboard_login_failed", "result": "failed"})
        raise HTTPException(status_code=401, detail="Invalid username or password")

    dashboard_login_failures.pop(source_ip, None)
    write_webapp_log({**log_event, "event": "dashboard_login_success", "result": "success"})
    _prune_sessions()
    token = secrets.token_hex(24)
    sessions[token] = {
        "role": user["role"],
        "expires": now + timedelta(hours=SESSION_TTL_HOURS),
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
def get_logs(limit: int = Query(50, ge=1, le=MAX_RESULTS), session: dict = Depends(require_session)):
    """Return the most recent raw log events from OpenSearch. Requires a valid session."""
    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }
    # ignore=[404]: logs-index only exists once Vector has shipped the first event
    result = client.search(index=LOGS_INDEX, body=query, ignore=[404])
    hits = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
    return {"count": len(hits), "logs": hits}



def _already_alerted_recently(alert_type: str, source_ip: str) -> bool:
    """
    Check if an alert of this type+source was already raised within
    ALERT_DEDUPE_MINUTES. Prevents inserting a new alert document on every
    detection run while the same attack is still ongoing.
    Every rule calls this before writing an alert; _write_alert() then
    closes the remaining race if two detection runs ever overlap.
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


def _write_alert(alert: dict):
    """
    Write an alert at most once per alert type + source IP + dedupe window.

    The document ID is built from those three values and written with
    create(), which OpenSearch rejects if that ID already exists. So if two
    detection runs ever overlap and both pass the _already_alerted_recently()
    check, only the first write succeeds.
    refresh="wait_for" makes the alert searchable before the next detection run.
    """
    window = int(datetime.utcnow().timestamp() // (ALERT_DEDUPE_MINUTES * 60))
    doc_id = f"{alert['alert_type']}|{alert['source_ip']}|{window}"
    try:
        client.create(index=ALERTS_INDEX, id=doc_id, body=alert, refresh="wait_for")
    except ConflictError:
        pass  # another detection run already wrote this alert


def _failed_logins_since(since: datetime, events=("login_failed",)) -> dict:
    """Query clause: demo web logins with one of `events` at or after `since`."""
    return {
        "bool": {
            "filter": [
                {"terms": {"event.keyword": list(events)}},
                {"range": {"timestamp": {"gte": since.isoformat()}}},
            ]
        }
    }


def _buckets(result: dict, agg_name: str) -> list:
    return result.get("aggregations", {}).get(agg_name, {}).get("buckets", [])


def _run_detection():
    """
    Run every detection rule once. Called by the background loop.

    New alerts are written to ALERTS_INDEX (permanent record).
    Deduping avoids writing a duplicate alert every few seconds while
    the same attack is still active.
    """
    _run_brute_force_rule()
    _run_password_spraying_rule()
    _run_correlation_rule()
    _run_xss_detection()


def _run_brute_force_rule():
    """
    Brute force rule (MITRE T1110): many passwords tried against ONE account.

    If one source IP has FAILED_LOGIN_THRESHOLD or more failed web logins
    against the same username within TIME_WINDOW_MINUTES, raise an alert.
    Counting per username (not just per IP) keeps this separate from
    password spraying, where each account only gets one or two tries.
    Attempts on a blocked account count too (GUESS_EVENTS).

    Uses an aggregation (count per IP, then per username) so OpenSearch does
    the counting - no cap on how many events a big attack can have.
    """
    since = datetime.utcnow() - timedelta(minutes=TIME_WINDOW_MINUTES)
    query = {
        "size": 0,
        "query": _failed_logins_since(since, GUESS_EVENTS),
        "aggs": {
            "by_ip": {
                "terms": {"field": "source_ip.keyword", "size": AGG_BUCKET_LIMIT},
                "aggs": {
                    "by_user": {
                        "terms": {
                            "field": "username.keyword",
                            "size": AGG_BUCKET_LIMIT,
                            "min_doc_count": FAILED_LOGIN_THRESHOLD,
                        }
                    }
                },
            }
        },
    }
    result = client.search(index=LOGS_INDEX, body=query, ignore=[404])

    alert_type = "Web Login Brute Force"
    for ip_bucket in _buckets(result, "by_ip"):
        user_buckets = ip_bucket.get("by_user", {}).get("buckets", [])
        if not user_buckets:
            continue
        source_ip = ip_bucket["key"]
        if _already_alerted_recently(alert_type, source_ip):
            continue

        top = max(user_buckets, key=lambda b: b["doc_count"])
        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": alert_type,
            "source_ip": source_ip,
            "target_username": top["key"],
            "attempt_count": top["doc_count"],
            "severity": "HIGH",
            "matched_rule": f"{FAILED_LOGIN_THRESHOLD}_failed_web_logins_same_user_{TIME_WINDOW_MINUTES}min",
            "mitre_technique": "Brute Force",
            "mitre_id": "T1110",
            "mitre_tactic": "Credential Access",
        }
        _write_alert(alert)


# Signatures checked against Nginx request paths - simple pattern matching,
# same approach real basic WAFs use at a signature level (not ML-based).
XSS_SIGNATURES = [
    "<script", "onerror=", "onload=", "javascript:", "alert(",
    "%3cscript", "document.cookie", "<img", "<svg", "onmouseover=",
]


def _decoded_path(path: str) -> str:
    """
    URL-decode the request path (twice, to also catch double-encoding) and
    lowercase it. Browsers send `<img onerror=...>` as `%3Cimg%20onerror%3D...`,
    so matching the raw path would miss most real payloads.
    """
    decoded = path
    for _ in range(2):
        decoded = unquote_plus(decoded)
    return decoded.lower()


def _run_xss_detection():
    """
    XSS detection rule - scans Nginx access logs (path field, which
    includes query strings) for known XSS payload signatures.

    Uses helpers.scan() to page through EVERY request in the window rather
    than a fixed-size search, so a burst of normal traffic can't push the
    attack request out of view.

    NOTE on classification: this does NOT map to a MITRE ATT&CK
    technique - ATT&CK models post-compromise adversary behavior, not
    web application injection classes. The honest mapping here is
    OWASP Injection / CWE-79 (Cross-Site Scripting), not a MITRE ID.
    """
    since = datetime.utcnow() - timedelta(minutes=TIME_WINDOW_MINUTES)
    query = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"log_type.keyword": "nginx_access"}},
                    {"range": {"timestamp": {"gte": since.isoformat()}}},
                ]
            }
        },
    }

    hits_by_ip = defaultdict(list)  # source_ip -> [matched signature per request]
    try:
        for hit in helpers.scan(client, index=LOGS_INDEX, query=query):
            event = hit["_source"]
            path = _decoded_path(event.get("path") or "")
            matched_sig = next((sig for sig in XSS_SIGNATURES if sig in path), None)
            if matched_sig:
                hits_by_ip[event.get("source_ip", "unknown")].append(matched_sig)
    except NotFoundError:
        return  # logs-index doesn't exist yet

    alert_type = "XSS Attempt Detected"
    for source_ip, sigs in hits_by_ip.items():
        if _already_alerted_recently(alert_type, source_ip):
            continue

        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": alert_type,
            "source_ip": source_ip,
            "attempt_count": len(sigs),
            "severity": "HIGH",
            "matched_rule": f"xss_signature:{sigs[0]}",
            "mitre_technique": "N/A (OWASP Injection)",
            "mitre_id": "CWE-79",
            "mitre_tactic": "N/A",
        }
        _write_alert(alert)


def _run_correlation_rule():
    """
    Correlation rule (v2) - TRUE cross-event correlation, not just a
    threshold count. Logic:

    If a source IP has >=2 failed web logins FOLLOWED BY a successful
    web login within the same TIME_WINDOW_MINUTES, that's a strong
    signal of a compromised/guessed credential (attacker got in after
    a few tries) - meaningfully different from raw brute-force volume.

    Step 1: find each IP's latest successful login in the window.
    Step 2: count that IP's failures in the window BEFORE that success.
    """
    since = datetime.utcnow() - timedelta(minutes=TIME_WINDOW_MINUTES)
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"event.keyword": "login_success"}},
                    {"range": {"timestamp": {"gte": since.isoformat()}}},
                ]
            }
        },
        "aggs": {
            "by_ip": {
                "terms": {"field": "source_ip.keyword", "size": AGG_BUCKET_LIMIT},
                "aggs": {"last_success": {"max": {"field": "timestamp"}}},
            }
        },
    }
    result = client.search(index=LOGS_INDEX, body=query, ignore=[404])

    alert_type = "Suspicious Login: Failed Attempts Then Success"
    for ip_bucket in _buckets(result, "by_ip"):
        source_ip = ip_bucket["key"]
        last_success_ms = ip_bucket["last_success"]["value"]

        fail_query = _failed_logins_since(since)
        fail_query["bool"]["filter"] += [
            {"term": {"source_ip.keyword": source_ip}},
            {"range": {"timestamp": {"lt": int(last_success_ms), "format": "epoch_millis"}}},
        ]
        fail_count = client.count(index=LOGS_INDEX, body={"query": fail_query}, ignore=[404]).get("count", 0)
        if fail_count < 2:
            continue
        if _already_alerted_recently(alert_type, source_ip):
            continue

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
        _write_alert(alert)


def _run_password_spraying_rule():
    """
    Password spraying rule (MITRE T1110.003). Brute force tries MANY
    passwords against ONE account; spraying tries one or two common
    passwords against MANY accounts, so no single account collects enough
    failures to trip the brute-force threshold (or a lockout). Logic:

    If one source IP has failed web logins against SPRAY_USERNAME_THRESHOLD
    or more DIFFERENT usernames within SPRAY_WINDOW_MINUTES, raise an alert.
    The key difference from brute force: count distinct usernames, not events.
    Attempts on blocked accounts count too (GUESS_EVENTS).
    """
    since = datetime.utcnow() - timedelta(minutes=SPRAY_WINDOW_MINUTES)
    query = {
        "size": 0,
        "query": _failed_logins_since(since, GUESS_EVENTS),
        "aggs": {
            "by_ip": {
                "terms": {"field": "source_ip.keyword", "size": AGG_BUCKET_LIMIT},
                "aggs": {"by_user": {"terms": {"field": "username.keyword", "size": AGG_BUCKET_LIMIT}}},
            }
        },
    }
    result = client.search(index=LOGS_INDEX, body=query, ignore=[404])

    alert_type = "Password Spraying Attack"
    for ip_bucket in _buckets(result, "by_ip"):
        # Case/whitespace variants of one name ("Admin", "admin ") count once
        usernames = {
            b["key"].strip().lower()
            for b in ip_bucket.get("by_user", {}).get("buckets", [])
            if b["key"].strip()
        }
        if len(usernames) < SPRAY_USERNAME_THRESHOLD:
            continue
        source_ip = ip_bucket["key"]
        if _already_alerted_recently(alert_type, source_ip):
            continue

        alert = {
            "timestamp": datetime.utcnow().isoformat(),
            "alert_type": alert_type,
            "source_ip": source_ip,
            "attempt_count": len(usernames),
            "severity": "HIGH",
            "matched_rule": f"{SPRAY_USERNAME_THRESHOLD}_distinct_usernames_{SPRAY_WINDOW_MINUTES}min",
            "mitre_technique": "Password Spraying",
            "mitre_id": "T1110.003",
            "mitre_tactic": "Credential Access",
        }
        _write_alert(alert)


@app.get("/alerts")
def get_alerts(limit: int = Query(50, ge=1, le=MAX_RESULTS), session: dict = Depends(require_session)):
    """
    Returns the alert HISTORY from ALERTS_INDEX - not just what's happening
    in the current time window. Detection itself runs in the background
    loop, so this endpoint only reads. An alert stays visible on the
    dashboard even after the attack that triggered it is no longer "live".
    """
    query = {
        "size": limit,
        "sort": [{"timestamp": {"order": "desc"}}],
        "query": {"match_all": {}},
    }
    result = client.search(index=ALERTS_INDEX, body=query, ignore=[404])
    hits = [hit["_source"] for hit in result.get("hits", {}).get("hits", [])]
    return {"count": len(hits), "alerts": hits}


def _parse_block_target(ip: str) -> str:
    """
    Validate and normalise an IP for blocking (so "0:0::1" and "::1" are the
    same address), and refuse anything that would lock us out:
    loopback/unspecified/link-local/multicast, this machine's own addresses,
    and the Docker bridge range Nginx uses to reach the API.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        raise HTTPException(status_code=400, detail=f"'{ip}' is not a valid IP address")
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    normalised = str(addr)

    if (addr.is_loopback or addr.is_unspecified or addr.is_link_local or addr.is_multicast
            or normalised in _own_addresses() or _in_networks(normalised, DOCKER_NETWORKS)):
        raise HTTPException(status_code=400, detail=f"Refusing to block '{normalised}' - protected address")
    return normalised


def _own_addresses() -> set:
    """
    This machine's own primary IPv4/IPv6 addresses (the API shares the host's
    network). Connecting a UDP socket sends no packets - it only asks the
    kernel which local address it would use to reach the outside.
    """
    addrs = set()
    for family, probe in ((socket.AF_INET, "192.0.2.1"), (socket.AF_INET6, "2001:db8::1")):
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.connect((probe, 9))
                addrs.add(str(ipaddress.ip_address(s.getsockname()[0].split("%")[0])))
        except OSError:
            pass
    return addrs


def _firewall_tool_for(ip: str) -> str:
    """
    iptables only understands IPv4, ip6tables only understands IPv6 -
    they are separate tools, not one universal command. This picks the
    right one based on the actual address format.
    """
    return "ip6tables" if ipaddress.ip_address(ip).version == 6 else "iptables"


def _iptables(tool: str, action: str, chain: str, ip: str) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            [tool, action, chain, "-s", ip, "-j", "DROP"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail=f"{tool} not found in container")


def _apply_firewall_block(ip: str):
    """
    Add a DROP rule for ip to every chain in FIREWALL_CHAINS (skipping chains
    that already have it). INPUT must succeed; DOCKER-USER only exists once
    Docker has set up its rules (and may not exist for IPv6), so a missing
    DOCKER-USER chain is tolerated.
    """
    tool = _firewall_tool_for(ip)
    for chain in FIREWALL_CHAINS:
        if _iptables(tool, "-C", chain, ip).returncode == 0:
            continue  # rule already present
        result = _iptables(tool, "-I", chain, ip)
        if result.returncode != 0:
            if chain == "INPUT":
                raise HTTPException(status_code=500, detail=f"{tool} command failed: {result.stderr}")
            logger.warning("Could not add %s rule in %s for %s: %s", tool, chain, ip, result.stderr)


def _remove_firewall_block(ip: str):
    """
    Remove the DROP rule(s) for ip. A rule that's already gone (e.g. after a
    reboot, since iptables rules don't persist) is not an error - unblocking
    must always succeed so the blocklist can't get stuck.
    """
    tool = _firewall_tool_for(ip)
    for chain in FIREWALL_CHAINS:
        while _iptables(tool, "-C", chain, ip).returncode == 0:
            _iptables(tool, "-D", chain, ip)


def _restore_firewall_rules():
    """
    On API startup, re-apply a DROP rule for every IP in blocked-index.
    iptables rules are lost on reboot but the index record survives, so
    without this the dashboard would show IPs as blocked that aren't.
    """
    result = client.search(
        index=BLOCKED_INDEX,
        body={"size": MAX_RESULTS, "query": {"term": {"type.keyword": "ip"}}},
        ignore=[404],
    )
    for hit in result.get("hits", {}).get("hits", []):
        ip = hit["_source"].get("ip")
        if _valid_ip(ip):
            try:
                _apply_firewall_block(ip)
            except HTTPException as e:
                logger.warning("Could not restore block for %s: %s", ip, e.detail)


@app.post("/block/{ip}")
def block_ip(ip: str, session: dict = Depends(require_admin)):
    """
    Block an IP at the host firewall using iptables (IPv4) or
    ip6tables (IPv6) - picked automatically based on address format.

    The rule goes into INPUT (traffic to the host itself, e.g. the API) and
    DOCKER-USER (traffic to published container ports like 8080/8090).

    Requires the api container to run with network_mode: host and
    NET_ADMIN capability (see docker-compose.yml) - this is what lets
    a command run inside the container actually affect the HOST's
    firewall, not just the container's own network namespace.

    Safety: _parse_block_target() refuses loopback, this machine's own
    addresses and the Docker range, no matter what - protects against ever
    locking yourself out of your own machine.
    """
    _require_blocking_enabled()
    ip = _parse_block_target(ip)

    existing = client.search(
        index=BLOCKED_INDEX,
        body={"query": {"term": {"ip.keyword": ip}}},
        ignore=[404],
    )
    if existing.get("hits", {}).get("total", {}).get("value", 0) > 0:
        return {"status": "already_blocked", "ip": ip}

    _apply_firewall_block(ip)

    record = {
        "type": "ip",
        "ip": ip,
        "blocked_at": datetime.utcnow().isoformat(),
        "blocked_by": "admin",
    }
    client.index(index=BLOCKED_INDEX, body=record, refresh="wait_for")
    return {"status": "blocked", "ip": ip}


@app.post("/unblock/{ip}")
def unblock_ip(ip: str, session: dict = Depends(require_admin)):
    """Remove the DROP rule(s) for a previously blocked IP (IPv4 or IPv6)."""
    _require_blocking_enabled()
    normalised = _valid_ip(ip)
    if not normalised:
        raise HTTPException(status_code=400, detail=f"'{ip}' is not a valid IP address")

    _remove_firewall_block(normalised)
    client.delete_by_query(
        index=BLOCKED_INDEX,
        body={"query": {"bool": {"must": [{"term": {"ip.keyword": normalised}}, {"term": {"type.keyword": "ip"}}]}}},
        ignore=[404],
        refresh=True,
    )
    return {"status": "unblocked", "ip": normalised}


@app.post("/block-account/{username}")
def block_account(username: str, session: dict = Depends(require_admin)):
    """
    Block a demo account manually (admin-triggered, not automatic lockout).
    This only affects the DEMO_ACCOUNTS login target - purely app-level,
    no system risk at all.
    """
    _require_blocking_enabled()
    if _account_blocked(username):
        return {"status": "already_blocked", "username": username}

    record = {
        "type": "account",
        "username": username,
        "blocked_at": datetime.utcnow().isoformat(),
        "blocked_by": "admin",
    }
    client.index(index=BLOCKED_INDEX, body=record, refresh="wait_for")
    return {"status": "blocked", "username": username}


@app.post("/unblock-account/{username}")
def unblock_account(username: str, session: dict = Depends(require_admin)):
    """Unblock a previously blocked demo account."""
    _require_blocking_enabled()
    client.delete_by_query(
        index=BLOCKED_INDEX,
        body={"query": {"bool": {"must": [{"term": {"username.keyword": username}}, {"term": {"type.keyword": "account"}}]}}},
        ignore=[404],
        refresh=True,
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
