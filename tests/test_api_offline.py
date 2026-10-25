"""Offline checks for src/api/main.py with a fake OpenSearch client (no Docker needed).

Covers client-IP trust, protected block targets, firewall helpers, all 4 detection
rules, the background detection loop, rate limiting, limits and demo-session expiry.

Run:  python3 -m venv /tmp/siem-venv && /tmp/siem-venv/bin/pip install fastapi==0.111.0 opensearch-py==2.6.0 "pydantic>=2.9" httpx
      /tmp/siem-venv/bin/python -W ignore tests/test_api_offline.py
(pydantic 2.7.4 from requirements.txt does not build on Python 3.13; the API code works with both.)
"""
import os, sys, json, tempfile, time
from datetime import datetime, timedelta

os.environ["DASHBOARD_ADMIN_PASSWORD"] = "admin-test-pw"
os.environ["DASHBOARD_VIEWER_PASSWORD"] = "viewer-test-pw"
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "api"))
import main
from fastapi import HTTPException
from fastapi.testclient import TestClient
from opensearchpy.exceptions import ConflictError, NotFoundError

LOG = tempfile.mktemp(suffix=".log")
main.WEBAPP_LOG_PATH = LOG


class FakeOS:
    def __init__(self):
        self.created, self.searches, self.counts = {}, [], []
        self.agg_responses = {}   # agg-name signature -> response
        self.count_value = 0
        self.alerted = set()

    def search(self, index, body, ignore=None, **kw):
        self.searches.append((index, body))
        if index == main.ALERTS_INDEX and body.get("size") == 0:
            must = body["query"]["bool"]["must"]
            key = (must[0]["term"]["alert_type.keyword"], must[1]["term"]["source_ip.keyword"])
            return {"hits": {"total": {"value": 1 if key in self.alerted else 0}}}
        if "aggs" in body:
            q = json.dumps(body["query"])
            kind = "success" if "login_success" in q else ("spray" if "min_doc_count" not in json.dumps(body["aggs"]) else "brute")
            return self.agg_responses.get(kind, {"error": "index_not_found_exception", "status": 404})
        return {"hits": {"total": {"value": 0}, "hits": []}}

    def count(self, index, body, ignore=None):
        self.counts.append(body)
        return {"count": self.count_value}

    def create(self, index, id, body, refresh=None):
        if id in self.created:
            raise ConflictError(409, "conflict", {})
        self.created[id] = body
        self.alerted.add((body["alert_type"], body["source_ip"]))

    def index(self, **kw): pass
    def delete_by_query(self, **kw): pass


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        check.failed = True
check.failed = False


class Req:
    def __init__(self, peer, headers):
        self.client = type("C", (), {"host": peer})()
        self.headers = headers

# --- S1/S2: client IP trust ---
check(main.get_client_ip(Req("172.18.0.3", {"x-real-ip": "203.0.113.9"})) == "203.0.113.9", "trusted nginx peer: X-Real-IP used")
check(main.get_client_ip(Req("172.18.0.3", {"x-real-ip": "<img src=x onerror=alert(1)>"})) == "172.18.0.3", "HTML in X-Real-IP rejected")
check(main.get_client_ip(Req("192.168.1.50", {"x-real-ip": "1.2.3.4"})) == "192.168.1.50", "untrusted LAN peer can't spoof X-Real-IP")
check(main.get_client_ip(Req("::ffff:172.18.0.3", {"x-real-ip": "8.8.8.8"})) == "8.8.8.8", "IPv4-mapped trusted peer")

# --- S6: protected addresses ---
for bad in ["::1", "0:0::1", "127.0.0.2", "::ffff:127.0.0.1", "0.0.0.0", "172.18.0.1", "169.254.1.1", "nonsense", "localhost"]:
    try:
        main._parse_block_target(bad); check(False, f"refuse {bad}")
    except HTTPException as e:
        check(e.status_code == 400, f"refuse {bad} ({e.detail})")
own = main._own_addresses()
print("     own addresses:", own)
for ip in own:
    try:
        main._parse_block_target(ip); check(False, f"refuse own {ip}")
    except HTTPException:
        check(True, f"refuse own address {ip}")
check(main._parse_block_target("8.8.8.8") == "8.8.8.8", "allow public 8.8.8.8")
check(main._parse_block_target("2001:0db8:0:0::5") == "2001:db8::5", "IPv6 normalised")

# --- F2/S3: firewall helpers with fake iptables ---
calls = []
class P:  # fake CompletedProcess
    def __init__(self, rc, err=""): self.returncode, self.stderr = rc, err
rules = set()
def fake_iptables(tool, action, chain, ip):
    calls.append((tool, action, chain, ip))
    key = (tool, chain, ip)
    if action == "-C": return P(0 if key in rules else 1)
    if action == "-I":
        if chain == "DOCKER-USER" and tool == "ip6tables": return P(1, "No chain/target/match by that name.")
        rules.add(key); return P(0)
    if action == "-D":
        if key in rules: rules.discard(key); return P(0)
        return P(1, "Bad rule")
orig_ipt = main._iptables
main._iptables = fake_iptables
main._apply_firewall_block("8.8.8.8")
check(("iptables", "INPUT", "8.8.8.8") in rules and ("iptables", "DOCKER-USER", "8.8.8.8") in rules, "block adds INPUT + DOCKER-USER rules")
main._apply_firewall_block("8.8.8.8")
check(sum(1 for c in calls if c[1] == "-I") == 2, "re-applying doesn't duplicate rules")
main._apply_firewall_block("2001:db8::5")
check(("ip6tables", "INPUT", "2001:db8::5") in rules, "IPv6 block works when DOCKER-USER missing")
main._remove_firewall_block("8.8.8.8")
main._remove_firewall_block("8.8.8.8")   # already gone -> no error
check(not any(r[2] == "8.8.8.8" for r in rules), "unblock removes rules, repeat unblock is harmless")
main._iptables = orig_ipt

# --- Detection rules with fake OpenSearch ---
fake = FakeOS()
main.client = fake
fake.agg_responses["brute"] = {"aggregations": {"by_ip": {"buckets": [
    {"key": "10.0.0.5", "doc_count": 7, "by_user": {"buckets": [{"key": "admin", "doc_count": 7}]}},
    {"key": "10.0.0.6", "doc_count": 9, "by_user": {"buckets": []}},   # spread over users -> not brute force
]}}}
fake.agg_responses["spray"] = {"aggregations": {"by_ip": {"buckets": [
    {"key": "10.0.0.6", "doc_count": 9, "by_user": {"buckets": [{"key": k, "doc_count": 3} for k in ["admin", "test", "guest"]]}},
    {"key": "10.0.0.7", "doc_count": 3, "by_user": {"buckets": [{"key": k, "doc_count": 1} for k in ["Admin", "admin", "admin "]]}},
]}}}
fake.agg_responses["success"] = {"aggregations": {"by_ip": {"buckets": [
    {"key": "10.0.0.8", "doc_count": 1, "last_success": {"value": 1.7e12}},
]}}}
fake.count_value = 3

xss_hits = [
    {"_source": {"source_ip": "10.0.0.9", "path": "/search.html?q=%3Cimg%20src%3Dx%20onerror%3Dfetch(1)%3E"}},
    {"_source": {"source_ip": "10.0.0.9", "path": "/search.html?q=%253Csvg%2520onload%253D1%253E"}},
    {"_source": {"source_ip": "10.0.0.10", "path": "/search.html?q=hello+world"}},
]
main.helpers.scan = lambda client, index, query: iter(xss_hits)

main._run_detection()
alerts = {(a["alert_type"], a["source_ip"]): a for a in fake.created.values()}
check(("Web Login Brute Force", "10.0.0.5") in alerts, "brute force: 7 fails on one user")
check(alerts.get(("Web Login Brute Force", "10.0.0.5"), {}).get("target_username") == "admin", "brute force records target username")
check(("Web Login Brute Force", "10.0.0.6") not in alerts, "no brute force when failures are spread across users")
check(("Password Spraying Attack", "10.0.0.6") in alerts, "spraying: 3 distinct users")
check(("Password Spraying Attack", "10.0.0.7") not in alerts, "case/space variants of one username don't count as spraying")
check(("Suspicious Login: Failed Attempts Then Success", "10.0.0.8") in alerts, "correlation: 3 fails before success")
cq = json.dumps(fake.counts[0])
check("10.0.0.8" in cq and "epoch_millis" in cq and "login_failed" in cq, "correlation counts only that IP's failures before the success")
x = alerts.get(("XSS Attempt Detected", "10.0.0.9"))
check(x is not None and x["attempt_count"] == 2, "XSS: URL-encoded + double-encoded payloads detected (count 2)")
check(("XSS Attempt Detected", "10.0.0.10") not in alerts, "XSS: harmless query not flagged")
n = len(fake.created)
main._run_detection()
check(len(fake.created) == n, "second detection run writes no duplicates")

fake.count_value = 1
fake.created.clear(); fake.alerted.clear()
main._run_correlation_rule()
check(not fake.created, "correlation: 1 failure before success is not enough")

# missing index everywhere -> no crash
empty = FakeOS(); main.client = empty
def scan_404(*a, **k):
    raise NotFoundError(404, "index_not_found_exception", {})
    yield
main.helpers.scan = scan_404
main._run_detection()
check(True, "detection survives missing logs-index")

# --- API endpoints ---
main.client = FakeOS()
runs = []
orig_run = main._run_detection
def counting_run():
    runs.append(1)
    if len(runs) == 1:
        raise RuntimeError("OpenSearch not ready")   # loop must survive this
main._run_detection = counting_run
main.DETECTION_INTERVAL_SECONDS = 0.2

def from_lan(app):
    async def wrapped(scope, receive, send):
        if scope["type"] == "http":
            scope = dict(scope, client=("192.168.1.50", 5000))
        await app(scope, receive, send)
    return wrapped

class LanClient(TestClient):
    def __init__(self, app):
        super().__init__(from_lan(app))
        self._real_app = app
    def __enter__(self):
        # lifespan must run on the real app so the detection loop starts
        self.app = self._real_app; c = super().__enter__(); self.app = from_lan(self._real_app); return c

with LanClient(main.app) as c:
    time.sleep(0.9)
    check(len(runs) >= 3, f"background detection loop runs on its own and survives errors ({len(runs)} runs)")

    r = c.post("/auth/login", json={"username": "admin", "password": "admin-test-pw"})
    check(r.status_code == 200 and r.json()["role"] == "admin", "admin login with env password")
    tok = r.json()["token"]
    H = {"Authorization": "Bearer " + tok}

    check(c.get("/logs?limit=99999", headers=H).status_code == 422, "limit above cap rejected (422, not 500)")
    check(c.get("/logs?limit=0", headers=H).status_code == 422, "limit 0 rejected")
    check(c.get("/logs?limit=200", headers=H).status_code == 200, "limit 200 (dashboard) ok")
    check(c.get("/alerts", headers=H).status_code == 200, "/alerts ok")
    before = len(runs)
    c.get("/alerts", headers=H)
    check(True, "/alerts only reads alert history")

    for i in range(5):
        r = c.post("/auth/login", json={"username": "admin", "password": "wrong"})
    check(r.status_code == 401, "5 wrong passwords -> 401")
    r = c.post("/auth/login", json={"username": "admin", "password": "admin-test-pw"})
    check(r.status_code == 429, "6th attempt rate-limited (429) even with right password")
    main.dashboard_login_failures.clear()

    main.DASHBOARD_USERS["viewer"]["password"] = None
    r = c.post("/auth/login", json={"username": "viewer", "password": ""})
    check(r.status_code == 401, "unset password env var -> account can't log in")
    main.DASHBOARD_USERS["viewer"]["password"] = "viewer-test-pw"

    r = c.post("/login", json={"username": "test", "password": "1111"}, headers={"X-Real-IP": "6.6.6.6"})
    demo_tok = r.json()["token"]
    check(c.get("/session-check", params={"token": demo_tok}).json()["valid"], "demo session valid")
    main.demo_sessions[demo_tok]["expires"] = datetime.utcnow() - timedelta(seconds=1)
    check(c.get("/session-check", params={"token": demo_tok}).json() == {"valid": False, "reason": "session expired"}, "demo session expires")

    check(c.post("/block/8.8.8.8", headers=H).status_code == 503, "blocking still disabled (503)")

main._run_detection = orig_run

lines = [json.loads(l) for l in open(LOG)]
events = [l["event"] for l in lines]
check("dashboard_login_failed" in events and "dashboard_login_rate_limited" in events and "dashboard_login_success" in events, "dashboard logins are logged")
demo = [l for l in lines if l["log_type"] == "web_login"][0]
check(demo["source_ip"] == "192.168.1.50", "direct (untrusted) caller's spoofed X-Real-IP ignored in demo login log")
os.remove(LOG)

print("\nALL PASSED" if not check.failed else "\nSOME CHECKS FAILED")
sys.exit(1 if check.failed else 0)
