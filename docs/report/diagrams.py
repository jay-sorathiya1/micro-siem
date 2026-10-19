"""Generate all report diagrams (PNG, 200 dpi) for the Micro-SIEM project report."""
import os, subprocess, sys
from PIL import Image, ImageDraw

OUT = sys.argv[1]  # e.g. docs/report/diagrams
os.makedirs(OUT, exist_ok=True)

BLUE, BLUE_DARK, GREEN, GREEN_DARK = "#5b9bd5", "#2e75b6", "#70ad47", "#548235"
FONT = "Liberation Serif"


def dot(name, src):
    path = f"{OUT}/{name}.dot"
    open(path, "w").write(src)
    subprocess.run(["dot", "-Tpng", "-Gdpi=200", path, "-o", f"{OUT}/{name}.png"], check=True)
    print("ok", name, Image.open(f"{OUT}/{name}.png").size)


# --- stick-figure actor image for the use case diagram ---
actor = Image.new("RGBA", (120, 200), (255, 255, 255, 0))
d = ImageDraw.Draw(actor)
c = (84, 130, 53, 255)
d.ellipse((38, 6, 82, 50), fill=c)
d.rectangle((52, 50, 68, 130), fill=c)
d.line((20, 75, 100, 75), fill=c, width=14)
d.line((60, 125, 28, 192), fill=c, width=14)
d.line((60, 125, 92, 192), fill=c, width=14)
actor.save(f"{OUT}/actor.png")

# ---------------------------------------------------------------- 5.1 USE CASE
uc = lambda n, t: f'{n} [label="{t}", shape=ellipse, style=filled, fillcolor="{BLUE}", fontcolor=white, color="{BLUE_DARK}", width=2.6, height=0.55];'
act = lambda n, t: (f'{n} [shape=plain, label=<<table border="0" cellspacing="2"><tr><td fixedsize="true" width="46" height="76">'
                    f'<img src="{OUT}/actor.png" scale="true"/></td></tr><tr><td><font point-size="13"><b>{t}</b></font></td></tr></table>>];')
dot("usecase", f"""
digraph G {{
  rankdir=LR; graph [fontname="{FONT}", nodesep=0.18, ranksep=1.3, pad=0.3];
  node [fontname="{FONT}", fontsize=12]; edge [color="#7f9fbf", arrowsize=0.6];
  {act("admin", "Admin (Security Analyst)")}
  {act("viewer", "Viewer")}
  subgraph cluster_sys {{
    label="Micro-SIEM System"; fontsize=15; fontname="{FONT} Bold"; style=rounded; color="#555555"; margin=18;
    {uc("u1", "Login to Dashboard")}
    {uc("u2", "View Dashboard Statistics")}
    {uc("u3", "View All Logs")}
    {uc("u4", "View Threats / Alerts")}
    {uc("u5", "Analyze / Mitigate Alert")}
    {uc("u6", "Block / Unblock IP (future)")}
    {uc("u7", "Block / Unblock Account (future)")}
    {uc("u8", "View Blocked List")}
    {uc("u9", "Logout")}
    {uc("d1", "Login to Demo Portal")}
    {uc("d2", "Search Records")}
    {uc("s1", "Collect & Store Logs")}
    {uc("s2", "Run Detection Rules")}
    {uc("s3", "Raise MITRE-Mapped Alert")}
  }}
  {act("user", "Demo User / Attacker")}
  {act("engine", "Detection Engine (timer)")}
  admin -> {{u1 u2 u3 u4 u5 u6 u7 u8 u9}} [arrowhead=none];
  viewer -> {{u1 u2 u9}} [arrowhead=none, color="#a0b8a0"];
  {{d1 d2}} -> user [arrowhead=none, dir=back];
  {{s1 s2 s3}} -> engine [arrowhead=none];
  u5 -> u6 [style=dashed, label="<<extend>>", fontsize=9, constraint=false, color="#999999"];
  s2 -> s3 [style=dashed, label="<<include>>", fontsize=9, constraint=false, color="#999999"];
}}""")

# ---------------------------------------------------------------- 5.2 CLASS
def cls(n, title, attrs, ops):
    a = "".join(f'<tr><td align="left">{x}</td></tr>' for x in attrs) or '<tr><td> </td></tr>'
    o = "".join(f'<tr><td align="left">{x}</td></tr>' for x in ops) or '<tr><td> </td></tr>'
    return (f'{n} [shape=plain, label=<<table border="0" cellborder="1" cellspacing="0" cellpadding="4" color="#7f7f7f">'
            f'<tr><td bgcolor="{BLUE}"><font color="white"><b>{title}</b></font></td></tr>'
            f'<tr><td bgcolor="#f2f2f2"><table border="0" cellspacing="0" cellpadding="1">{a}</table></td></tr>'
            f'<tr><td bgcolor="#f2f2f2"><table border="0" cellspacing="0" cellpadding="1">{o}</table></td></tr></table>>];')

dot("class", f"""
digraph G {{
  graph [fontname="{FONT}", nodesep=0.5, ranksep=0.8, pad=0.3]; node [fontname="{FONT}", fontsize=11];
  edge [fontname="{FONT}", fontsize=10, color="#5a6f8a"];
  {cls("api", "MicroSIEM_API (FastAPI app)", ["- client : OpenSearch", "- sessions : dict", "- demo_sessions : dict", "- BLOCKING_ENABLED : bool"],
       ["+ web_login(LoginRequest)", "+ dashboard_login(DashboardLoginRequest)", "+ get_logs(limit)", "+ get_alerts(limit)", "+ get_blocked()", "+ block_ip(ip) / unblock_ip(ip)", "+ block_account(u) / unblock_account(u)"])}
  {cls("auth", "SessionManager", ["- sessions : token → role, expires", "- SESSION_TTL_HOURS = 8", "- login_failures : ip → [time]"],
       ["+ require_session(header)", "+ require_admin(session)", "+ get_client_ip(request)", "- _prune_sessions()"])}
  {cls("engine", "DetectionEngine", ["- DETECTION_INTERVAL = 5 s", "- ALERT_DEDUPE = 5 min", "- GUESS_EVENTS"],
       ["+ _detection_loop()", "+ _run_detection()", "- _already_alerted_recently()", "- _write_alert(alert)"])}
  {cls("rule", "«rule» DetectionRule", ["- window_minutes : int", "- threshold : int", "- mitre_id : str"], ["+ run() : alerts"])}
  {cls("bf", "BruteForceRule", ["threshold = 5 / same user", "window = 2 min", "T1110"], ["+ _run_brute_force_rule()"])}
  {cls("sp", "PasswordSprayingRule", ["threshold = 3 users", "window = 5 min", "T1110.003"], ["+ _run_password_spraying_rule()"])}
  {cls("co", "CorrelationRule", ["fails ≥ 2 then success", "window = 2 min", "T1078"], ["+ _run_correlation_rule()"])}
  {cls("xs", "XSSRule", ["XSS_SIGNATURES[10]", "window = 2 min", "CWE-79"], ["+ _run_xss_detection()", "- _decoded_path(path)"])}
  {cls("alert", "Alert", ["timestamp : datetime", "alert_type : str", "source_ip : str", "attempt_count : int", "severity : str", "matched_rule : str", "mitre_id / technique / tactic"], [])}
  {cls("log", "LogEvent", ["timestamp : datetime", "log_type : str", "event : str", "username : str", "source_ip : str", "method / path / status"], [])}
  {cls("blk", "BlockRecord", ["type : ip | account", "ip / username : str", "blocked_at : datetime", "blocked_by : str"], [])}
  {cls("fw", "FirewallManager", ["FIREWALL_CHAINS = INPUT, DOCKER-USER"], ["+ _apply_firewall_block(ip)", "+ _remove_firewall_block(ip)", "+ _restore_firewall_rules()", "+ _parse_block_target(ip)"])}
  {cls("req", "LoginRequest / DashboardLoginRequest", ["username : str", "password : str"], ["(Pydantic validation)"])}
  api -> auth [label="uses", arrowhead=vee];
  api -> engine [label="starts (lifespan)", arrowhead=vee];
  api -> fw [label="uses", arrowhead=vee];
  api -> req [label="validates", arrowhead=vee, style=dashed];
  engine -> rule [label="runs 1..4", arrowhead=odiamond, dir=back, arrowtail=diamond];
  bf -> rule [arrowhead=empty]; sp -> rule [arrowhead=empty]; co -> rule [arrowhead=empty]; xs -> rule [arrowhead=empty];
  rule -> log [label="reads *", arrowhead=vee, style=dashed];
  engine -> alert [label="writes 0..*", arrowhead=vee];
  fw -> blk [label="1 → 1", arrowhead=vee, style=dashed];
  {{rank=same; bf; sp; co; xs}}
}}""")

# ---------------------------------------------------------------- 5.3 ACTIVITY diagrams
def activity(name, body):
    dot(name, f"""
digraph G {{
  graph [fontname="{FONT}", nodesep=0.45, ranksep=0.42, pad=0.3]; edge [fontname="{FONT}", fontsize=11, color="{BLUE_DARK}", arrowsize=0.7];
  node [fontname="{FONT}", fontsize=13, shape=box, style="rounded,filled", fillcolor="{GREEN}", fontcolor=white, color="{GREEN_DARK}", width=2.2, height=0.5];
  start [shape=circle, label="", width=0.38, fillcolor="{BLUE}", color="{BLUE_DARK}"];
  end [shape=doublecircle, label="", width=0.3, fillcolor="#595959", color="#595959"];
  {body}
}}""")

dia = lambda n, t="": f'{n} [shape=diamond, label="{t}", fillcolor="{BLUE}", color="{BLUE_DARK}", width=0.6, height=0.6, fontsize=10];'

activity("activity_admin", f"""
  a1 [label="Open Dashboard (port 8090)"]; a2 [label="Enter Username & Password"];
  {dia("c1", "Rate\\nlimit?")} {dia("c2", "Valid?")}
  r1 [label="HTTP 429 – Try Later", fillcolor="#c00000", color="#c00000"];
  a3 [label="Session Token + Role Issued"]; {dia("c3", "Role")}
  ad [label="Admin Console"]; vw [label="Viewer Dashboard (read-only)"];
  {dia("c4", "Choose")}
  m1 [label="Dashboard Stats & Charts"]; m2 [label="All Logs"]; m3 [label="Threats & Action"];
  m4 [label="Analyze / Mitigate Alert"]; lo [label="Logout"];
  start -> a1 -> a2 -> c1;
  c1 -> r1 [label="≥5 failures"]; r1 -> a2 [style=dashed];
  c1 -> c2 [label="ok"]; c2 -> a2 [label="No (401, logged)"]; c2 -> a3 [label="Yes"];
  a3 -> c3; c3 -> ad [label="admin"]; c3 -> vw [label="viewer"];
  ad -> c4; c4 -> m1; c4 -> m2; c4 -> m3; m3 -> m4;
  {{m1 m2 m4 vw}} -> lo; lo -> end;
""")

activity("activity_detection", f"""
  a1 [label="Timer fires (every 5 s)"]; a2 [label="Query logs-index (time window)"];
  a3 [label="Brute Force\\nfails per IP + user"]; a4 [label="Password Spraying\\ndistinct users per IP"];
  a5 [label="Correlation\\nfails before success"]; a6 [label="XSS\\ndecode path, match signatures"];
  {dia("c1", "Rule\\nmatched?")} {dia("c2", "Alerted in\\nlast 5 min?")}
  a7 [label="Build alert (severity, MITRE ID)"]; a8 [label="create() in alerts-index"];
  a9 [label="Dashboards show alert"]; sk [label="Skip (de-duplicated)", fillcolor="#7f7f7f", color="#7f7f7f"];
  start -> a1 -> a2; a2 -> a3; a2 -> a4; a2 -> a5; a2 -> a6;
  {{a3 a4 a5 a6}} -> c1; c1 -> a1 [label="No", style=dashed]; c1 -> c2 [label="Yes"];
  c2 -> sk [label="Yes"]; c2 -> a7 [label="No"]; a7 -> a8 -> a9 -> end; sk -> a1 [style=dashed];
  {{rank=same; a3; a4; a5; a6}}
""")

activity("activity_attacker", f"""
  a1 [label="Open Demo Portal (port 8080)"]; a2 [label="Submit Username & Password"];
  {dia("c0", "Account\\nblocked?")} {dia("c1", "Credentials\\nvalid?")}
  b1 [label="Refused – login_blocked logged", fillcolor="#c00000", color="#c00000"];
  f1 [label="login_failed logged"]; s1 [label="login_success + token"];
  s2 [label="Search Page (reflects query)"]; x1 [label="Payload in URL → Nginx access log"];
  v1 [label="Vector ships events to OpenSearch"]; d1 [label="Detection Engine raises alert"];
  start -> a1 -> a2 -> c0; c0 -> b1 [label="Yes"]; c0 -> c1 [label="No"];
  c1 -> f1 [label="No"]; c1 -> s1 [label="Yes"]; f1 -> a2 [label="retry", style=dashed];
  s1 -> s2 -> x1; {{b1 f1 x1}} -> v1 -> d1 -> end;
""")

# ---------------------------------------------------------------- 5.4 DEPLOYMENT
dot("deployment", f"""
digraph G {{
  rankdir=LR; newrank=true; graph [fontname="{FONT}", nodesep=0.45, ranksep=0.75, pad=0.3];
  node [fontname="{FONT}", fontsize=12, shape=box3d, style=filled, fillcolor="#fff2cc", color="#bf9000"];
  edge [fontname="{FONT}", fontsize=10, color="#404040", arrowsize=0.7];
  subgraph cluster_clients {{ label="Client Devices (LAN / ngrok)"; style="rounded,dashed"; color="#7f7f7f"; fontname="{FONT} Bold";
    br1 [label="Attacker / Demo User\\nBrowser", shape=box, fillcolor="#deebf7", color="{BLUE_DARK}"];
    br2 [label="Admin / Viewer\\nBrowser", shape=box, fillcolor="#deebf7", color="{BLUE_DARK}"]; }}
  subgraph cluster_host {{ label="Host Machine: Kali Linux + Docker Engine"; style=rounded; color="#2e75b6"; fontname="{FONT} Bold"; fontsize=14;
    subgraph cluster_net {{ label="Docker bridge network: siem-net"; labelloc=t; labeljust=r; style="rounded,filled"; fillcolor="#f7f9fc"; color="#9dc3e6"; fontname="{FONT} Bold";
      ng1 [label="nginx-loginpage\\nNginx 1.30.6  :8080\\nDemo site + /api proxy"];
      ng2 [label="react-console\\nNginx 1.30.6  :8090\\nDashboards + /api proxy"];
      vec [label="vector\\nVector 0.59.0\\nlog shipper"];
      os [label="opensearch\\nOpenSearch 3.8.0\\n127.0.0.1:9200"];
      osd [label="opensearch-dashboards\\n127.0.0.1:5601"];
    }}
    api [label="fastapi-app\\nFastAPI + Uvicorn  :8000\\n(network_mode: host)", fillcolor="#e2f0d9", color="{GREEN_DARK}"];
    v1 [label="Volume: webapp-logs\\n(login.log)", shape=cylinder, fillcolor="#ededed", color="#7f7f7f"];
    v2 [label="Volume: nginx-logs\\n(access_json.log)", shape=cylinder, fillcolor="#ededed", color="#7f7f7f"];
  }}
  {{rank=same; br1; br2}} {{rank=same; ng1; ng2}} {{rank=same; api; v2}} {{rank=same; v1; vec}} {{rank=same; os; osd}}
  br1 -> ng1 [xlabel="HTTP :8080"]; br2 -> ng2 [xlabel="HTTP :8090"];
  ng1 -> api [xlabel="/api/"]; ng2 -> api [xlabel="/api/"];
  ng1 -> v2 [xlabel="writes"]; api -> v1 [xlabel="writes"];
  v1 -> vec [xlabel="tails"]; v2 -> vec [xlabel="tails"];
  vec -> os [xlabel="bulk index"]; api -> os [xlabel="query / alerts", constraint=false]; osd -> os [xlabel="explore", constraint=false];
}}""")

# ---------------------------------------------------------------- Architecture / data flow (chapter 3)
dot("architecture", f"""
digraph G {{
  rankdir=TB; graph [fontname="{FONT}", nodesep=0.5, ranksep=0.45, pad=0.3];
  node [fontname="{FONT}", fontsize=13, shape=box, style="rounded,filled", color="{BLUE_DARK}", fillcolor="#deebf7", width=2.4];
  edge [fontname="{FONT}", fontsize=10, color="#404040", arrowsize=0.7];
  s1 [label="Demo Web Login\\n(FastAPI /login)"]; s2 [label="Nginx Access\\nLog (8080)"];
  f1 [label="login.log\\n(JSON lines)", shape=note, fillcolor="#ededed", color="#7f7f7f"];
  f2 [label="access_json.log\\n(JSON lines)", shape=note, fillcolor="#ededed", color="#7f7f7f"];
  vec [label="Vector\\nsource → parse → sink", fillcolor="#fff2cc", color="#bf9000"];
  os [label="OpenSearch\\nlogs-index", shape=cylinder, fillcolor="#fff2cc", color="#bf9000"];
  de [label="Detection Engine\\n4 rules, every 5 s", fillcolor="#e2f0d9", color="{GREEN_DARK}"];
  al [label="OpenSearch\\nalerts-index", shape=cylinder, fillcolor="#fff2cc", color="#bf9000"];
  ui [label="Admin / Viewer\\nDashboards (8090)", fillcolor="#fbe5d6", color="#c55a11"];
  s1 -> f1 -> vec; s2 -> f2 -> vec; vec -> os -> de -> al -> ui [label=" "];
  os -> ui [label="raw logs", style=dashed];
}}""")

# ---------------------------------------------------------------- 4.4 GANTT (matplotlib)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams["font.family"] = "serif"; plt.rcParams["font.serif"] = ["Liberation Serif"]
import matplotlib.dates as mdates
from datetime import date, timedelta

tasks = [
    ("Requirement Analysis", None, None, None),
    ("Study of SIEM concepts & tools", date(2026, 7, 1), date(2026, 7, 10), "#f4b183"),
    ("Requirement gathering", date(2026, 7, 8), date(2026, 7, 16), "#f4b183"),
    ("Define scope & detection rules", date(2026, 7, 14), date(2026, 7, 22), "#f4b183"),
    ("Planning & Design", None, None, None),
    ("Architecture & tool selection", date(2026, 7, 20), date(2026, 7, 31), "#70ad47"),
    ("UML diagrams & index design", date(2026, 7, 28), date(2026, 8, 8), "#70ad47"),
    ("Implementation", None, None, None),
    ("Sprint 1: Docker, OpenSearch, Vector", date(2026, 8, 6), date(2026, 8, 20), "#9b72cf"),
    ("Sprint 2: FastAPI + demo portal", date(2026, 8, 18), date(2026, 9, 3), "#9b72cf"),
    ("Sprint 3: Detection rules + alerts", date(2026, 9, 1), date(2026, 9, 17), "#9b72cf"),
    ("Sprint 4: Dashboards + auth (RBAC)", date(2026, 9, 10), date(2026, 9, 26), "#9b72cf"),
    ("Sprint 5: Blocking module", date(2026, 9, 6), date(2026, 9, 14), "#9b72cf"),
    ("Sprint 6: Security hardening", date(2026, 10, 5), date(2026, 10, 16), "#9b72cf"),
    ("Testing", None, None, None),
    ("Unit & integration testing", date(2026, 9, 20), date(2026, 10, 10), "#ffd966"),
    ("Live end-to-end & UI testing", date(2026, 10, 12), date(2026, 10, 19), "#ffd966"),
    ("Documentation", None, None, None),
    ("Report, presentation & viva prep", date(2026, 10, 10), date(2026, 10, 31), "#5b9bd5"),
]
fig, ax = plt.subplots(figsize=(10, 7.2), dpi=200)
plt.rcParams["font.family"] = "serif"; plt.rcParams["font.serif"] = ["Liberation Serif"]
ys = list(range(len(tasks)))[::-1]
for y, (name, s, e, col) in zip(ys, tasks):
    if s is None:
        ax.text(date(2026, 6, 30), y, name, va="center", ha="right", fontsize=10, fontweight="bold", family="Liberation Serif")
        ax.axhspan(y - 0.5, y + 0.5, color="#dbe5f1", zorder=0)
    else:
        ax.barh(y, (e - s).days, left=s, color=col, edgecolor="#404040", height=0.6, zorder=2)
        ax.text(date(2026, 6, 30), y, name + "   ", va="center", ha="right", fontsize=9, family="Liberation Serif")
ax.set_yticks([]); ax.set_ylim(-0.7, len(tasks) - 0.3)
ax.set_xlim(date(2026, 7, 1), date(2026, 11, 1))
ax.xaxis.set_major_locator(mdates.MonthLocator()); ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
ax.xaxis.set_minor_locator(mdates.WeekdayLocator(byweekday=0))
ax.grid(axis="x", which="minor", color="#d9d9d9", lw=0.6); ax.grid(axis="x", which="major", color="#7f7f7f", lw=1)
ax.xaxis.tick_top(); ax.tick_params(axis="x", labelsize=10)
for sp in ["right", "bottom", "left"]: ax.spines[sp].set_visible(False)
plt.tight_layout(); plt.savefig(f"{OUT}/gantt.png", bbox_inches="tight"); print("ok gantt")

# class diagram rotated 90 degrees so it can use the full page height in the report
Image.open(f"{OUT}/class.png").rotate(90, expand=True, fillcolor="white").save(f"{OUT}/class_rot.png")
print("ok class_rot")
