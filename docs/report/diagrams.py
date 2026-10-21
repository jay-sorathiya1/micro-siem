"""Generate all report diagrams (PNG, 200 dpi) for the Micro-SIEM project report.

Layouts are kept portrait-friendly and fonts large so the text stays readable
after the figure is scaled to the page (the script prints the effective
printed font size of each diagram; aim for >= 8 pt).

Usage: python3 docs/report/diagrams.py docs/report/diagrams
"""
import os, subprocess, sys
from PIL import Image, ImageDraw

OUT = sys.argv[1]  # e.g. docs/report/diagrams
os.makedirs(OUT, exist_ok=True)

BLUE, BLUE_DARK, GREEN, GREEN_DARK = "#5b9bd5", "#2e75b6", "#70ad47", "#548235"
FONT = "Liberation Serif"
DPI = 200
TEXT_W, MAX_H = 6.27, 8.0      # usable page area in the report (inches)

# name -> (smallest font size used in the diagram, max height allowed in the report)
SIZES = {}


def dot(name, src, min_font, max_h=MAX_H):
    path = f"{OUT}/{name}.dot"
    open(path, "w").write(src)
    subprocess.run(["dot", "-Tpng", f"-Gdpi={DPI}", path, "-o", f"{OUT}/{name}.png"], check=True)
    os.remove(path)
    SIZES[name] = (min_font, max_h)


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
uc = lambda n, t: f'{n} [label="{t}", shape=ellipse, style=filled, fillcolor="{BLUE}", fontcolor=white, color="{BLUE_DARK}", width=3.3, height=0.62];'
act = lambda n, t: (f'{n} [shape=plain, label=<<table border="0" cellspacing="2"><tr><td fixedsize="true" width="50" height="84">'
                    f'<img src="{OUT}/actor.png" scale="true"/></td></tr><tr><td><font point-size="17"><b>{t}</b></font></td></tr></table>>];')
dot("usecase", f"""
digraph G {{
  rankdir=LR; graph [fontname="{FONT}", nodesep=0.14, ranksep=0.9, pad=0.2];
  node [fontname="{FONT}", fontsize=17]; edge [color="#7f9fbf", arrowsize=0.7, penwidth=1.3];
  {act("admin", "Admin<br/>(Security Analyst)")}
  {act("viewer", "Viewer")}
  subgraph cluster_sys {{
    label="Micro-SIEM System"; fontsize=19; fontname="{FONT} Bold"; style=rounded; color="#555555"; margin=14;
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
  {act("user", "Demo User /<br/>Attacker")}
  {act("engine", "Detection Engine<br/>(timer)")}
  admin -> {{u1 u2 u3 u4 u5 u6 u7 u8 u9}} [arrowhead=none];
  viewer -> {{u1 u2 u9}} [arrowhead=none, color="#a0b8a0"];
  {{d1 d2}} -> user [arrowhead=none, dir=back];
  {{s1 s2 s3}} -> engine [arrowhead=none];
  u5 -> u6 [style=dashed, label="«extend»", fontsize=14, constraint=false, color="#999999"];
  s2 -> s3 [style=dashed, label="«include»", fontsize=14, constraint=false, color="#999999"];
}}""", 17, max_h=8.0)

# ---------------------------------------------------------------- 5.2 CLASS (two figures)
def cls(n, title, attrs, ops):
    a = "".join(f'<tr><td align="left">{x}</td></tr>' for x in attrs) or '<tr><td> </td></tr>'
    o = "".join(f'<tr><td align="left">{x}</td></tr>' for x in ops) or '<tr><td> </td></tr>'
    return (f'{n} [shape=plain, label=<<table border="0" cellborder="1" cellspacing="0" cellpadding="5" color="#7f7f7f">'
            f'<tr><td bgcolor="{BLUE}"><font color="white"><b>{title}</b></font></td></tr>'
            f'<tr><td bgcolor="#f2f2f2"><table border="0" cellspacing="0" cellpadding="1">{a}</table></td></tr>'
            f'<tr><td bgcolor="#f2f2f2"><table border="0" cellspacing="0" cellpadding="1">{o}</table></td></tr></table>>];')

CLASS_HEAD = f"""  graph [fontname="{FONT}", nodesep=0.35, ranksep=0.7, pad=0.2]; node [fontname="{FONT}", fontsize=16];
  edge [fontname="{FONT}", fontsize=15, color="#5a6f8a", penwidth=1.3];"""

dot("class_core", f"""
digraph G {{
  rankdir=LR;
{CLASS_HEAD}
  {cls("api", "MicroSIEM_API (FastAPI app)", ["- client : OpenSearch", "- sessions : dict", "- demo_sessions : dict", "- BLOCKING_ENABLED : bool"],
       ["+ web_login(LoginRequest)", "+ dashboard_login(...)", "+ get_logs(limit)", "+ get_alerts(limit)", "+ get_blocked()", "+ block_ip / unblock_ip(ip)", "+ block_account / unblock_account(u)"])}
  {cls("auth", "SessionManager", ["- sessions : token → role, expires", "- SESSION_TTL_HOURS = 8", "- login_failures : ip → [time]"],
       ["+ require_session(header)", "+ require_admin(session)", "+ get_client_ip(request)", "- _prune_sessions()"])}
  {cls("engine", "DetectionEngine", ["- DETECTION_INTERVAL = 5 s", "- ALERT_DEDUPE = 5 min"],
       ["+ _detection_loop()", "+ _run_detection()"])}
  {cls("fw", "FirewallManager", ["- FIREWALL_CHAINS = INPUT, DOCKER-USER"],
       ["+ _apply_firewall_block(ip)", "+ _remove_firewall_block(ip)", "+ _restore_firewall_rules()", "+ _parse_block_target(ip)"])}
  {cls("req", "LoginRequest / DashboardLoginRequest", ["username : str", "password : str"], ["(Pydantic validation)"])}
  {cls("blk", "BlockRecord", ["type : ip | account", "ip / username : str", "blocked_at : datetime", "blocked_by : str"], [])}
  api -> auth [label="uses", arrowhead=vee];
  api -> engine [label="starts", arrowhead=vee];
  api -> fw [label="uses", arrowhead=vee];
  api -> req [label="validates", arrowhead=vee, style=dashed];
  fw -> blk [label=" stores", arrowhead=vee, style=dashed];
  {{rank=same; auth; engine; fw; blk; req}}
}}""", 15)

dot("class_rules", f"""
digraph G {{
  rankdir=LR;
{CLASS_HEAD}
  {cls("engine", "DetectionEngine", ["- DETECTION_INTERVAL = 5 s", "- ALERT_DEDUPE = 5 min", "- GUESS_EVENTS"],
       ["+ _run_detection()", "- _already_alerted_recently()", "- _write_alert(alert)"])}
  {cls("rule", "«rule» DetectionRule", ["- window_minutes : int", "- threshold : int", "- mitre_id : str"], ["+ run() : alerts"])}
  {cls("bf", "BruteForceRule", ["5 fails, same user, 2 min", "MITRE T1110"], ["+ _run_brute_force_rule()"])}
  {cls("sp", "PasswordSprayingRule", ["3+ usernames, 5 min", "MITRE T1110.003"], ["+ _run_password_spraying_rule()"])}
  {cls("co", "CorrelationRule", ["2+ fails then success, 2 min", "MITRE T1078"], ["+ _run_correlation_rule()"])}
  {cls("xs", "XSSRule", ["10 signatures, 2 min", "CWE-79"], ["+ _run_xss_detection()", "- _decoded_path(path)"])}
  {cls("alert", "Alert", ["timestamp : datetime", "alert_type : str", "source_ip : str", "attempt_count : int", "severity : str", "matched_rule : str", "mitre_id / technique / tactic"], [])}
  {cls("log", "LogEvent", ["timestamp : datetime", "log_type : str", "event : str", "username : str", "source_ip : str", "method / path / status"], [])}
  engine -> rule [label="runs 4", arrowtail=diamond, dir=back];
  bf -> rule [arrowhead=empty, dir=back, arrowtail=empty]; sp -> rule [dir=back, arrowtail=empty];
  co -> rule [dir=back, arrowtail=empty]; xs -> rule [dir=back, arrowtail=empty];
  engine -> alert [label="writes", arrowhead=vee];
  rule -> log [label="reads", arrowhead=vee, style=dashed];
  {{rank=same; bf; sp; co; xs}}
  {{rank=same; rule; alert}}
}}""", 15)

# ---------------------------------------------------------------- 5.3 ACTIVITY diagrams
def activity(name, body, max_h=MAX_H):
    dot(name, f"""
digraph G {{
  graph [fontname="{FONT}", nodesep=0.35, ranksep=0.32, pad=0.2]; edge [fontname="{FONT}", fontsize=15, color="{BLUE_DARK}", arrowsize=0.8, penwidth=1.3];
  node [fontname="{FONT}", fontsize=17, shape=box, style="rounded,filled", fillcolor="{GREEN}", fontcolor=white, color="{GREEN_DARK}", height=0.5, margin="0.15,0.06"];
  start [shape=circle, label="", width=0.4, fillcolor="{BLUE}", color="{BLUE_DARK}"];
  end [shape=doublecircle, label="", width=0.32, fillcolor="#595959", color="#595959"];
  {body}
}}""", 15, max_h=max_h)

dia = lambda n, t="": f'{n} [shape=diamond, label="{t}", fillcolor="{BLUE}", color="{BLUE_DARK}", fontsize=15, margin="0.02,0.02"];'

activity("activity_admin", f"""
  a1 [label="Open Dashboard (port 8090)"]; a2 [label="Enter Username & Password"];
  {dia("c1", "Rate\\nlimit?")} {dia("c2", "Valid?")}
  r1 [label="HTTP 429\\nTry Later", fillcolor="#c00000", color="#c00000"];
  a3 [label="Session Token + Role Issued"]; {dia("c3", "Role?")}
  ad [label="Admin Console"]; vw [label="Viewer Dashboard\\n(read-only)"];
  {dia("c4", "Choose")}
  m1 [label="Stats & Charts"]; m2 [label="All Logs"]; m3 [label="Threats & Action"];
  m4 [label="Analyze / Mitigate"]; lo [label="Logout"];
  start -> a1 -> a2 -> c1;
  c1 -> r1 [label=" 5 failures"]; r1 -> a2 [style=dashed];
  c1 -> c2 [label=" ok"]; c2 -> a2 [label=" No (401)"]; c2 -> a3 [label=" Yes"];
  a3 -> c3; c3 -> ad [label=" admin"]; c3 -> vw [label=" viewer"];
  ad -> c4; c4 -> m1; c4 -> m2; c4 -> m3; m3 -> m4;
  {{m1 m2 m4 vw}} -> lo; lo -> end;
""", max_h=7.9)

activity("activity_detection", f"""
  a1 [label="Timer fires (every 5 seconds)"];
  a2 [label="Query recent events in logs-index"];
  a3 [label="Run the rules in order:\\l1. Brute Force – failures per IP + username\\l2. Password Spraying – distinct usernames per IP\\l3. Correlation – failures before a success\\l4. XSS – URL-decoded path vs. signatures\\l", fillcolor="#e2f0d9", fontcolor="#1f3b12"];
  {dia("c1", "Rule\\nmatched?")} {dia("c2", "Alerted in\\nlast 5 min?")}
  a7 [label="Build alert (severity, MITRE ID)"]; a8 [label="create() in alerts-index"];
  a9 [label="Alert shown on dashboards"]; sk [label="Skip (de-duplicated)", fillcolor="#7f7f7f", color="#7f7f7f"];
  sl [label="Wait 5 seconds", fillcolor="#7f7f7f", color="#7f7f7f"];
  start -> a1 -> a2 -> a3 -> c1;
  c1 -> sl [label=" No"]; c1 -> c2 [label=" Yes"];
  c2 -> sk [label=" Yes"]; c2 -> a7 [label=" No"]; a7 -> a8 -> a9 -> sl; sk -> sl;
  sl -> a1 [style=dashed, constraint=false]; a9 -> end [style=dotted, label=" stop"];
""", max_h=7.6)

activity("activity_attacker", f"""
  a1 [label="Open Demo Portal (port 8080)"]; a2 [label="Submit Username & Password"];
  {dia("c0", "Account\\nblocked?")} {dia("c1", "Credentials\\nvalid?")}
  b1 [label="Refused\\nlogin_blocked logged", fillcolor="#c00000", color="#c00000"];
  f1 [label="login_failed\\nlogged"]; s1 [label="login_success\\n+ token"];
  s2 [label="Search Page\\n(reflects query)"]; x1 [label="Payload in URL\\n→ Nginx access log"];
  v1 [label="Vector ships events to OpenSearch"]; d1 [label="Detection Engine raises alert"];
  start -> a1 -> a2 -> c0; c0 -> b1 [label=" Yes"]; c0 -> c1 [label=" No"];
  c1 -> f1 [label=" No"]; c1 -> s1 [label=" Yes"]; f1 -> a2 [label=" retry", style=dashed];
  s1 -> s2 -> x1; {{b1 f1 x1}} -> v1 -> d1 -> end;
""", max_h=7.6)

# ---------------------------------------------------------------- 5.4 DEPLOYMENT (top to bottom)
dot("deployment", f"""
digraph G {{
  rankdir=TB; newrank=true; graph [fontname="{FONT}", nodesep=0.3, ranksep=0.42, pad=0.2];
  node [fontname="{FONT}", fontsize=16, shape=box3d, style=filled, fillcolor="#fff2cc", color="#bf9000"];
  edge [fontname="{FONT}", fontsize=14, color="#404040", arrowsize=0.8, penwidth=1.3];
  subgraph cluster_clients {{ label="Client Devices (LAN / ngrok)"; fontsize=17; style="rounded,dashed"; color="#7f7f7f"; fontname="{FONT} Bold";
    br1 [label="Attacker / Demo User\\nBrowser", shape=box, fillcolor="#deebf7", color="{BLUE_DARK}"];
    br2 [label="Admin / Viewer\\nBrowser", shape=box, fillcolor="#deebf7", color="{BLUE_DARK}"]; }}
  subgraph cluster_host {{ label="Host Machine: Kali Linux + Docker Engine"; labelloc=b; style=rounded; color="#2e75b6"; fontname="{FONT} Bold"; fontsize=18;
    subgraph cluster_net {{ label="Docker network: siem-net"; labeljust=l; style="rounded,filled"; fillcolor="#f7f9fc"; color="#9dc3e6"; fontname="{FONT} Bold"; fontsize=16;
      ng1 [label="nginx-loginpage\\nNginx 1.30.6 :8080\\nDemo site + /api proxy"];
      ng2 [label="react-console\\nNginx 1.30.6 :8090\\nDashboards + /api proxy"];
      vec [label="vector\\nVector 0.59.0\\nlog shipper"];
      os [label="opensearch\\nOpenSearch 3.8.0\\n127.0.0.1:9200"];
      osd [label="opensearch-dashboards\\n127.0.0.1:5601"];
    }}
    api [label="fastapi-app\\nFastAPI + Uvicorn :8000\\n(host network)", fillcolor="#e2f0d9", color="{GREEN_DARK}"];
    v1 [label="Volume: webapp-logs\\n(login.log)", shape=cylinder, fillcolor="#ededed", color="#7f7f7f"];
    v2 [label="Volume: nginx-logs\\n(access_json.log)", shape=cylinder, fillcolor="#ededed", color="#7f7f7f"];
  }}
  {{rank=same; br1; br2}} {{rank=same; ng1; ng2}} {{rank=same; api; v2}} {{rank=same; v1; vec}} {{rank=same; os; osd}}
  br1 -> ng1 [label=" HTTP :8080"]; br2 -> ng2 [label=" HTTP :8090"];
  ng1 -> api [taillabel="/api/", labeldistance=4.5, labelangle=-25]; ng2 -> api [taillabel="/api/", labeldistance=3.5, labelangle=25];
  ng1 -> v2 [label=" writes"]; api -> v1 [label=" writes"];
  v1 -> vec [taillabel="tails", labeldistance=3.5, labelangle=30]; v2 -> vec [taillabel="tails", labeldistance=3, labelangle=-35];
  vec -> os [label=" bulk index"]; api -> os [label=" query / alerts"]; osd -> os [label=" explore", constraint=false];
}}""", 14, max_h=7.2)

# ---------------------------------------------------------------- Architecture / data flow (chapter 3)
dot("architecture", f"""
digraph G {{
  rankdir=TB; graph [fontname="{FONT}", nodesep=0.5, ranksep=0.35, pad=0.2];
  node [fontname="{FONT}", fontsize=17, shape=box, style="rounded,filled", color="{BLUE_DARK}", fillcolor="#deebf7", width=2.6];
  edge [fontname="{FONT}", fontsize=15, color="#404040", arrowsize=0.8, penwidth=1.3];
  s1 [label="Demo Web Login\\n(FastAPI /login)"]; s2 [label="Nginx Access\\nLog (8080)"];
  f1 [label="login.log\\n(JSON lines)", shape=note, fillcolor="#ededed", color="#7f7f7f"];
  f2 [label="access_json.log\\n(JSON lines)", shape=note, fillcolor="#ededed", color="#7f7f7f"];
  vec [label="Vector\\nsource → parse → sink", fillcolor="#fff2cc", color="#bf9000"];
  os [label="OpenSearch\\nlogs-index", shape=cylinder, fillcolor="#fff2cc", color="#bf9000"];
  de [label="Detection Engine\\n4 rules, every 5 s", fillcolor="#e2f0d9", color="{GREEN_DARK}"];
  al [label="OpenSearch\\nalerts-index", shape=cylinder, fillcolor="#fff2cc", color="#bf9000"];
  ui [label="Admin / Viewer\\nDashboards (8090)", fillcolor="#fbe5d6", color="#c55a11"];
  s1 -> f1 -> vec; s2 -> f2 -> vec; vec -> os -> de -> al -> ui;
  os -> ui [label=" raw logs", style=dashed];
}}""", 15, max_h=5.2)

# ---------------------------------------------------------------- 4.4 GANTT (matplotlib)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
plt.rcParams["font.family"] = "serif"; plt.rcParams["font.serif"] = ["Liberation Serif"]
import matplotlib.dates as mdates
from datetime import date

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
GANTT_W = 7.0                       # figure width in inches (displayed at ~6.27")
fig, ax = plt.subplots(figsize=(GANTT_W, 7.4), dpi=DPI)
ys = list(range(len(tasks)))[::-1]
for y, (name, s, e, col) in zip(ys, tasks):
    if s is None:
        ax.text(date(2026, 6, 30), y, name, va="center", ha="right", fontsize=11.5, fontweight="bold")
        ax.axhspan(y - 0.5, y + 0.5, color="#dbe5f1", zorder=0)
    else:
        ax.barh(y, (e - s).days, left=s, color=col, edgecolor="#404040", height=0.62, zorder=2)
        ax.text(date(2026, 6, 30), y, name + "  ", va="center", ha="right", fontsize=11)
ax.set_yticks([]); ax.set_ylim(-0.7, len(tasks) - 0.3)
ax.set_xlim(date(2026, 7, 1), date(2026, 11, 1))
ax.xaxis.set_major_locator(mdates.MonthLocator()); ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %Y"))
ax.xaxis.set_minor_locator(mdates.WeekdayLocator(byweekday=0))
ax.grid(axis="x", which="minor", color="#d9d9d9", lw=0.6); ax.grid(axis="x", which="major", color="#7f7f7f", lw=1)
ax.xaxis.tick_top(); ax.tick_params(axis="x", labelsize=11.5)
for sp in ["right", "bottom", "left"]: ax.spines[sp].set_visible(False)
plt.savefig(f"{OUT}/gantt.png", bbox_inches="tight")
SIZES["gantt"] = (11, MAX_H)

# ---------------------------------------------------------------- report: effective printed font size
print(f"{'diagram':20s} {'px':>11s}  shown at   smallest text in print")
for name, (font, max_h) in SIZES.items():
    w, h = Image.open(f"{OUT}/{name}.png").size
    shown_w = min(TEXT_W, max_h * w / h)
    eff = font * shown_w / (w / DPI)
    print(f"{name:20s} {w:5d}x{h:<5d}  {shown_w:4.2f}\"x{shown_w*h/w:4.2f}\"  {eff:4.1f} pt {'OK' if eff >= 8 else 'SMALL'}")
