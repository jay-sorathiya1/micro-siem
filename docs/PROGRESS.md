# Micro-SIEM — Progress & Project Flow

Living log of what's built, what changed, and what's next. Update this
whenever a real feature lands or a real bug gets fixed — not every tiny
edit, but anything worth remembering for the report or viva.

---

## Project Flow (high level)

```
auth.log ─────┐
web login.log ─┼──▶ Vector ──▶ OpenSearch ──▶ FastAPI (detection + auth)
nginx access.log ┘                                   │
                                                        ├─▶ Admin Dashboard
                                                        └─▶ Viewer Dashboard

Demo attack surface (separate):
Home (8080) → Login (3 accounts) → Search (XSS target)
```

---

## Status: Core Features (Done)

- [x] 2 active log sources ingested (web login, Nginx access)
- [x] Web login brute-force detection (T1110)
- [x] Correlation rule — fail-then-success (T1078)
- [x] XSS detection — signature-based (OWASP/CWE-79, honestly not forced into MITRE)
- [x] Attack Vectors chart colour-coded: XSS + brute force = red, suspicious login = blue (admin + viewer)
- [x] Admin + Viewer dashboards, real backend session auth (not browser popup)
- [x] Role-based access (viewer can't call block/unblock — 403 enforced server-side)
- [x] IST timezone across all dashboard timestamps
- [x] Mobile-responsive, single-screen dashboards
- [x] Demo attack-surface site: Home → Login → Search (real XSS target)
- [x] ngrok tested for remote/mobile-data demo access
- [x] GitHub repo set up, push workflow working
- [x] Project report — `docs/Micro-SIEM.docx` (45 pages, college format from `PROJECT_FINAL_INDEX.docx`); all 8 diagrams and 13 screenshots in place (screenshots cropped to page content), index page numbers updated; still needs student name/enrollment/guide filled
- [x] Presentation — `docs/Micro-SIEM.pptx` (20 slides, speaker notes); real screenshots on slides 13–15; still needs student name/enrollment/guide filled
- [x] Viva guide — `docs/Micro-SIEM_Viva_Guide.pdf` (14 pages: all 12 APIs, token sessions, LAN access, OpenSearch, Vector, 26 likely faculty questions with answers, demo-day tips)

## Disabled for Now (code kept, planned for a future version)

- **IP-level blocking** (iptables/ip6tables) and **account-level blocking** — switched off via
  `BLOCKING_ENABLED = False` in `src/api/main.py`. Block/unblock endpoints return 503, so no
  firewall rule runs and no account gets locked. In the admin dashboard, "Execute IP Level Block",
  "Block User" and "Unblock" show a "Coming Soon" popup. Blocked panel kept (read-only list).
  Re-enable: set flag to `True` + restore old button handlers in `admin.html` from git history.
- **SSH ingestion + SSH brute-force detection (T1110)** — not used on this machine (decision: no
  SSH). Vector config and detection rule still exist; `auth.log` source just has no data.

---

## Known Bugs Fixed (keep for viva reference)

| Bug | Root Cause | Fix |
|---|---|---|
| `auth.log` was an empty directory | Docker auto-created the mount path before rsyslog existed | Removed dir, installed+enabled rsyslog |
| Vector→OpenSearch bulk insert 400 error | OpenSearch 3.8 rejects old ES6 `_type` field | Added `api_version = "v8"` to Vector sink |
| FastAPI querying `@timestamp` | Vector's real field is `timestamp` | Fixed queries |
| VRL `merge()` fallible assignment error | Needs infallible form | Changed to `merge!()` |
| Mobile logins showed same IP as local | Read `request.client.host` instead of `X-Forwarded-For` | Fixed header parsing |
| Chart.js "undefined" legend | No dataset label + legend shown on single-series chart | Added label, hid legend |
| Donut chart overflowing panel | Flexbox `min-height: auto` default | `min-height: 0` down the flex chain + bounded canvas wrapper |
| IP block failed on IPv6 address | `iptables` is IPv4-only, IPv6 needs `ip6tables` | Auto-detect via `ipaddress` module, pick right tool |
| Duplicate login log entries (~0.6s apart) | Double-tap/click, no submit lock on the button | Added `isSubmitting` guard + disabled button while request in flight |

---

## Open Bugs (found in full code review — NOT fixed yet)

Ordered by priority. None of these are fixed; this is the to-fix list.

### Security (in the SIEM itself, not the intentional demo holes)

| # | Bug | Where | Root Cause | Suggested Fix |
|---|---|---|---|---|
| S1 | Stored XSS in admin dashboard via spoofed IP | `main.py:149`, `nginx/default.conf:24`, `admin.html` threat + log tables | `source_ip` = first entry of client-controlled `X-Forwarded-For` (nginx `$proxy_add_x_forwarded_for` appends, doesn't replace). Admin renders `source_ip` unescaped via `innerHTML` and inside `onclick="openModal('...')"`. 5 failed logins with `X-Forwarded-For: <img src=x onerror=...>` → script runs in admin's browser, can read the session token and call `/block`/`/unblock` | Take IP from `X-Real-IP` (set by nginx to `$remote_addr`) and validate with `ipaddress`; escape every rendered field; stop building `onclick` strings from data |
| S2 | IP spoofing evades/frames detection | same as S1 | Same spoofable header — attacker rotates a fake IP per request so the per-IP threshold never trips, or frames an innocent IP so admin blocks it | Same fix as S1 |
| S3 | IP block doesn't stop web attackers | `main.py:535` | Rule goes in `INPUT`; Docker-published ports (8080/8090) are routed through `FORWARD`/`DOCKER-USER`, never `INPUT`. Only SSH and direct `:8000` are actually blocked. Local attacks show as Docker gateway IP; ngrok attacks come from the local ngrok agent | Also insert into `DOCKER-USER` chain, or honestly describe blocking as "host-level (SSH + API)" |
| S4 | Dashboard login brute-forceable | `main.py:83-86`, `/auth/login` | 4-digit hardcoded passwords committed to GitHub, no rate limit, SIEM doesn't log its own login attempts | Rate-limit + log `/auth/login` failures as a log source; move creds to env vars |
| S5 | OpenSearch exposed with no auth | `docker-compose.yml` ports 9200/5601 | Security plugin disabled and ports published on all interfaces → anyone on the LAN can read/delete/forge logs, alerts, blocklist | Bind to `127.0.0.1:9200:9200` / `127.0.0.1:5601:5601` |
| S6 | Loopback protection bypassable | `main.py:64, 520` | `NEVER_BLOCK_IPS` is exact string match — `0:0::1`, `127.0.0.2` pass | Use `ipaddress.ip_address(ip).is_loopback` (and protect own LAN IP) |
| S7 | `escapeHtml()` incomplete | `admin.html` | Doesn't escape `"` / `'`; blocked-list `onclick` uses unescaped username | Escape quotes; use event listeners instead of inline `onclick` |

### Detection correctness

| # | Bug | Where | Root Cause | Suggested Fix |
|---|---|---|---|---|
| D1 | Alert spam — ~40 duplicate alerts per attack per open dashboard | `main.py:340-355`, `452-471` | `_already_alerted_recently()` only used by XSS rule; brute-force and correlation rules insert a new alert every `/alerts` call (every 3s per dashboard). Admin UI's group-by-IP hides it, but stat tile + bar chart are inflated | Call dedupe in all rules |
| D2 | Detection only runs while a dashboard is open | `main.py:482` | Detection is triggered by `GET /alerts` polling. No dashboard open during attack + 2-min window passes = attack never detected. Two dashboards = double runs/races | Run `_run_detection()` in a background loop (FastAPI startup task) |
| D3 | SSH rule matches wrong lines (incl. successful logins) | `main.py:327` | `match` on "Failed password" is analyzed OR → matches `Accepted password`, sudo "incorrect password", etc. Lines without IP group under `unknown` → bogus alert | Use `match_phrase` |
| D4 | Dedupe race | `_already_alerted_recently` | OpenSearch ~1s refresh — just-written alert not yet searchable, so duplicates can slip through | `refresh="wait_for"` on alert index, or deterministic doc IDs |
| D5 | Big attacks under-counted | `main.py:323` | `size: 500` caps events per window | Use a `terms` aggregation on `source_ip` |

### Functional / UI

| # | Bug | Where | Root Cause | Suggested Fix |
|---|---|---|---|---|
| F1 | Nginx rows show "Invalid Date", junk chart bucket | `toIST()` in `admin.html` + `viewer.html` | Nginx `$time_iso8601` ends `+00:00`; code appends `Z` → `...+00:00Z` → unparseable | Only append `Z` if no timezone suffix present |
| F2 | Blocklist drifts from real firewall | `main.py:553-570` | iptables rules don't survive reboot, but `blocked-index` record does. Unblock then fails on `iptables -D` → 500 before index cleanup → stuck entry | Delete index record even if rule missing; re-apply rules on API startup |
| F3 | `/alerts` + `/logs` 500 on fresh start | `main.py:259, 333, 445` | No `ignore=[404]` before Vector creates `logs-index` | Add `ignore=[404]` |
| F4 | Unbounded `limit` → 500 | `/logs`, `/alerts` | >10000 exceeds `max_result_window` | Cap `limit` |
| F5 | `demo_sessions` never expire | `main.py:80` | No TTL/cleanup | Add expiry like dashboard sessions |

### Infra / demo-day risks

- `:latest` images + unversioned `chart.js` CDN — a version jump already broke things once (`_type` bug). Pin versions before the viva.
- `depends_on` doesn't wait for OpenSearch healthcheck (add `condition: service_healthy`).
- Dashboards need internet (Tailwind play CDN, Chart.js, Google Fonts) — no internet at venue = broken UI.
- Dashboards call `http://<host>:8000` directly — likely unreachable through ngrok (untested); the ngrok test probably only covered the demo site.
- Vector has no persistent data dir → may skip lines after container recreate.
- README is stale (mentions Streamlit/8501, missing React console on 8090).
- `.git` owned by root ("dubious ownership" error) — fix with `sudo chown -R $USER .git`.

---

## Pending / Next Up

### High priority
- [ ] Password-spraying detection rule — distinct usernames from one IP (MITRE T1110.003)
- [ ] Formal Detection Playbooks (one write-up per rule)
- [ ] Incident Verification Reports (proof-of-detection per rule: screenshot, timestamp, resolution)
- [ ] Full live-demo rehearsal, timed, in the exact order for faculty

### Medium priority
- [ ] Nginx scanning/enumeration detection (bonus 5th rule — many paths hit fast by one IP)
- [ ] Multi-PC live demo rehearsal (admin + viewer on separate physical devices — works, not yet rehearsed as a scenario)

### Explicitly deferred (don't re-suggest without being asked)
- Grafana dashboard — tried once, explicitly rejected by user, reverted
- Full React/npm build tooling — deliberately avoided, staying with plain HTML + CDN React
- Cloud deployment (DigitalOcean/Azure via student pack) — confirmed out of scope for this Minor Project

---

## Working Rules (for continuing this project)

- **Never build/edit/create files unless explicitly told to build.** Discuss and plan freely otherwise.
- Honest, direct opinions — no sugarcoating, push back when something's a bad idea.
- Explain logic/reasoning, not just working code.
- Realistic, defensible scope matters more than feature count — every addition should survive a viva question.

---

*Last updated: blocking disabled behind Coming Soon popup, chart colours added, SSH dropped; project verified running end-to-end on Docker (web login + Nginx pipeline, dashboards, API).*
