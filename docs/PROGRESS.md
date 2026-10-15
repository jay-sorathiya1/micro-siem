# Micro-SIEM — Progress & Project Flow

Living log of what's built, what changed, and what's next. Update this
whenever a real feature lands or a real bug gets fixed — not every tiny
edit, but anything worth remembering for the report or viva.

---

## Project Flow (high level)

```
web login.log ───┬──▶ Vector ──▶ OpenSearch ──▶ FastAPI (background detection loop + auth)
nginx access.log ┘                                   │
                                     react-dashboard Nginx (8090, proxies /api/)
                                                        ├─▶ Admin Dashboard
                                                        └─▶ Viewer Dashboard

Demo attack surface (separate):
Home (8080) → Login (3 accounts) → Search (XSS target)
```

---

## Status: Core Features (Done)

- [x] 2 active log sources ingested (web login, Nginx access) + dashboard logins now logged too (`log_type: dashboard_login`)
- [x] Web login brute-force detection (T1110) — **now 5 failures on the SAME username** from one IP within 2 min (was: any usernames). Keeps brute force and spraying separate: a spray across many accounts no longer also trips brute force
- [x] Password-spraying detection (T1110.003) — failed logins against 3+ distinct usernames from one IP within 5 min; de-duplicated (one alert per IP per 5 min); `_run_password_spraying_rule()` in `main.py`. Verified live (before the aggregation rewrite): 3 usernames → 1 spraying alert (no brute force); 1 username ×6 → brute force only; case variants of one username → no alert; repeated spray → still 1 alert
- [x] Correlation rule — fail-then-success (T1078)
- [x] XSS detection — signature-based (OWASP/CWE-79, honestly not forced into MITRE); now matches the URL-decoded path
- [x] Detection runs in a background loop every 5 s (no longer depends on a dashboard being open)
- [x] Attack Vectors chart colour-coded: XSS, brute force, password spraying = red; suspicious login = blue (admin + viewer)
- [x] Admin + Viewer dashboards, real backend session auth (not browser popup)
- [x] Role-based access (viewer can't call block/unblock — 403 enforced server-side)
- [x] IST timezone across all dashboard timestamps
- [x] Mobile-responsive, single-screen dashboards
- [x] Demo attack-surface site: Home → Login → Search (real XSS target)
- [x] ngrok tested for remote/mobile-data demo access
- [x] GitHub repo set up, push workflow working (`gh` CLI installed in `~/.local/bin`, git uses it for credentials)
- [x] README rewritten (current structure, ports, rules, `.env` setup, XSS demo payload)
- [ ] Project report — old `docs/Micro-SIEM.docx` **deleted** (to be rewritten in a new format; full old text archived outside the repo, also in git history at `871bf4f`)
- [ ] Presentation — old `docs/Micro-SIEM.pptx` **deleted** (to be rewritten; all 20 slides + speaker notes archived, also in git history at `871bf4f`)
- [x] Viva guide — `docs/Micro-SIEM_Viva_Guide.pdf` (14 pages) — **now outdated** in places: dashboards use `/api` on 8090 not `:8000`, passwords live in `.env`, detection is a background loop, brute force is per username, OpenSearch is localhost-only

## Disabled for Now (code kept, planned for a future version)

- **IP-level blocking** (iptables/ip6tables) and **account-level blocking** — switched off via
  `BLOCKING_ENABLED = False` in `src/api/main.py`. Block/unblock endpoints return 503, so no
  firewall rule runs and no account gets locked. In the admin dashboard, "Execute IP Level Block",
  "Block User" and "Unblock" show a "Coming Soon" popup. Blocked panel kept (read-only list).
  Re-enable: set flag to `True` + restore old button handlers in `admin.html` from git history
  (the Unblock buttons now use `data-unblock-type` / `data-target` attributes and a delegated
  click listener, so wire the restored handlers into `unblockIp()` / `unblockAccount()`).
  When enabled, blocks now go into both `INPUT` and `DOCKER-USER`, are re-applied on API
  startup, and refuse loopback / own IP / Docker range (see S3, S6, F2 below).

## Removed from the Project

- **SSH entirely** (decision: no SSH) — `auth.log` source + VRL regex parser removed from
  `vector/vector.toml`, `/var/log/auth.log` mount removed from `docker-compose.yml`, SSH
  brute-force rule removed from `main.py`, SSH wording removed from the admin sidebar and demo
  home page. Project now has 2 log sources (web login, Nginx). rsyslog no longer needed.
- **Old report + presentation** — `docs/Micro-SIEM.docx` and `docs/Micro-SIEM.pptx` deleted (commit `46d2081`), pending rewrite.

---

## Known Bugs Fixed (keep for viva reference)

| Bug | Root Cause | Fix |
|---|---|---|
| `auth.log` was an empty directory | Docker auto-created the mount path before rsyslog existed | Removed dir, installed+enabled rsyslog |
| Vector→OpenSearch bulk insert 400 error | OpenSearch 3.8 rejects old ES6 `_type` field | Added `api_version = "v8"` to Vector sink |
| FastAPI querying `@timestamp` | Vector's real field is `timestamp` | Fixed queries |
| VRL `merge()` fallible assignment error | Needs infallible form | Changed to `merge!()` |
| Mobile logins showed same IP as local | Read `request.client.host` instead of `X-Forwarded-For` | Fixed header parsing (later hardened, see S1/S2) |
| Chart.js "undefined" legend | No dataset label + legend shown on single-series chart | Added label, hid legend |
| Donut chart overflowing panel | Flexbox `min-height: auto` default | `min-height: 0` down the flex chain + bounded canvas wrapper |
| IP block failed on IPv6 address | `iptables` is IPv4-only, IPv6 needs `ip6tables` | Auto-detect via `ipaddress` module, pick right tool |
| Duplicate login log entries (~0.6s apart) | Double-tap/click, no submit lock on the button | Added `isSubmitting` guard + disabled button while request in flight |
| SSH rule matched wrong lines (was open bug D3) | `match` on "Failed password" is an analyzed OR query | Resolved by removing SSH from the project |
| Alert spam — same attack re-alerted every dashboard refresh (was D1) | Only XSS used `_already_alerted_recently()`; brute-force and correlation rules wrote a new alert on every `/alerts` call | All 4 rules now call `_already_alerted_recently()` → one alert per rule per IP per 5 min |
| Duplicate alerts with two dashboards open (was D4) | Admin + viewer poll `/alerts` at the same moment; both runs pass the dedupe check before either write is searchable | New `_write_alert()`: deterministic doc ID (alert type + IP + 5-min window) written with `create()` (rejected if it exists) + `refresh="wait_for"`. Verified live: 2 concurrent dashboards for 30 s during an ongoing attack → exactly 1 alert per rule per IP |
| `/alerts` and `/logs` HTTP 500 right after a fresh start (was F3) | `logs-index` only exists once Vector ships the first event; 3 log searches had no `ignore=[404]` | Added `ignore=[404]` + safe `.get()` access. Verified live: with the index deleted, both return 200 with empty lists |

### Fixed in code — 2026-10-15 (offline-tested, NOT yet verified on the live Docker stack)

Docker daemon was not running, so these were tested offline: the API ran against a fake
OpenSearch client (all endpoint, rule, rate-limit, IP-trust and firewall-helper checks passed —
note the test venv used pydantic 2.14 because 2.7.4 doesn't build on the host's Python 3.13;
the Docker image still uses the pinned 2.7.4 on Python 3.11), dashboard JS was syntax-checked
and `toIST`/`escapeHtml` tested in Node, both Nginx configs passed `nginx -t`, and
`docker compose config` validated. **Still to do: full live run** (see Pending).

| # | Bug | Fix |
|---|---|---|
| S1 | Stored XSS in admin dashboard via spoofed IP | API: new `get_client_ip()` trusts `X-Real-IP` only from Nginx (Docker range 172.16.0.0/12) or loopback, and only if it parses as an IP. Both Nginx configs replace (not append) `X-Real-IP`/`X-Forwarded-For` with `$remote_addr`. `admin.html`: every rendered field goes through `escapeHtml()`; no more `onclick="...'${value}'..."` strings (data attributes + delegated listeners) |
| S2 | IP spoofing evades/frames detection | Nginx `realip` module: `X-Forwarded-For` believed only from `set_real_ip_from 172.16.0.0/12` / `127.0.0.1` (the host itself, e.g. ngrok agent), `real_ip_recursive on`. Remote clients can't fake their IP. Side effect: Nginx access-log `source_ip` is now the real client for ngrok traffic too, so XSS alerts are attributed correctly. Limitation: a LAN that itself uses 172.16.0.0/12 would be trusted |
| S3 | IP block didn't stop web attackers | `_apply_firewall_block()` inserts the DROP rule into `INPUT` **and** `DOCKER-USER` (published container ports go through FORWARD → DOCKER-USER). Missing DOCKER-USER chain (e.g. ip6tables) is tolerated. Still true: ngrok traffic all arrives from the local agent, so IP blocking can't stop ngrok users |
| S4 | Dashboard login brute-forceable | Passwords moved to env vars (`DASHBOARD_ADMIN_PASSWORD`, `DASHBOARD_VIEWER_PASSWORD`) read from git-ignored `.env` (`.env.example` committed; compose refuses to start without them). Constant-time compare. Rate limit: 5 failures per IP per 5 min → HTTP 429. Every attempt logged as `dashboard_login_success / _failed / _rate_limited`. Note: the old passwords are still in git history |
| S5 | OpenSearch exposed with no auth | Ports 9200, 9600, 5601 bound to `127.0.0.1` in compose |
| S6 | Loopback protection bypassable | `_parse_block_target()`: parses + normalises with `ipaddress` (`0:0::1` → `::1`, IPv4-mapped unwrapped), refuses loopback, unspecified, link-local, multicast, the machine's own primary IPv4/IPv6 and the Docker range |
| S7 | `escapeHtml()` incomplete | Escapes `"` and `'` too, handles non-strings; blocked-list Unblock buttons use escaped data attributes |
| D2 | Detection only ran while a dashboard was open | FastAPI `lifespan` starts `_detection_loop()`: runs all 4 rules every 5 s in a worker thread, logs and survives errors (e.g. OpenSearch still starting). `/alerts` now only reads alert history |
| D5 | Big attacks under-counted (`size: 500`) | Brute force + spraying use `terms` aggregations (IP → username); correlation uses a `max` aggregation for each IP's last success + a `count` of earlier failures; XSS uses `helpers.scan()` to page through every request in the window |
| D6 | Brute force also fired on password spraying (new, from code review) | Brute force counts failures per IP **and username**; alert records `target_username` |
| D7 | URL-encoded XSS payloads mostly missed (new) | Browser sends `<img onerror=…>` as `%3Cimg%20onerror%3D…`; path is now URL-decoded (twice, for double encoding) before signature matching |
| F1 | Nginx rows showed "Invalid Date", junk chart bucket | `toIST()` (admin + viewer) only appends `Z` when the timestamp has no zone; unparseable → `-` and skipped in the activity chart |
| F2 | Blocklist drifted from real firewall | Unblock removes rules if present and **always** deletes the index record (no more stuck entries); on API startup, blocks from `blocked-index` are re-applied (only when blocking is enabled) |
| F4 | Unbounded `limit` → 500 | `limit` on `/logs` and `/alerts` validated `1–1000` (422 otherwise) |
| F5 | `demo_sessions` never expired | Demo sessions get an 8 h expiry checked in `/session-check`; expired dashboard + demo sessions pruned on each login |
| I1 | `:latest` images + unversioned CDN | Pinned: OpenSearch + Dashboards `3.8.0`, Vector `0.59.0-alpine`, Nginx `1.30.6-alpine`, Tailwind `3.4.17`, Chart.js `4.5.1`. Note: Vector was `:latest` before, so 0.59.0 is untested with this config until the live run |
| I2 | `depends_on` didn't wait for OpenSearch | `condition: service_healthy` on Vector, API and OpenSearch Dashboards |
| I3 | Dashboards needed internet | Tailwind + Chart.js served from `react-dashboard/vendor/`. Google Fonts still from the internet — offline it falls back to system fonts (cosmetic only) |
| I4 | Dashboards called `http://<host>:8000` directly (not ngrok-friendly) | react-dashboard Nginx proxies `/api/` → FastAPI; pages use same-origin `/api` (override still possible with `window.MICRO_SIEM_API_URL`). Only port 8090 needs to be exposed for the dashboards |
| I5 | Vector had no persistent data dir | `data_dir = "/var/lib/vector"` + `vector-data` volume |
| I6 | README stale | Rewritten |
| I7 | Obsolete compose `version:` key | Removed |

---

## Open Bugs / Known Limitations

- Not a bug, but know it for the viva: browsers on the SIEM machine itself appear as the Docker gateway IP (e.g. `172.18.0.1`) in the logs, and can send a trusted `X-Forwarded-For` (they *are* the host).
- In-memory sessions + rate-limit counters: restarting the API logs everyone out and resets the counters.
- Old dashboard passwords (`2632`/`2000`) are in git history — change them in `.env` if the repo is public.
- `search.html` is still intentionally XSS-vulnerable (demo target) — by design.

---

## Pending / Next Up

### High priority
- [ ] **Live verification of the 2026-10-15 fixes** on the Docker stack: `docker compose up --build`, then check: dashboards load via 8090 (incl. from a phone / ngrok), each of the 4 rules fires once, XSS alert shows the real client IP, Nginx rows show proper IST times, `X-Forwarded-For: <img…>` from another machine is ignored, dashboard login → 429 after 5 failures, OpenSearch unreachable from another PC on :9200
- [ ] Rewrite project report and presentation from scratch in the new format (old .docx/.pptx deleted) — must reflect SSH removal, 2 log sources, password-spraying rule, current 4 rules, and the 2026-10-15 fixes (background detection, per-username brute force, IP trust, rate limiting, `.env`)
- [ ] Update viva guide for SSH removal, password-spraying rule and the 2026-10-15 changes
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
- **Every file change (edit, create, delete) must also be recorded in this PROGRESS.md in the same pass.**
- Honest, direct opinions — no sugarcoating, push back when something's a bad idea.
- Explain logic/reasoning, not just working code.
- Realistic, defensible scope matters more than feature count — every addition should survive a viva question.

---

*Last updated 2026-10-15: fixed all open bugs S1–S7, D2, D5, F1, F2, F4, F5, all infra/demo-day risks, plus new D6 (brute force per username) and D7 (URL-decoded XSS matching); README rewritten; `.env`/`.env.example`/`.gitignore` added; Tailwind + Chart.js vendored. Offline-tested only — live Docker verification pending. Earlier: old report + presentation deleted; SSH removed; password-spraying rule added; D1, D4, F3 fixed and verified live.*
