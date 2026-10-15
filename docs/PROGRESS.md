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
- [x] Web login brute-force detection (T1110) — **now 5 failures on the SAME username** from one IP within 2 min (was: any usernames); attempts on blocked accounts (`login_blocked`) count too, same for spraying. Keeps brute force and spraying separate: a spray across many accounts no longer also trips brute force
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

### Fixed 2026-10-15 — verified live on the Docker stack (34/35 checks passed, 1 inconclusive)

**Live run 2026-10-15** (`docker compose up --build`, all 6 containers up, OpenSearch healthy, no dashboard open during the attacks; each scenario sent from its own fake client IP via `X-Forwarded-For` from the host, which Nginx trusts):
- Ingestion: web-login and Nginx events reach `logs-index` via Vector; Nginx events carry the forwarded client IP
- Detection (background loop, no dashboard open): 6 fails on one user → brute force only; 3 users → spraying only; 2 fails + success → correlation only; URL-encoded `<img onerror=alert(document.cookie)>` (no `<script`) → XSS; normal traffic → no alert; continued attack → still 1 alert
- Dashboards via 8090: pages + vendored Tailwind/Chart.js served; admin + viewer login through `/api` with `.env` passwords; `/api/alerts` + `/api/logs` work; `limit=99999` → 422; no token → 401; viewer block → 403; admin block → 503 (disabled); Nginx timestamp `…+00:00` renders as IST
- Security: dashboard login `401×5 → 429` and attempts logged as `dashboard_login_*`; direct call to `:8000` from an untrusted address with fake `X-Real-IP` → real peer IP logged; fake `X-Forwarded-For: <img…>` never reaches the logs; OpenSearch `:9200` unreachable from another network, still reachable on localhost; Vector checkpoints in the `vector-data` volume; 0 detection-loop errors
- **All 12 API endpoints tested live (49/49 checks passed):** `GET /` (direct, via 8080 and 8090 proxies); `POST /auth/login` (admin/viewer roles, wrong password/unknown user → 401, missing field → 422); `GET /logs` + `GET /alerts` (admin + viewer, `limit` 1–1000 enforced → 422 for 0/1001/5000/abc, missing/bad/malformed token → 401); `GET /blocked` (admin + viewer, no token → 401); `POST /block`, `/unblock`, `/block-account`, `/unblock-account` (admin → 503 disabled, viewer → 403, no token → 401, GET → 405); `POST /login` demo (success token, wrong password → `success:false`, bad JSON → 422); `GET /session-check` (valid / fake / missing token); `POST /auth/logout` (token invalidated, other sessions unaffected); `/openapi.json` lists exactly 12 paths, `/docs` serves
- **Account blocking tested live (28/28 passed)** — the code is still switched off (`BLOCKING_ENABLED = False`), so it was tested with a temporary second API container on `127.0.0.1:8001` with the flag flipped *inside the container only* (no `NET_ADMIN`, so no firewall rules possible), sharing the real `blocked-index`; effects checked on the REAL demo site (8080 → API 8000). Results: viewer → 403 / anonymous → 401 on block + unblock; admin block → `blocked`, again → `already_blocked`; `/blocked` lists it (viewer can read); blocked user refused immediately with the right AND wrong password ("blocked by an administrator", no token); their existing session is rejected on next `/session-check` and the token deleted; other users and their sessions unaffected; username match is case-sensitive (`Test` ≠ `test`, which matches the case-sensitive login); attempts logged as `event: login_blocked, result: blocked`; unblock → can log in immediately; unblocking a non-blocked account is harmless; non-existent and HTML usernames can be blocked and are stored as plain text. Test container removed, `blocked-index` left empty
- **Finding → fixed same day (D8, see table):** attempts against a blocked account were logged as `login_blocked`, not `login_failed`, so brute force / spraying didn't count them
- **Inconclusive:** "LAN client can't spoof `X-Forwarded-For` with a valid IP" could not be tested from this one machine — a test container on another Docker network gets source-NATed to the gateway `172.18.0.1` (which Nginx trusts), and with NAT off Docker isolation drops the reply. A real LAN device is DNATed without source NAT, so it should appear with its own IP — **confirm from a phone on the same Wi-Fi** (see Pending)

Earlier offline testing (before Docker was available): the API ran against a fake
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
| D8 | Attacks on a **blocked** account raised no alert (found in account-blocking test) | `GUESS_EVENTS = ("login_failed", "login_blocked")` in `main.py`; brute-force and spraying rules count both, correlation still counts only `login_failed` (a blocked attempt isn't a real failed password check). Verified live (7/7): 6 tries on blocked `test` (even with the right password) → brute force only, `target_username: test`, count 6; 1 try each on 3 blocked accounts → spraying only; 2 blocked tries + a success on another account → no correlation alert. Side effect to know: a legitimate user of a blocked account retrying 5× also triggers brute force |
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
- [x] Live verification of the 2026-10-15 fixes on the Docker stack — 34/35 checks passed (details under "Fixed 2026-10-15")
- [ ] From a phone on the same Wi-Fi: open `http://<PC-IP>:8080`, make a failed login, confirm the log shows the phone's own IP; also open the dashboards on `http://<PC-IP>:8090` (and via ngrok) and check they render
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

*Last updated 2026-10-15: D8 fixed — brute force + spraying now also count `login_blocked` attempts (verified live 7/7). Before that: fixed all open bugs S1–S7, D2, D5, F1, F2, F4, F5, all infra/demo-day risks, plus new D6 (brute force per username) and D7 (URL-decoded XSS matching); README rewritten; `.env`/`.env.example`/`.gitignore` added; Tailwind + Chart.js vendored. Verified live on Docker (34/35; LAN-spoof check needs a phone test). Earlier: old report + presentation deleted; SSH removed; password-spraying rule added; D1, D4, F3 fixed and verified live.*
