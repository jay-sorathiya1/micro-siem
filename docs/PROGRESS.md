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

- [x] 3 real log sources ingested (SSH auth.log, web login, Nginx access)
- [x] SSH brute-force detection (T1110)
- [x] Web login brute-force detection (T1110)
- [x] Correlation rule — fail-then-success (T1078)
- [x] XSS detection — signature-based (OWASP/CWE-79, honestly not forced into MITRE)
- [x] Real IP-level blocking (iptables + ip6tables, IPv4/IPv6 both handled)
- [x] Real account-level blocking (app-level, admin-triggered)
- [x] Blocked panel with Unblock buttons (admin dashboard)
- [x] Blocked accounts actually locked out of demo login going forward
- [x] Blocked-account sessions kicked out on next page load (session-check)
- [x] Admin + Viewer dashboards, real backend session auth (not browser popup)
- [x] Role-based access (viewer can't call block/unblock — 403 enforced server-side)
- [x] IST timezone across all dashboard timestamps
- [x] Mobile-responsive, single-screen dashboards
- [x] Demo attack-surface site: Home → Login → Search (real XSS target)
- [x] ngrok tested for remote/mobile-data demo access
- [x] GitHub repo set up, push workflow working

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

*Last updated: reflects state after IPv6 firewall fix + double-submit bug diagnosis.*
