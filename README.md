# Micro-SIEM

A small Security Information and Event Management system: it collects web
login and Nginx access logs, stores them in OpenSearch, runs four detection
rules every few seconds, and shows the results on admin and viewer dashboards.
A deliberately weak demo website is included as the attack target.

## Structure
```
micro-siem/
├── docker-compose.yml        # ties everything together
├── .env.example              # copy to .env and set dashboard passwords
├── vector/
│   └── vector.toml           # log ingestion: login.log + Nginx access log -> OpenSearch
├── src/api/                  # FastAPI backend: detection rules, auth, API
│   ├── Dockerfile
│   ├── requirements.txt
│   └── main.py
├── nginx/                    # demo attack-target site (port 8080)
│   ├── default.conf
│   └── html/                 # index.html -> login.html -> search.html (XSS target)
├── react-dashboard/          # admin + viewer dashboards (port 8090)
│   ├── nginx.conf            # serves the pages, proxies /api/ to FastAPI
│   ├── login.html, admin.html, viewer.html
│   └── vendor/               # Tailwind + Chart.js, served locally (works offline)
└── docs/                     # PROGRESS.md (living project log), screenshots, viva guide
```

## How it works
```
FastAPI /login  -> login.log ---------┐
Nginx (8080)    -> access_json.log ---┴-> Vector -> OpenSearch (logs-index)
                                                          │
         FastAPI background loop (every 5 s) runs the rules, writes alerts-index
                                                          │
             Admin / Viewer dashboards (8090) <- /api/ <--┘
```

Detection rules (`src/api/main.py`):

| Rule | Logic | Mapping |
|---|---|---|
| Web login brute force | 5 failed logins on the **same username** from one IP within 2 min (attempts on blocked accounts count too) | MITRE T1110 |
| Password spraying | failed logins on **3+ different usernames** from one IP within 5 min (attempts on blocked accounts count too) | MITRE T1110.003 |
| Fail-then-success correlation | 2+ failures followed by a success from one IP within 2 min | MITRE T1078 |
| XSS attempt | known payload signatures in the URL-decoded Nginx request path | OWASP / CWE-79 |

Each rule raises at most one alert per source IP per 5 minutes.

## How to run
From the `micro-siem/` folder:

```bash
cp .env.example .env      # first time only - then set the two passwords in .env
docker compose up --build
```

The first run takes a few minutes (pulling images and building the API image).
Services wait for OpenSearch to be healthy before starting.

## Access points
| What | URL | Reachable from |
|---|---|---|
| Demo attack-target site | http://localhost:8080 | anywhere on the network |
| Admin / viewer dashboards | http://localhost:8090 | anywhere on the network |
| FastAPI + auto docs | http://localhost:8000/docs | anywhere on the network |
| OpenSearch API | http://localhost:9200 | this machine only |
| OpenSearch Dashboards (raw data) | http://localhost:5601 | this machine only |

Demo-site accounts (intentionally weak): `admin/1234`, `test/1111`, `guest/0000`.
Dashboard accounts: `admin` and `viewer`, with the passwords from your `.env`.

For the XSS demo, use a payload such as `<img src=x onerror=alert(1)>` on the
search page. A `<script>` tag is detected too, but browsers don't run scripts
inserted with `innerHTML`, so it won't pop up.

## Checking things are working
```bash
docker compose ps              # see which containers are up
docker compose logs vector     # confirm Vector is shipping events
docker compose logs api        # confirm FastAPI started without errors
```

## Important notes
- **Client IPs:** both Nginx containers only trust `X-Forwarded-For` from a
  proxy on this machine (e.g. the ngrok agent), so remote clients can't fake
  their IP. Browsers on this machine show up as the Docker gateway address.
- **IP / account blocking** is built but switched off (`BLOCKING_ENABLED = False`
  in `main.py`); the dashboard shows a "Coming Soon" popup. When enabled, an
  IP block is added to both the `INPUT` and `DOCKER-USER` firewall chains.
- **Dashboard login** is rate-limited (5 failures per IP per 5 min) and every
  attempt is logged as `dashboard_login` events.
- Image versions are pinned in `docker-compose.yml`; change them deliberately.

## Common issues
- **Compose says `DASHBOARD_ADMIN_PASSWORD is missing a value`** -> create `.env`
  from `.env.example`.
- **"connection refused" between containers** -> use the service name
  (`opensearch`) as the hostname, not `localhost`. The API is the exception: it
  runs in host network mode and uses `localhost:9200`.
- **Vector shows no data** -> it only reads new lines (`read_from = "end"`);
  make a login attempt or load a page on port 8080 to generate events.
