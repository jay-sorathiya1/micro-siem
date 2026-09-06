# Micro-SIEM — Project Setup

## Structure
```
micro-siem/
├── docker-compose.yml       # ties everything together
├── vector/
│   └── vector.toml          # log ingestion config (auth.log -> OpenSearch)
├── src/
│   ├── api/                 # FastAPI backend (your detection logic)
│   │   ├── Dockerfile
│   │   ├── requirements.txt
│   │   └── main.py
│   └── dashboard/            # Streamlit frontend
│       ├── Dockerfile
│       ├── requirements.txt
│       └── app.py
├── config/                   # (for future config files)
├── detections/                # (for future detection rule files, MITRE mapping)
├── docs/                      # (for your Project Charter, playbooks, reports)
└── tests/                     # (for your Incident Verification Reports)
```

## How to run
From the `micro-siem/` folder:

```bash
docker-compose up --build
```

First run will take a few minutes (pulling OpenSearch image + building your two custom images).

## Access points (all in your browser)
- OpenSearch API: http://localhost:9200
- OpenSearch Dashboards (optional raw data explorer): http://localhost:5601
- FastAPI (your backend + auto docs): http://localhost:8000/docs
- Streamlit dashboard (your main demo screen): http://localhost:8501

## Checking things are working
```bash
docker-compose ps                 # see which containers are up
docker-compose logs vector        # confirm Vector is reading auth.log
docker-compose logs api           # confirm FastAPI started without errors
docker-compose logs dashboard     # confirm Streamlit started
```

## Important notes
- `vector.toml` reads `/var/log/auth.log` from YOUR HOST MACHINE (mounted as a volume).
  If your logs are somewhere else, update the volume path in `docker-compose.yml`.
- Detection logic lives in `src/api/main.py` inside the `/alerts` endpoint —
  this is the part you should understand deeply, not just run.
- The dashboard auto-refreshes every 3 seconds — good for a live demo.

## Common issues
- **"connection refused" between containers** → don't use `localhost`, use the
  service name (`opensearch`, `api`) as the hostname — Docker Compose networking.
- **Vector shows no data** → check the volume path to `auth.log` is correct for
  your machine, and that SSH is actually generating log entries.
- **OpenSearch takes a while to be ready** → `depends_on` only waits for the
  container to start, not for OpenSearch to actually accept connections. If
  Vector/API fail on first `docker-compose up`, just run it again.
