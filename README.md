# WebScan: web application security scanner (educational)

Flask backend + SQLite storage + browser UI + HTML report + pytest tests.

## What it checks (all non-destructive, GET only)
- Missing security headers (CSP, HSTS, X-Frame-Options, ...) and version banners
- Cookie flags (HttpOnly, Secure, SameSite)
- HTTPS use and TLS certificate expiry
- Exposed sensitive paths (/.env, /.git/HEAD, ...)
- Forms: missing CSRF tokens, passwords over HTTP
- Input handling signals: unescaped reflection of a harmless canary, SQL error messages

## Safety
Scans are limited to localhost/private IPs. To allow another host you own:
`export WEBSCAN_ALLOWED=staging.mycompany.com`. The UI also requires an authorization checkbox.

## Run
```
pip install -r requirements.txt
python demo_target.py      # terminal 1: vulnerable lab app on :8000
python app.py              # terminal 2: scanner on :5000
```
Open http://127.0.0.1:5000 and scan `http://127.0.0.1:8000/?q=test`.

## Test
`pytest -q`

## API
- POST /api/scan  {url, confirmed}
- GET  /api/scans, /api/scans/<id>, /report/<id>

## Ideas to extend
Crawler for multiple pages, severity scoring (CVSS-style), PDF export, scheduled scans, user login.

## Deploy on Render
1. Web service 1 (scanner): Build `pip install -r requirements.txt`, Start `gunicorn app:app --threads 4`.
2. Web service 2 (lab target): same repo, Start `gunicorn demo_target:app`.
3. On service 1 add env var `WEBSCAN_ALLOWED` = the lab service hostname (e.g. `webscan-lab.onrender.com`).
