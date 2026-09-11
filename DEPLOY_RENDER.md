# ExposureGraph on Render

ExposureGraph can be deployed as one authenticated Render web service.

- Runtime: Python
- Build command: `pip install -r api/requirements.txt && npm --prefix web ci && npm --prefix web run build && rm -rf api/static && cp -r web/dist api/static`
- Start command: `cd api && uvicorn serve:app --host 0.0.0.0 --port $PORT`
- Recommended region: Frankfurt

Environment variables:

- `PYTHON_VERSION=3.12.11`
- `DATA_DIR=/tmp/exposuregraph`
- `EXPOSURE_AUTH_USER=<username>`
- `EXPOSURE_AUTH_PASSWORD=<strong password>`

When the auth variables are set, every route except `/health` is protected with HTTP Basic authentication. The public deployment does not expose a local Flowsint instance; Flowsint remains optional unless a secure reachable Flowsint endpoint is configured separately.
