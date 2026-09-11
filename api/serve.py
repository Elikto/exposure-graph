import base64
import os
import secrets
from pathlib import Path

from fastapi import Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.staticfiles import StaticFiles

from app.main import app


class OptionalBasicAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        username = os.getenv("EXPOSURE_AUTH_USER", "").strip()
        password = os.getenv("EXPOSURE_AUTH_PASSWORD", "")
        if not username or not password or request.url.path == "/health":
            return await call_next(request)

        auth = request.headers.get("Authorization", "")
        valid = False
        if auth.startswith("Basic "):
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8")
                supplied_user, supplied_password = decoded.split(":", 1)
                valid = secrets.compare_digest(supplied_user, username) and secrets.compare_digest(supplied_password, password)
            except Exception:
                valid = False
        if not valid:
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="ExposureGraph"'},
                content="Authentication required",
            )
        return await call_next(request)


app.add_middleware(OptionalBasicAuthMiddleware)

static_dir = Path(__file__).resolve().parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="web")
