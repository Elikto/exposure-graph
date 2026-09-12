import asyncio
import base64
import os
import secrets
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import HTTPException, Request
from fastapi.responses import Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.staticfiles import StaticFiles

from app.main import CONNECTORS, app
from app.models import GraphEdge, GraphNode, SearchRequest, SearchResponse
from app.storage import save_search
from app.utils import detect_kind, root_node_id
from app.connectors.maigret_fast import MaigretFastConnector


FAST_MAIGRET = MaigretFastConnector()
FAST_SKIP = {"Holehe", "Maigret Public Profiles", "Flowsint"}


@app.post("/api/search/fast", response_model=SearchResponse)
async def fast_search(request: SearchRequest) -> SearchResponse:
    query = request.query.strip()
    kind = detect_kind(query) if request.kind == "auto" else request.kind
    personal_kinds = {"email", "phone", "username", "person", "address"}
    if kind in personal_kinds and not request.owned_or_authorized:
        raise HTTPException(status_code=400, detail="Personal-identifier searches require ownership or explicit authorization.")

    root_id = root_node_id(kind, query)
    root = GraphNode(
        id=root_id,
        type=kind,
        label=query,
        properties={"query": query, "kind": kind, "scan_mode": "fast"},
        source="Search input",
        confidence=1.0,
        risk=0,
    )
    fast_connectors = [connector for connector in CONNECTORS if connector.name not in FAST_SKIP]
    results = await asyncio.gather(
        *(connector.run(query, kind, root_id) for connector in fast_connectors),
        return_exceptions=True,
    )

    node_map = {root.id: root}
    edge_map: dict[str, GraphEdge] = {}
    breaches = []
    source_runs = []
    warnings = []
    for item in results:
        if isinstance(item, Exception):
            warnings.append(str(item))
            continue
        if item.run:
            source_runs.append(item.run)
        for node in item.nodes:
            node_map.setdefault(node.id, node)
        for edge in item.edges:
            edge_map.setdefault(edge.id, edge)
        breaches.extend(item.breaches)

    username = ""
    parent_id = root_id
    if kind == "username":
        username = query.strip().lstrip("@")
    elif kind == "email":
        candidates: list[tuple[float, str, str]] = []
        for node in node_map.values():
            for key in ("username", "handle", "screen_name", "screenName", "login", "preferredUsername"):
                value = node.properties.get(key)
                if isinstance(value, str):
                    candidate = value.strip().lstrip("@")
                    if len(candidate) >= 2 and " " not in candidate and "@" not in candidate:
                        candidates.append((float(node.confidence), candidate, node.id))
        if candidates:
            _, username, parent_id = max(candidates, key=lambda item: item[0])
        else:
            local_part = query.split("@", 1)[0].strip().lstrip("@")
            if len(local_part) >= 3:
                username = local_part
                parent_id = f"fast:username:{local_part.lower()}"
                node_map[parent_id] = GraphNode(
                    id=parent_id,
                    type="username",
                    label=local_part,
                    properties={
                        "username": local_part,
                        "evidence_level": "candidate",
                        "match_reason": "Derived from the email local-part for the fast scan only",
                    },
                    source="Fast scan candidate",
                    confidence=0.36,
                    risk=0,
                )
                edge_map[f"{root_id}->{parent_id}"] = GraphEdge(
                    id=f"{root_id}->{parent_id}",
                    source=root_id,
                    target=parent_id,
                    label="POSSIBLE_USERNAME",
                    source_name="Fast scan candidate",
                    confidence=0.36,
                )

    if username:
        expanded = await FAST_MAIGRET.run(username, "username", parent_id)
        if expanded.run:
            source_runs.append(expanded.run)
        for node in expanded.nodes:
            node_map.setdefault(node.id, node)
        for edge in expanded.edges:
            edge_map.setdefault(edge.id, edge)

    warnings.append(
        "Mode rapide: Holehe, Flowsint approfondi et l’énumération large de profils sont ignorés. "
        "Utilisez Scan complet pour la couverture maximale."
    )
    result = SearchResponse(
        search_id=str(uuid.uuid4()),
        query=query,
        kind=kind,
        created_at=datetime.now(timezone.utc),
        nodes=list(node_map.values()),
        edges=list(edge_map.values()),
        breaches=breaches,
        sources=source_runs,
        warnings=warnings,
    )
    save_search(result)
    return result


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
