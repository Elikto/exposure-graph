import asyncio
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models import ConnectorStatus, GraphNode, SearchRequest, SearchResponse
from app.storage import get_search, init_db, list_searches, save_search
from app.utils import detect_kind, root_node_id
from app.connectors.crtsh import CRTSHConnector
from app.connectors.flowsint import FlowsintConnector
from app.connectors.gravatar import GravatarConnector
from app.connectors.hibp import HIBPConnector
from app.connectors.rdap import RDAPConnector

app = FastAPI(title="ExposureGraph API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5180", "http://127.0.0.1:5180"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

CONNECTORS = [HIBPConnector(), GravatarConnector(), RDAPConnector(), CRTSHConnector(), FlowsintConnector()]


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "app": settings.app_name}


@app.get("/api/connectors", response_model=list[ConnectorStatus])
def connector_statuses() -> list[ConnectorStatus]:
    return [
        ConnectorStatus(name="Flowsint", configured=bool(settings.flowsint_api_token and settings.flowsint_sketch_id), category="OSINT graph", requires_key=True, note="Read-only graph import in MVP"),
        ConnectorStatus(name="Have I Been Pwned", configured=bool(settings.hibp_api_key), category="Breach intelligence", requires_key=True, note="Breaches, pastes, official stealer-log domains when plan/verification permits"),
        ConnectorStatus(name="Gravatar", configured=settings.enable_gravatar, category="Public identity", note="Public avatar presence"),
        ConnectorStatus(name="RDAP", configured=settings.enable_rdap, category="Infrastructure", note="Domain/IP registration data"),
        ConnectorStatus(name="Certificate Transparency", configured=settings.enable_crtsh, category="Infrastructure", note="crt.sh certificate names"),
        ConnectorStatus(name="VirusTotal", configured=bool(settings.vt_api_key), category="Reputation", requires_key=True, note="Connector planned"),
        ConnectorStatus(name="Shodan", configured=bool(settings.shodan_api_key), category="Infrastructure", requires_key=True, note="Connector planned"),
    ]


@app.get("/api/searches")
def searches() -> list[dict]:
    return list_searches()


@app.get("/api/searches/{search_id}", response_model=SearchResponse)
def search_by_id(search_id: str) -> SearchResponse:
    result = get_search(search_id)
    if result is None:
        raise HTTPException(status_code=404, detail="Search not found")
    return result


@app.post("/api/search", response_model=SearchResponse)
async def search(request: SearchRequest) -> SearchResponse:
    query = request.query.strip()
    kind = detect_kind(query) if request.kind == "auto" else request.kind

    personal_kinds = {"email", "phone", "username", "person", "address"}
    if kind in personal_kinds and not request.owned_or_authorized:
        raise HTTPException(
            status_code=400,
            detail="Personal-identifier searches require ownership or explicit authorization.",
        )

    root_id = root_node_id(kind, query)
    root = GraphNode(
        id=root_id,
        type=kind,
        label=query,
        properties={"query": query, "kind": kind},
        source="Search input",
        confidence=1.0,
        risk=0,
    )

    results = await asyncio.gather(
        *(connector.run(query, kind, root_id) for connector in CONNECTORS),
        return_exceptions=True,
    )
    node_map = {root.id: root}
    edge_map = {}
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
            if node.id not in node_map:
                node_map[node.id] = node
        for edge in item.edges:
            if edge.id not in edge_map:
                edge_map[edge.id] = edge
        breaches.extend(item.breaches)

    if kind in {"person", "address"}:
        warnings.append(
            "MVP: no data-broker or illicit-dump lookup is performed for names/addresses; "
            "only configured Flowsint data can match them."
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
