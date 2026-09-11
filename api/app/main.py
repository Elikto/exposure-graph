import asyncio
import uuid
import httpx
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models import ConnectorStatus, GraphNode, SearchRequest, SearchResponse
from app.storage import delete_integration, get_integration, get_search, init_db, list_searches, save_search, set_integration
from app.utils import detect_kind, root_node_id
from app.connectors.crtsh import CRTSHConnector
from app.connectors.flowsint import FlowsintConnector
from app.connectors.gravatar import GravatarConnector
from app.connectors.hibp import HIBPConnector
from app.connectors.rdap import RDAPConnector
from app.connectors.urlscan import URLScanConnector
from app.connectors.virustotal import VirusTotalConnector
from app.connectors.shodan import ShodanConnector

app = FastAPI(title="ExposureGraph API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5180", "http://127.0.0.1:5180", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

CONNECTORS = [HIBPConnector(), GravatarConnector(), RDAPConnector(), CRTSHConnector(), URLScanConnector(), VirusTotalConnector(), ShodanConnector(), FlowsintConnector()]


REMOVAL_OVERRIDES = {
    "reddit.com": ("Reddit", "https://support.reddithelp.com/hc/en-us/articles/204579509-How-do-I-delete-my-account", "medium"),
    "tiktok.com": ("TikTok", "https://support.tiktok.com/en/account-and-privacy/manage-account/delete-account", "medium"),
    "twitch.tv": ("Twitch", "https://help.twitch.tv/s/article/delete-twitch-account", "medium"),
    "twitchtracker.com": ("Twitch", "https://help.twitch.tv/s/article/delete-twitch-account", "medium"),
    "discord.com": ("Discord", "https://support.discord.com/hc/fr/articles/212500837-Comment-supprimer-votre-compte-Discord", "medium"),
    "discords.com": ("Discord", "https://support.discord.com/hc/fr/articles/212500837-Comment-supprimer-votre-compte-Discord", "medium"),
    "wordpress.com": ("WordPress.com", "https://wordpress.com/fr/support/fermer-compte/", "medium"),
    "vimeo.com": ("Vimeo", "https://help.vimeo.com/hc/fr/articles/12425669379601-Comment-supprimer-mon-compte", "easy"),
    "paypal.com": ("PayPal", "https://www.paypal.com/fr/cshelp/article/comment-fermer-mon-compte-paypal%C2%A0-help247", "medium"),
    "apple.com": ("Apple", "https://privacy.apple.com/", "medium"),
}


def _domain_matches(host: str, candidate: str) -> bool:
    host = host.lower().split(":")[0].strip(".")
    candidate = candidate.lower().split(":")[0].strip(".")
    return host == candidate or host.endswith("." + candidate) or candidate.endswith("." + host)


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "app": settings.app_name}


@app.get("/api/connectors", response_model=list[ConnectorStatus])
def connector_statuses() -> list[ConnectorStatus]:
    return [
        ConnectorStatus(name="Flowsint", configured=bool((get_integration("flowsint") or {}).get("access_token") or settings.flowsint_api_token), category="OSINT graph", requires_key=True, note="Graph plus Maigret, Sherlock, Holehe and other local enrichers after login"),
        ConnectorStatus(name="Have I Been Pwned", configured=bool(settings.hibp_api_key), category="Breach intelligence", requires_key=True, note="Breaches, pastes, official stealer-log domains when plan/verification permits"),
        ConnectorStatus(name="Gravatar", configured=settings.enable_gravatar, category="Public identity", note="Public avatar presence"),
        ConnectorStatus(name="RDAP", configured=settings.enable_rdap, category="Infrastructure", note="Domain/IP registration data"),
        ConnectorStatus(name="Certificate Transparency", configured=settings.enable_crtsh, category="Infrastructure", note="crt.sh certificate names"),
        ConnectorStatus(name="urlscan.io", configured=settings.enable_urlscan, category="Public web scans", requires_key=False, note="Public historical URL/domain scans; API key increases quota"),
        ConnectorStatus(name="VirusTotal", configured=bool(settings.vt_api_key), category="Reputation", requires_key=True, note="Domain/IP reputation and detections"),
        ConnectorStatus(name="Shodan", configured=bool(settings.shodan_api_key), category="Infrastructure", requires_key=True, note="IP exposure and open services"),
    ]




@app.post("/api/removal-links")
async def removal_links(payload: dict) -> list[dict]:
    domains = [str(d).strip().lower() for d in payload.get("domains", []) if str(d).strip()][:250]
    catalog: list[dict] = []
    try:
        async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
            resp = await client.get("https://raw.githubusercontent.com/justdeleteme/justdelete.me/master/sites.json")
        if resp.status_code == 200:
            raw = resp.json()
            if isinstance(raw, list):
                catalog = [item for item in raw if isinstance(item, dict)]
    except Exception:
        catalog = []
    results = []
    for domain in domains:
        found = None
        for key, (name, url, difficulty) in REMOVAL_OVERRIDES.items():
            if _domain_matches(domain, key):
                found = {"domain": domain, "name": name, "url": url, "difficulty": difficulty, "source": "official/current"}
                break
        if not found:
            for item in catalog:
                item_domains = item.get("domains") or []
                if any(_domain_matches(domain, str(candidate)) for candidate in item_domains):
                    found = {"domain": domain, "name": item.get("name") or domain, "url": item.get("url"), "difficulty": item.get("difficulty") or "unknown", "notes": item.get("notes_fr") or item.get("notes"), "source": "JustDeleteMe"}
                    break
        results.append(found or {"domain": domain, "name": domain, "url": None, "difficulty": "unknown", "source": "not_catalogued"})
    return results

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


@app.get("/api/monitored-identities")
def monitored_identities() -> list[dict]:
    from app.storage import list_monitored_identities
    return list_monitored_identities()


@app.post("/api/monitored-identities", status_code=201)
def create_monitored_identity(payload: dict) -> dict:
    import sqlite3
    from app.storage import add_monitored_identity
    value = str(payload.get("value", "")).strip().lower()
    kind = str(payload.get("kind", "email"))
    owned = bool(payload.get("owned_or_authorized", False))
    label = payload.get("label")
    if kind != "email" or "@" not in value:
        raise HTTPException(status_code=400, detail="A valid email address is required")
    if not owned:
        raise HTTPException(status_code=400, detail="Ownership or explicit authorization is required")
    try:
        return add_monitored_identity(value, kind, label, owned)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This email is already monitored")


@app.delete("/api/monitored-identities/{identity_id}", status_code=204)
def remove_monitored_identity(identity_id: str) -> None:
    from app.storage import delete_monitored_identity
    if not delete_monitored_identity(identity_id):
        raise HTTPException(status_code=404, detail="Monitored identity not found")


def _flowsint_token() -> str:
    integration = get_integration("flowsint") or {}
    return str(integration.get("access_token") or settings.flowsint_api_token or "")


@app.get("/api/integrations/flowsint")
async def flowsint_integration_status() -> dict:
    token = _flowsint_token()
    if not token:
        return {"connected": False, "sketch_id": settings.flowsint_sketch_id}
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{settings.flowsint_base_url.rstrip('/')}/api/auth/me", headers=headers)
        if resp.status_code != 200:
            return {"connected": False, "expired": True, "sketch_id": settings.flowsint_sketch_id}
        user = resp.json()
        return {"connected": True, "email": user.get("email"), "sketch_id": (get_integration("flowsint") or {}).get("sketch_id") or settings.flowsint_sketch_id}
    except Exception as exc:
        return {"connected": False, "error": str(exc), "sketch_id": settings.flowsint_sketch_id}


@app.post("/api/integrations/flowsint/session")
async def flowsint_integration_session(payload: dict) -> dict:
    token = str(payload.get("token", "")).strip()
    if not token:
        raise HTTPException(status_code=400, detail="Flowsint session token is required")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{settings.flowsint_base_url.rstrip('/')}/api/auth/me", headers=headers)
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid or expired Flowsint session")
        user = resp.json()
        email = str(user.get("email") or "")
        set_integration("flowsint", {"access_token": token, "email": email, "sketch_id": settings.flowsint_sketch_id})
        return {"connected": True, "email": email, "sketch_id": settings.flowsint_sketch_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Flowsint bridge error: {exc}")


@app.post("/api/integrations/flowsint/login")
async def flowsint_integration_login(payload: dict) -> dict:
    email = str(payload.get("email", "")).strip()
    password = str(payload.get("password", ""))
    if not email or not password:
        raise HTTPException(status_code=400, detail="Email and password are required")
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                f"{settings.flowsint_base_url.rstrip('/')}/api/auth/token",
                data={"username": email, "password": password},
            )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Flowsint login failed")
        body = resp.json()
        token = body.get("access_token")
        if not token:
            raise HTTPException(status_code=502, detail="Flowsint did not return an access token")
        set_integration("flowsint", {"access_token": token, "email": email, "sketch_id": settings.flowsint_sketch_id})
        return {"connected": True, "email": email, "sketch_id": settings.flowsint_sketch_id}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Flowsint connection error: {exc}")


@app.delete("/api/integrations/flowsint", status_code=204)
def flowsint_integration_logout() -> None:
    delete_integration("flowsint")


@app.get("/api/integrations/flowsint/enrichers")
async def flowsint_enrichers() -> list[dict]:
    token = _flowsint_token()
    if not token:
        raise HTTPException(status_code=401, detail="Connect Flowsint first")
    headers = {"Authorization": f"Bearer {token}"}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{settings.flowsint_base_url.rstrip('/')}/api/enrichers", headers=headers)
        if resp.status_code == 401:
            raise HTTPException(status_code=401, detail="Flowsint session expired")
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, list) else []
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Unable to list Flowsint enrichers: {exc}")
