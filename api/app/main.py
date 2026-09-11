import asyncio
import uuid
import httpx
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.models import ConnectorStatus, GraphEdge, GraphNode, SearchRequest, SearchResponse
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
from app.connectors.trestle import TrestleConnector
from app.connectors.people_data_labs import PeopleDataLabsConnector
from app.connectors.github_email import GitHubEmailConnector
from app.connectors.holehe import HoleheConnector
from app.connectors.maigret_public import MaigretPublicConnector
from app.connectors.brave_search import BraveSearchConnector

app = FastAPI(title="ExposureGraph API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5180", "http://127.0.0.1:5180", "http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAIGRET = MaigretPublicConnector()
CONNECTORS = [
    HIBPConnector(), GravatarConnector(), GitHubEmailConnector(), HoleheConnector(), BraveSearchConnector(),
    RDAPConnector(), CRTSHConnector(), URLScanConnector(), VirusTotalConnector(), ShodanConnector(),
    TrestleConnector(), PeopleDataLabsConnector(), MAIGRET, FlowsintConnector(),
]


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
        ConnectorStatus(name="Have I Been Pwned", configured=bool((get_integration("email_osint") or {}).get("hibp_api_key") or settings.hibp_api_key), category="Breach intelligence", requires_key=True, note="Official breaches, pastes and stealer-log domains when the HIBP plan permits"),
        ConnectorStatus(name="Gravatar", configured=settings.enable_gravatar, category="Public identity", note="Exact-email public profile, username, display name and avatar"),
        ConnectorStatus(name="GitHub Public Email", configured=True, category="Public identity", note="Exact public commit-author email to GitHub account correlation"),
        ConnectorStatus(name="Holehe", configured=True, category="Account presence", note="Checks public account-existence signals without password recovery"),
        ConnectorStatus(name="Maigret Public Profiles", configured=True, category="Public profiles", note="Scans hundreds of public sites for discovered usernames; matches are candidates until corroborated"),
        ConnectorStatus(name="Brave Web Search", configured=bool((get_integration("email_osint") or {}).get("brave_api_key") or settings.brave_api_key), category="Public web index", requires_key=True, note="Exact-phrase web search across Brave's independent index"),
        ConnectorStatus(name="RDAP", configured=settings.enable_rdap, category="Infrastructure", note="Domain/IP registration data"),
        ConnectorStatus(name="Certificate Transparency", configured=settings.enable_crtsh, category="Infrastructure", note="crt.sh certificate names"),
        ConnectorStatus(name="urlscan.io", configured=settings.enable_urlscan, category="Public web scans", requires_key=False, note="Public historical URL/domain scans; API key increases quota"),
        ConnectorStatus(name="VirusTotal", configured=bool((get_integration("threat_intel") or {}).get("vt_api_key") or settings.vt_api_key), category="Reputation", requires_key=True, note="Domain/IP reputation and detections"),
        ConnectorStatus(name="Shodan", configured=True, category="Infrastructure", requires_key=False, note="Shodan InternetDB active; optional API key unlocks the full Shodan host API"),
        ConnectorStatus(name="Trestle Identity", configured=bool((get_integration("identity_osint") or {}).get("trestle_api_key")), category="Identity enrichment", requires_key=True, note="Authorized reverse-phone identity: owner, addresses and associated emails when coverage permits"),
        ConnectorStatus(name="People Data Labs", configured=bool((get_integration("identity_osint") or {}).get("pdl_api_key")), category="Identity enrichment", requires_key=True, note="Authorized person enrichment from email or phone with likelihood scoring"),
    ]




@app.get("/api/integrations/threat-intel")
def threat_intel_status() -> dict:
    saved = get_integration("threat_intel") or {}
    return {
        "virustotal": bool(saved.get("vt_api_key") or settings.vt_api_key),
        "shodan": bool(saved.get("shodan_api_key") or settings.shodan_api_key),
    }


@app.post("/api/integrations/threat-intel")
def configure_threat_intel(payload: dict) -> dict:
    current = get_integration("threat_intel") or {}
    vt = str(payload.get("vt_api_key") or current.get("vt_api_key") or "").strip()
    shodan = str(payload.get("shodan_api_key") or current.get("shodan_api_key") or "").strip()
    set_integration("threat_intel", {"vt_api_key": vt, "shodan_api_key": shodan})
    return {"virustotal": bool(vt), "shodan": bool(shodan)}


@app.get("/api/integrations/email-osint")
def email_osint_status() -> dict:
    saved = get_integration("email_osint") or {}
    return {
        "hibp": bool(saved.get("hibp_api_key") or settings.hibp_api_key),
        "brave": bool(saved.get("brave_api_key") or settings.brave_api_key),
    }


@app.post("/api/integrations/email-osint")
def configure_email_osint(payload: dict) -> dict:
    current = get_integration("email_osint") or {}
    hibp = str(payload.get("hibp_api_key") or current.get("hibp_api_key") or "").strip()
    brave = str(payload.get("brave_api_key") or current.get("brave_api_key") or "").strip()
    set_integration("email_osint", {"hibp_api_key": hibp, "brave_api_key": brave})
    return {"hibp": bool(hibp), "brave": bool(brave)}


@app.get("/api/integrations/identity-osint")
def identity_osint_status() -> dict:
    saved = get_integration("identity_osint") or {}
    return {"trestle": bool(saved.get("trestle_api_key")), "pdl": bool(saved.get("pdl_api_key"))}


@app.post("/api/integrations/identity-osint")
def configure_identity_osint(payload: dict) -> dict:
    current = get_integration("identity_osint") or {}
    trestle = str(payload.get("trestle_api_key") or current.get("trestle_api_key") or "").strip()
    pdl = str(payload.get("pdl_api_key") or current.get("pdl_api_key") or "").strip()
    set_integration("identity_osint", {"trestle_api_key": trestle, "pdl_api_key": pdl})
    return {"trestle": bool(trestle), "pdl": bool(pdl)}


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

    # Full e-mail scan: follow usernames that were discovered from exact/high-confidence
    # e-mail sources into public-profile enumeration. A bare e-mail local-part is scanned
    # only as a low-confidence candidate and is never presented as confirmed ownership.
    if kind == "email":
        username_candidates: dict[str, tuple[str, float, str]] = {}
        username_keys = ("username", "handle", "screen_name", "screenName", "login", "preferredUsername")
        for node in list(node_map.values()):
            if node.source == "Search input":
                continue
            values: list[str] = []
            if node.type.lower() == "username":
                values.append(node.label)
            for key in username_keys:
                value = node.properties.get(key)
                if isinstance(value, str) and value.strip():
                    values.append(value.strip())
            for value in values:
                candidate = value.strip().lstrip("@")
                if len(candidate) < 2 or " " in candidate or "@" in candidate:
                    continue
                score = float(node.confidence)
                existing = username_candidates.get(candidate.lower())
                if not existing or score > existing[1]:
                    username_candidates[candidate.lower()] = (node.id, score, node.source)

        local_part = query.split("@", 1)[0].strip().lstrip("@")
        if len(local_part) >= 3 and local_part.lower() not in username_candidates:
            derived_id = f"derived:username:{local_part.lower()}"
            node_map[derived_id] = GraphNode(
                id=derived_id,
                type="username",
                label=local_part,
                properties={
                    "username": local_part,
                    "evidence_level": "candidate",
                    "match_reason": "Derived from the email local-part only; not proof of ownership",
                },
                source="Email local-part candidate",
                confidence=0.40,
                risk=0,
            )
            edge_map[f"{root_id}->{derived_id}"] = GraphEdge(
                id=f"{root_id}->{derived_id}",
                source=root_id,
                target=derived_id,
                label="POSSIBLE_USERNAME",
                source_name="Derived candidate",
                confidence=0.40,
            )
            username_candidates[local_part.lower()] = (derived_id, 0.40, "Email local-part candidate")

        known_names: set[str] = set()
        for known_node in node_map.values():
            if known_node.confidence < 0.85:
                continue
            for key in ("display_name", "displayName", "full_name", "fullName", "fullname", "name"):
                value = known_node.properties.get(key)
                if isinstance(value, str) and len(value.strip()) >= 6:
                    known_names.add(" ".join(value.lower().split()))
            if known_node.type.lower() in {"person", "individual"} and len(known_node.label.strip()) >= 6:
                known_names.add(" ".join(known_node.label.lower().split()))

        ranked_candidates = sorted(username_candidates.items(), key=lambda item: item[1][1], reverse=True)[:3]
        expansion_results = await asyncio.gather(
            *(MAIGRET.run(username_key, "username", data[0]) for username_key, data in ranked_candidates),
            return_exceptions=True,
        )
        for (username_key, (parent_id, evidence_confidence, evidence_source)), expanded in zip(ranked_candidates, expansion_results):
            if isinstance(expanded, Exception):
                warnings.append(f"Maigret {username_key}: {expanded}")
                continue
            if expanded.run:
                expanded.run.message = f"{username_key}: {expanded.run.message}"
                source_runs.append(expanded.run)
            base_profile_confidence = 0.58 if evidence_confidence >= 0.80 else 0.42
            for node in expanded.nodes:
                extracted_name = ""
                for key in ("display_name", "displayName", "full_name", "fullName", "fullname", "name"):
                    value = node.properties.get(key)
                    if isinstance(value, str) and value.strip():
                        extracted_name = " ".join(value.lower().split())
                        break
                name_corroborated = bool(extracted_name and extracted_name in known_names)
                node.confidence = 0.84 if name_corroborated else base_profile_confidence
                node.properties["evidence_level"] = "probable" if name_corroborated else "candidate"
                node.properties["derived_from_username"] = username_key
                node.properties["username_evidence_source"] = evidence_source
                node.properties["match_reason"] = (
                    "Username match plus a public display-name match from an independent email-linked source"
                    if name_corroborated
                    else "Same public username found on this site; this alone does not prove account ownership"
                )
                if node.id not in node_map:
                    node_map[node.id] = node
            for edge in expanded.edges:
                edge.confidence = base_profile_confidence
                if edge.id not in edge_map:
                    edge_map[edge.id] = edge

    identity_types = {"person", "individual", "email", "address", "socialaccount", "username"}

    def evidence_key(node: GraphNode) -> tuple[str, str]:
        node_type = node.type.lower()
        if node_type == "socialaccount":
            raw_url = node.properties.get("profile_url") or node.properties.get("profileUrl") or node.properties.get("url")
            if raw_url:
                return node_type, str(raw_url).strip().lower().rstrip("/")
        return node_type, " ".join(node.label.lower().split()).rstrip("/")

    evidence: dict[tuple[str, str], set[str]] = {}
    max_evidence_confidence: dict[tuple[str, str], float] = {}
    for node in node_map.values():
        if node.type.lower() not in identity_types or node.source == "Search input":
            continue
        key = evidence_key(node)
        evidence.setdefault(key, set()).add(node.source)
        max_evidence_confidence[key] = max(max_evidence_confidence.get(key, 0.0), float(node.confidence))
    for node in node_map.values():
        key = evidence_key(node)
        sources = sorted(evidence.get(key, set()))
        if len(sources) >= 2:
            node.properties["corroborated"] = True
            node.properties["corroborated_sources"] = sources
            strong_anchor = max_evidence_confidence.get(key, 0.0) >= 0.95
            node.properties["evidence_level"] = "confirmed" if strong_anchor else "probable"
            target_confidence = 0.96 if strong_anchor else min(0.91, 0.75 + 0.08 * len(sources))
            node.confidence = max(node.confidence, target_confidence)

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
