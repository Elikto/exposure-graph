import hashlib
import time
from urllib.parse import urlparse

import httpx

from app.config import settings
from app.models import GraphEdge, GraphNode, SourceRun
from app.storage import get_integration
from .base import ConnectorResult


def _hid(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _domain(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().removeprefix("www.")
    except Exception:
        return ""


class BraveSearchConnector:
    name = "Brave Web Search"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if kind not in {"email", "username", "person"}:
            return ConnectorResult(run=SourceRun(name=self.name, status="skipped", message="Email, username or person only"))
        integration = get_integration("email_osint") or {}
        api_key = str(integration.get("brave_api_key") or getattr(settings, "brave_api_key", "") or "").strip()
        if not api_key:
            return ConnectorResult(run=SourceRun(
                name=self.name, status="needs_key", message="BRAVE_SEARCH_API_KEY required"
            ))
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                resp = await client.get(
                    "https://api.search.brave.com/res/v1/web/search",
                    headers={
                        "Accept": "application/json",
                        "X-Subscription-Token": api_key,
                        "User-Agent": "ExposureGraph/0.5",
                    },
                    params={
                        "q": f'"{query.strip()}"',
                        "count": 20,
                        "safesearch": "moderate",
                        "spellcheck": "false",
                    },
                )
            resp.raise_for_status()
            items = (((resp.json() or {}).get("web") or {}).get("results") or [])[:20]
            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            query_l = query.strip().lower()
            for item in items:
                url = str(item.get("url") or "").strip()
                if not url:
                    continue
                title = str(item.get("title") or "").strip()
                description = str(item.get("description") or "").strip()
                haystack = f"{title} {description} {url}".lower()
                exact = query_l in haystack
                confidence = 0.82 if exact else 0.66
                level = "probable" if exact else "candidate"
                node_id = f"brave:{_hid(url.lower())}"
                domain = _domain(url)
                props = {
                    "platform": domain or title or "Web result",
                    "domain": domain,
                    "profile_url": url,
                    "title": title,
                    "snippet": description,
                    "age": item.get("age"),
                    "evidence_level": level,
                    "match_reason": "Exact identifier appears in indexed result" if exact else "Returned for exact-phrase web search",
                }
                nodes.append(GraphNode(
                    id=node_id,
                    type="website",
                    label=title or domain or url,
                    properties={k: v for k, v in props.items() if v not in (None, "")},
                    source=self.name,
                    confidence=confidence,
                    risk=5,
                ))
                edges.append(GraphEdge(
                    id=f"{root_id}->{node_id}",
                    source=root_id,
                    target=node_id,
                    label="MENTIONED_ON_WEB",
                    source_name=self.name,
                    confidence=confidence,
                ))

            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(
                nodes=nodes,
                edges=edges,
                run=SourceRun(
                    name=self.name,
                    status="ok",
                    message=f"{len(nodes)} indexed web result(s)",
                    duration_ms=elapsed,
                ),
            )
        except httpx.HTTPStatusError as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name,
                status="error",
                message=f"Brave HTTP {exc.response.status_code}",
                duration_ms=elapsed,
            ))
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status="error", message=str(exc), duration_ms=elapsed
            ))
