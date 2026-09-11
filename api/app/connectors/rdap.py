import time
import httpx

from app.config import settings
from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


class RDAPConnector:
    name = "RDAP"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if not settings.enable_rdap or kind not in {"domain", "ip"}:
            return ConnectorResult(run=SourceRun(
                name=self.name, status="skipped", message="Domain/IP only"
            ))
        path = "domain" if kind == "domain" else "ip"
        url = f"https://rdap.org/{path}/{query.strip()}"
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                resp = await client.get(url, headers={"user-agent": "ExposureGraph/0.1"})
            elapsed = int((time.perf_counter() - started) * 1000)
            resp.raise_for_status()
            payload = resp.json()
            node_id = f"rdap:{kind}:{query.strip().lower()}"
            props = {
                "handle": payload.get("handle"),
                "name": payload.get("name"),
                "country": payload.get("country"),
                "status": payload.get("status") or [],
                "port43": payload.get("port43"),
                "events": payload.get("events") or [],
                "links": payload.get("links") or [],
            }
            return ConnectorResult(
                nodes=[GraphNode(
                    id=node_id,
                    type="rdap",
                    label=f"RDAP {query.strip()}",
                    properties=props,
                    source="RDAP",
                    confidence=1.0,
                    risk=10,
                )],
                edges=[GraphEdge(
                    id=f"{root_id}->{node_id}", source=root_id, target=node_id,
                    label="REGISTRATION_INFO", source_name="RDAP", confidence=1.0,
                )],
                run=SourceRun(name=self.name, status="ok", message="RDAP record found", duration_ms=elapsed),
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name,
                status="error",
                message=str(exc),
                duration_ms=elapsed,
            ))
