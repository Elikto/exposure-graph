import time
import httpx

from app.config import settings
from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


class VirusTotalConnector:
    name = "VirusTotal"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if kind not in {"domain", "ip"}:
            return ConnectorResult(run=SourceRun(name=self.name, status="skipped", message="Domain/IP only"))
        if not settings.vt_api_key:
            return ConnectorResult(run=SourceRun(name=self.name, status="needs_key", message="VT_API_KEY required"))
        path = f"domains/{query}" if kind == "domain" else f"ip_addresses/{query}"
        url = f"https://www.virustotal.com/api/v3/{path}"
        headers = {"x-apikey": settings.vt_api_key, "User-Agent": "ExposureGraph/0.2"}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            attrs = (resp.json().get("data") or {}).get("attributes") or {}
            stats = attrs.get("last_analysis_stats") or {}
            suspicious = int(stats.get("suspicious") or 0)
            malicious = int(stats.get("malicious") or 0)
            risk = min(100, 10 + malicious * 15 + suspicious * 6)
            node_id = f"virustotal:{kind}:{query}"
            node = GraphNode(
                id=node_id,
                type="reputation",
                label=f"VirusTotal: {query}",
                properties={
                    "lastAnalysisStats": stats,
                    "reputation": attrs.get("reputation"),
                    "categories": attrs.get("categories") or {},
                    "registrar": attrs.get("registrar"),
                    "creationDate": attrs.get("creation_date"),
                },
                source="VirusTotal",
                confidence=1.0,
                risk=risk,
            )
            edge = GraphEdge(
                id=f"{root_id}->{node_id}",
                source=root_id,
                target=node_id,
                label="HAS_REPUTATION_REPORT",
                source_name="VirusTotal",
                confidence=1.0,
            )
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(nodes=[node], edges=[edge], run=SourceRun(name=self.name, status="ok", message="Report loaded", duration_ms=elapsed))
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(name=self.name, status="error", message=str(exc), duration_ms=elapsed))
