import time
import httpx

from app.config import settings
from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


class ShodanConnector:
    name = "Shodan"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if kind != "ip":
            return ConnectorResult(run=SourceRun(name=self.name, status="skipped", message="IP only"))
        if not settings.shodan_api_key:
            return ConnectorResult(run=SourceRun(name=self.name, status="needs_key", message="SHODAN_API_KEY required"))
        url = f"https://api.shodan.io/shodan/host/{query}"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, params={"key": settings.shodan_api_key, "minify": "true"})
            resp.raise_for_status()
            data = resp.json()
            ports = data.get("ports") or []
            node_id = f"shodan:ip:{query}"
            node = GraphNode(
                id=node_id,
                type="internet_exposure",
                label=f"Shodan: {query}",
                properties={"ports": ports, "hostnames": data.get("hostnames") or [], "org": data.get("org"), "isp": data.get("isp"), "asn": data.get("asn"), "country": data.get("country_name")},
                source="Shodan",
                confidence=1.0,
                risk=min(100, 10 + len(ports) * 4),
            )
            edge = GraphEdge(
                id=f"{root_id}->{node_id}",
                source=root_id,
                target=node_id,
                label="EXPOSED_ON_INTERNET",
                source_name="Shodan",
                confidence=1.0,
            )
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(nodes=[node], edges=[edge], run=SourceRun(name=self.name, status="ok", message=f"{len(ports)} open port(s)", duration_ms=elapsed))
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(name=self.name, status="error", message=str(exc), duration_ms=elapsed))
