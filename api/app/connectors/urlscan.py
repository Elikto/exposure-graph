import time
import urllib.parse
import httpx

from app.config import settings
from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


class URLScanConnector:
    name = "urlscan.io"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if not settings.enable_urlscan:
            return ConnectorResult(run=SourceRun(name=self.name, status="disabled", message="Disabled"))
        if kind != "domain":
            return ConnectorResult(run=SourceRun(name=self.name, status="skipped", message="Domain only"))

        q = urllib.parse.quote(f"domain:{query}", safe="")
        url = f"https://urlscan.io/api/v1/search/?q={q}&size=25"
        headers = {"User-Agent": "ExposureGraph/0.2"}
        if settings.urlscan_api_key:
            headers["API-Key"] = settings.urlscan_api_key
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                resp = await client.get(url, headers=headers)
            if resp.status_code == 429:
                return ConnectorResult(run=SourceRun(name=self.name, status="error", message="Rate limited"))
            resp.raise_for_status()
            payload = resp.json()
            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            for item in payload.get("results", [])[:25]:
                page = item.get("page") or {}
                task = item.get("task") or {}
                scan_id = str(item.get("_id") or task.get("uuid") or "")
                page_url = str(page.get("url") or task.get("url") or query)
                if not scan_id:
                    continue
                node_id = f"urlscan:{scan_id}"
                nodes.append(GraphNode(
                    id=node_id,
                    type="web_scan",
                    label=page_url,
                    properties={"domain": page.get("domain"), "ip": page.get("ip"), "country": page.get("country"), "scanId": scan_id, "scanTime": task.get("time")},
                    source="urlscan.io",
                    confidence=0.95,
                    risk=10,
                ))
                edges.append(GraphEdge(
                    id=f"{root_id}->{node_id}",
                    source=root_id,
                    target=node_id,
                    label="HAS_PUBLIC_SCAN",
                    source_name="urlscan.io",
                    confidence=0.95,
                ))
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(
                nodes=nodes,
                edges=edges,
                run=SourceRun(name=self.name, status="ok", message=f"{len(nodes)} public scan(s)", duration_ms=elapsed),
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(name=self.name, status="error", message=str(exc), duration_ms=elapsed))
