import time
import httpx

from app.config import settings
from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


class CRTSHConnector:
    name = "Certificate Transparency"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if not settings.enable_crtsh or kind != "domain":
            return ConnectorResult(run=SourceRun(
                name=self.name, status="skipped", message="Domain only"
            ))
        try:
            async with httpx.AsyncClient(timeout=25, follow_redirects=True) as client:
                resp = await client.get(
                    "https://crt.sh/",
                    params={"q": f"%.{query.strip()}", "output": "json"},
                    headers={"user-agent": "ExposureGraph/0.1"},
                )
            resp.raise_for_status()
            rows = resp.json()
            names: set[str] = set()
            for row in rows[:1000]:
                for name in str(row.get("name_value", "")).splitlines():
                    clean = name.strip().lower().removeprefix("*.")
                    if clean.endswith(query.strip().lower()):
                        names.add(clean)
            nodes = []
            edges = []
            for name in sorted(names)[:250]:
                node_id = f"domain:{name}"
                nodes.append(GraphNode(
                    id=node_id, type="domain", label=name,
                    properties={"domain": name}, source="crt.sh", confidence=0.95, risk=5,
                ))
                edges.append(GraphEdge(
                    id=f"{root_id}->{node_id}", source=root_id, target=node_id,
                    label="CERTIFICATE_NAME", source_name="crt.sh", confidence=0.95,
                ))
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(
                nodes=nodes, edges=edges,
                run=SourceRun(
                    name=self.name, status="ok", message=f"{len(nodes)} names", duration_ms=elapsed
                ),
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status="error", message=str(exc), duration_ms=elapsed
            ))
