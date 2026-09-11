import time
import httpx

from app.config import settings
from app.models import GraphEdge, GraphNode, SourceRun
from app.storage import get_integration
from .base import ConnectorResult


class FlowsintConnector:
    name = "Flowsint"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        integration = get_integration("flowsint") or {}
        token = integration.get("access_token") or settings.flowsint_api_token
        sketch_id = integration.get("sketch_id") or settings.flowsint_sketch_id
        if not token or not sketch_id:
            return ConnectorResult(run=SourceRun(
                name=self.name,
                status="needs_key",
                message="Connect Flowsint locally in ExposureGraph",
            ))
        url = f"{settings.flowsint_base_url.rstrip('/')}/api/sketches/{sketch_id}/graph"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                resp = await client.get(url, headers=headers)
            resp.raise_for_status()
            data = resp.json()
            raw_nodes = data.get("nodes", data.get("nds", [])) if isinstance(data, dict) else []
            raw_edges = data.get("edges", data.get("links", data.get("rls", []))) if isinstance(data, dict) else []
            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            id_map: set[str] = set()
            query_l = query.strip().lower()
            matched_ids: list[str] = []

            for item in raw_nodes[:1500]:
                node_id = str(item.get("id") or item.get("elementId") or "")
                if not node_id:
                    continue
                props = item.get("nodeProperties") or item.get("properties") or {}
                label = str(item.get("nodeLabel") or item.get("label") or node_id)
                node_type = str(item.get("nodeType") or item.get("type") or "flowsint")
                haystack = f"{label} {props}".lower()
                if query_l in haystack:
                    matched_ids.append(node_id)
                nodes.append(GraphNode(
                    id=f"flowsint:{node_id}",
                    type=node_type.lower(),
                    label=label,
                    properties={**props, "flowsintNodeId": node_id},
                    source="Flowsint",
                    confidence=0.9,
                    risk=20,
                ))
                id_map.add(node_id)
            for item in raw_edges[:2500]:
                source = item.get("source") or item.get("from") or item.get("from_id")
                target = item.get("target") or item.get("to") or item.get("to_id")
                if isinstance(source, dict):
                    source = source.get("id")
                if isinstance(target, dict):
                    target = target.get("id")
                if not source or not target or str(source) not in id_map or str(target) not in id_map:
                    continue
                edge_id = str(item.get("id") or f"{source}->{target}")
                edges.append(GraphEdge(
                    id=f"flowsint-edge:{edge_id}",
                    source=f"flowsint:{source}",
                    target=f"flowsint:{target}",
                    label=str(item.get("label") or item.get("type") or "RELATED_TO"),
                    properties=item.get("properties") or {},
                    source_name="Flowsint",
                    confidence=0.9,
                ))

            if matched_ids:
                adjacency: dict[str, set[str]] = {node_id: set() for node_id in id_map}
                for edge in raw_edges[:2500]:
                    source = edge.get("source") or edge.get("from") or edge.get("from_id")
                    target = edge.get("target") or edge.get("to") or edge.get("to_id")
                    if isinstance(source, dict): source = source.get("id")
                    if isinstance(target, dict): target = target.get("id")
                    source, target = str(source or ""), str(target or "")
                    if source in adjacency and target in adjacency:
                        adjacency[source].add(target)
                        adjacency[target].add(source)
                keep = set(matched_ids)
                frontier = set(matched_ids)
                for _ in range(2):
                    frontier = {n for cur in frontier for n in adjacency.get(cur, set())} - keep
                    keep |= frontier
                nodes = [n for n in nodes if n.id.removeprefix("flowsint:") in keep]
                edges = [e for e in edges if e.source.removeprefix("flowsint:") in keep and e.target.removeprefix("flowsint:") in keep]
            else:
                nodes = []
                edges = []

            for matched in matched_ids[:20]:
                edges.append(GraphEdge(
                    id=f"{root_id}->flowsint:{matched}",
                    source=root_id,
                    target=f"flowsint:{matched}",
                    label="MATCHES_FLOWSINT_NODE",
                    source_name="Flowsint",
                    confidence=1.0,
                ))
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(
                nodes=nodes,
                edges=edges,
                run=SourceRun(
                    name=self.name,
                    status="ok",
                    message=f"{len(nodes)} nodes, {len(matched_ids)} direct match(es)",
                    duration_ms=elapsed,
                ),
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name,
                status="error",
                message=str(exc),
                duration_ms=elapsed,
            ))
