import asyncio
import time
import uuid
import httpx

from app.config import settings
from app.models import GraphEdge, GraphNode, SourceRun
from app.storage import get_integration
from .base import ConnectorResult


def _phone_key(value: object) -> str:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    if digits.startswith("00"):
        digits = digits[2:]
    return digits[-9:] if len(digits) >= 9 else digits


def _flowsint_parts(data: object) -> tuple[list[dict], list[dict]]:
    if not isinstance(data, dict):
        return [], []
    nodes = data.get("nodes", data.get("nds", [])) or []
    edges = data.get("edges", data.get("links", data.get("rls", []))) or []
    return nodes, edges


def _node_id(item: dict) -> str:
    return str(item.get("id") or item.get("elementId") or "")


def _node_type(item: dict) -> str:
    return str(item.get("nodeType") or item.get("type") or "").lower()


def _node_props(item: dict) -> dict:
    props = item.get("nodeProperties") or item.get("properties") or {}
    return props if isinstance(props, dict) else {}


def _node_label(item: dict) -> str:
    return str(item.get("nodeLabel") or item.get("label") or _node_id(item))


def _edge_ends(item: dict) -> tuple[str, str]:
    source = item.get("source") or item.get("from") or item.get("from_id")
    target = item.get("target") or item.get("to") or item.get("to_id")
    if isinstance(source, dict):
        source = source.get("id")
    if isinstance(target, dict):
        target = target.get("id")
    return str(source or ""), str(target or "")


def _input_type(enricher: dict) -> str:
    inputs = enricher.get("inputs") or {}
    return str(inputs.get("type") if isinstance(inputs, dict) else "").lower()


class FlowsintConnector:
    name = "Flowsint"

    async def _refresh(self, client: httpx.AsyncClient, url: str, headers: dict, seconds: int = 4):
        data: object = {}
        for _ in range(seconds):
            await asyncio.sleep(1.0)
            refreshed = await client.get(url, headers=headers)
            if refreshed.status_code == 200:
                data = refreshed.json()
        return _flowsint_parts(data)

    async def _ensure_node(self, client: httpx.AsyncClient, sketch_id: str, headers: dict, node_type: str, label: str, props: dict) -> str:
        payload = {
            "id": f"exposuregraph-{uuid.uuid4()}",
            "nodeType": node_type,
            "nodeLabel": label,
            "nodeProperties": props,
            "nodeMetadata": {},
            "x": 100.0,
            "y": 100.0,
            "nodeSize": 4,
            "nodeShape": "circle",
            "nodeColor": None,
            "nodeFlag": None,
            "nodeIcon": None,
            "nodeImage": None,
        }
        created = await client.post(
            f"{settings.flowsint_base_url.rstrip('/')}/api/sketches/{sketch_id}/nodes/add",
            headers=headers,
            json=payload,
        )
        created.raise_for_status()
        body = created.json()
        node = body.get("node", body) if isinstance(body, dict) else {}
        return str(node.get("id") or "")

    async def _launch(self, client: httpx.AsyncClient, headers: dict, sketch_id: str, enricher: str, node_ids: list[str]) -> bool:
        if not node_ids:
            return False
        resp = await client.post(
            f"{settings.flowsint_base_url.rstrip('/')}/api/enrichers/{enricher}/launch",
            headers=headers,
            json={"node_ids": node_ids[:12], "sketch_id": sketch_id},
        )
        return resp.status_code < 400

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        integration = get_integration("flowsint") or {}
        token = integration.get("access_token") or settings.flowsint_api_token
        sketch_id = integration.get("sketch_id") or settings.flowsint_sketch_id
        if not token or not sketch_id:
            return ConnectorResult(run=SourceRun(name=self.name, status="needs_key", message="Connect Flowsint locally in ExposureGraph"))

        url = f"{settings.flowsint_base_url.rstrip('/')}/api/sketches/{sketch_id}/graph"
        headers = {"Authorization": f"Bearer {token}"}
        launched: list[str] = []
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                resp = await client.get(url, headers=headers)
                resp.raise_for_status()
                raw_nodes, raw_edges = _flowsint_parts(resp.json())

                if kind == "phone":
                    key = _phone_key(query)
                    phone_ids = [
                        _node_id(n) for n in raw_nodes
                        if _node_type(n) == "phone" and key and key in {_phone_key(_node_label(n)), _phone_key(_node_props(n).get("number"))}
                    ]
                    phone_ids = [x for x in phone_ids if x]
                    if not phone_ids:
                        node_id = await self._ensure_node(client, sketch_id, headers, "phone", query, {"number": query})
                        phone_ids = [node_id] if node_id else []
                    for name in ("phone_to_device_hudsonrock", "phone_to_carrier"):
                        if await self._launch(client, headers, sketch_id, name, phone_ids):
                            launched.append(name)
                    if launched:
                        raw_nodes, raw_edges = await self._refresh(client, url, headers, 5)

                if kind == "email":
                    q = query.strip().lower()
                    email_ids = []
                    for node in raw_nodes:
                        if _node_type(node) != "email":
                            continue
                        props = _node_props(node)
                        values = {_node_label(node).strip().lower(), str(props.get("email") or "").strip().lower(), str(props.get("value") or "").strip().lower()}
                        if q in values:
                            node_id = _node_id(node)
                            if node_id:
                                email_ids.append(node_id)
                    if not email_ids:
                        node_id = await self._ensure_node(client, sketch_id, headers, "email", query, {"email": query})
                        email_ids = [node_id] if node_id else []

                    enricher_resp = await client.get(f"{settings.flowsint_base_url.rstrip('/')}/api/enrichers", headers=headers)
                    enrichers = enricher_resp.json() if enricher_resp.status_code == 200 and isinstance(enricher_resp.json(), list) else []
                    safe_email_markers = ("email_to_username", "email_to_gravatar", "email_to_breaches", "holehe")
                    email_enrichers = [
                        str(e.get("name")) for e in enrichers
                        if isinstance(e, dict) and _input_type(e) == "email" and any(marker in str(e.get("name", "")).lower() for marker in safe_email_markers)
                    ]
                    for name in email_enrichers:
                        if await self._launch(client, headers, sketch_id, name, email_ids):
                            launched.append(name)
                    if email_enrichers:
                        raw_nodes, raw_edges = await self._refresh(client, url, headers, 4)

                    adjacent = set()
                    for edge in raw_edges:
                        source, target = _edge_ends(edge)
                        if source in email_ids:
                            adjacent.add(target)
                        if target in email_ids:
                            adjacent.add(source)
                    username_ids = [
                        _node_id(n) for n in raw_nodes
                        if _node_type(n) == "username" and _node_id(n) in adjacent
                    ]
                    username_enrichers = [
                        str(e.get("name")) for e in enrichers
                        if isinstance(e, dict) and _input_type(e) == "username" and any(marker in str(e.get("name", "")).lower() for marker in ("maigret", "sherlock"))
                    ]
                    for name in username_enrichers:
                        if await self._launch(client, headers, sketch_id, name, username_ids):
                            launched.append(name)
                    if username_ids and username_enrichers:
                        raw_nodes, raw_edges = await self._refresh(client, url, headers, 5)

            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            id_map: set[str] = set()
            query_l = query.strip().lower()
            matched_ids: list[str] = []

            for item in raw_nodes[:1800]:
                node_id = _node_id(item)
                if not node_id:
                    continue
                props = _node_props(item)
                label = _node_label(item)
                node_type = _node_type(item) or "flowsint"
                haystack = f"{label} {props}".lower()
                if kind == "phone":
                    if node_type == "phone" and _phone_key(query) in {_phone_key(label), _phone_key(props.get("number"))}:
                        matched_ids.append(node_id)
                elif kind == "email":
                    email_values = {label.strip().lower(), str(props.get("email") or "").strip().lower(), str(props.get("value") or "").strip().lower()}
                    if node_type == "email" and query_l in email_values:
                        matched_ids.append(node_id)
                elif query_l in haystack:
                    matched_ids.append(node_id)
                nodes.append(GraphNode(
                    id=f"flowsint:{node_id}", type=node_type, label=label,
                    properties={**props, "flowsintNodeId": node_id}, source="Flowsint",
                    confidence=0.9, risk=20,
                ))
                id_map.add(node_id)

            for item in raw_edges[:3000]:
                source, target = _edge_ends(item)
                if not source or not target or source not in id_map or target not in id_map:
                    continue
                edge_id = str(item.get("id") or f"{source}->{target}")
                edges.append(GraphEdge(
                    id=f"flowsint-edge:{edge_id}", source=f"flowsint:{source}", target=f"flowsint:{target}",
                    label=str(item.get("label") or item.get("type") or "RELATED_TO"),
                    properties=item.get("properties") or {}, source_name="Flowsint", confidence=0.9,
                ))

            if matched_ids:
                adjacency: dict[str, set[str]] = {node_id: set() for node_id in id_map}
                for edge in raw_edges[:3000]:
                    source, target = _edge_ends(edge)
                    if source in adjacency and target in adjacency:
                        adjacency[source].add(target)
                        adjacency[target].add(source)
                keep = set(matched_ids)
                frontier = set(matched_ids)
                hops = 3 if kind == "email" else 2
                for _ in range(hops):
                    frontier = {n for current in frontier for n in adjacency.get(current, set())} - keep
                    keep |= frontier
                nodes = [n for n in nodes if n.id.removeprefix("flowsint:") in keep]
                edges = [e for e in edges if e.source.removeprefix("flowsint:") in keep and e.target.removeprefix("flowsint:") in keep]
            else:
                nodes = []
                edges = []

            for matched in matched_ids[:20]:
                edges.append(GraphEdge(
                    id=f"{root_id}->flowsint:{matched}", source=root_id, target=f"flowsint:{matched}",
                    label="MATCHES_FLOWSINT_NODE", source_name="Flowsint", confidence=1.0,
                ))

            elapsed = int((time.perf_counter() - started) * 1000)
            suffix = f"; launched {len(launched)} enricher(s)" if launched else ""
            return ConnectorResult(
                nodes=nodes, edges=edges,
                run=SourceRun(name=self.name, status="ok", message=f"{len(nodes)} nodes, {len(matched_ids)} direct match(es){suffix}", duration_ms=elapsed),
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(name=self.name, status="error", message=str(exc), duration_ms=elapsed))
