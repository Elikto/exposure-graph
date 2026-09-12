import asyncio
import hashlib
import logging
import time
from pathlib import Path

from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


def _hid(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


class MaigretFastConnector:
    name = "Maigret Fast Profiles"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if kind != "username":
            return ConnectorResult(run=SourceRun(name=self.name, status="skipped", message="Username only"))
        username = query.strip().lstrip("@")
        if len(username) < 2:
            return ConnectorResult(run=SourceRun(name=self.name, status="skipped", message="Username too short"))
        try:
            import maigret as maigret_package
            from maigret.checking import maigret as scan_username
            from maigret.sites import MaigretDatabase

            db_path = Path(maigret_package.__file__).parent / "resources" / "data.json"
            if not db_path.exists():
                raise RuntimeError("Maigret site database unavailable")
            sites = MaigretDatabase().load_from_path(str(db_path)).ranked_sites_dict(
                top=40, disabled=False, id_type="username"
            )
            logger = logging.getLogger("exposuregraph.maigret.fast")
            logger.setLevel(logging.CRITICAL)
            logger.disabled = True
            results = await asyncio.wait_for(
                scan_username(
                    username=username,
                    site_dict=dict(sites),
                    logger=logger,
                    timeout=1.5,
                    is_parsing_enabled=True,
                    is_enrich_enabled=False,
                    max_connections=60,
                    no_progressbar=True,
                    retries=0,
                    dns_resolver="threaded",
                ),
                timeout=8,
            )
            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            for site_name, item in results.items():
                status = item.get("status")
                if not (status and getattr(status, "is_found", lambda: False)()):
                    continue
                url = str(item.get("url_user") or getattr(status, "site_url_user", "") or "").strip()
                if not url:
                    continue
                node_id = f"maigret-fast:{_hid(url.lower())}"
                nodes.append(GraphNode(
                    id=node_id,
                    type="socialaccount",
                    label=str(site_name),
                    properties={
                        "platform": str(site_name),
                        "username": username,
                        "profile_url": url,
                        "evidence_level": "candidate",
                        "match_reason": "Fast public username match; ownership requires corroboration",
                    },
                    source=self.name,
                    confidence=0.52,
                    risk=4,
                ))
                edges.append(GraphEdge(
                    id=f"{root_id}->{node_id}", source=root_id, target=node_id,
                    label="USERNAME_MATCH_ON", source_name=self.name, confidence=0.52,
                ))
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(
                nodes=nodes,
                edges=edges,
                run=SourceRun(
                    name=self.name, status="ok",
                    message=f"{len(sites)} priority sites checked, {len(nodes)} candidate profile(s)",
                    duration_ms=elapsed,
                ),
            )
        except asyncio.TimeoutError:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status="error", message="Fast profile scan timed out", duration_ms=elapsed
            ))
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status="error", message=str(exc), duration_ms=elapsed
            ))
