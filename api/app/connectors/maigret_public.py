import asyncio
import hashlib
import logging
import time
from pathlib import Path

from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


def _hid(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


class MaigretPublicConnector:
    name = "Maigret Public Profiles"

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
            db = MaigretDatabase().load_from_path(str(db_path))
            sites = db.ranked_sites_dict(
                top=150,
                disabled=False,
                id_type="username",
            )
            logger = logging.getLogger("exposuregraph.maigret")
            logger.setLevel(logging.CRITICAL)
            logger.disabled = True
            results = await asyncio.wait_for(
                scan_username(
                    username=username,
                    site_dict=dict(sites),
                    logger=logger,
                    timeout=2,
                    is_parsing_enabled=True,
                    is_enrich_enabled=True,
                    max_connections=80,
                    no_progressbar=True,
                    retries=0,
                    dns_resolver="threaded",
                ),
                timeout=20,
            )
            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            for site_name, item in results.items():
                status = item.get("status")
                is_found = bool(status and getattr(status, "is_found", lambda: False)())
                if not is_found:
                    continue
                url = str(item.get("url_user") or getattr(status, "site_url_user", "") or "").strip()
                if not url:
                    continue
                ids = {}
                try:
                    ids = dict((status.json() or {}).get("ids") or {})
                except Exception:
                    ids = {}
                node_id = f"maigret:{_hid(url.lower())}"
                props = {
                    "platform": str(site_name),
                    "username": username,
                    "profile_url": url,
                    "evidence_level": "candidate",
                    "match_reason": "Exact public username match; ownership requires corroboration",
                    **ids,
                }
                nodes.append(GraphNode(
                    id=node_id,
                    type="socialaccount",
                    label=str(site_name),
                    properties={k: v for k, v in props.items() if v not in (None, "", [], {})},
                    source=self.name,
                    confidence=0.56,
                    risk=5,
                ))
                edges.append(GraphEdge(
                    id=f"{root_id}->{node_id}",
                    source=root_id,
                    target=node_id,
                    label="USERNAME_MATCH_ON",
                    source_name=self.name,
                    confidence=0.56,
                ))

            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(
                nodes=nodes,
                edges=edges,
                run=SourceRun(
                    name=self.name,
                    status="ok",
                    message=f"{len(sites)} priority public sites checked, {len(nodes)} claimed profile(s)",
                    duration_ms=elapsed,
                ),
            )
        except asyncio.TimeoutError:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status="error", message="Maigret priority scan timed out", duration_ms=elapsed
            ))
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status="error", message=str(exc), duration_ms=elapsed
            ))
