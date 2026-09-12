import asyncio
import hashlib
import logging
import time
from pathlib import Path

from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


SOCIAL_PRIORITY = (
    "Facebook", "Instagram", "Twitter", "TikTok", "YouTube", "LinkedIn",
    "GitHub", "Reddit", "Twitch", "Pinterest", "Telegram", "Threads",
    "Snapchat", "Discord",
)
GENERAL_PRIORITY_COUNT = 40


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

            all_sites = MaigretDatabase().load_from_path(str(db_path)).ranked_sites_dict(
                top=9999, disabled=False, id_type="username"
            )
            selected_sites = {}
            by_lower = {name.lower(): (name, site) for name, site in all_sites.items()}
            for wanted in SOCIAL_PRIORITY:
                match = by_lower.get(wanted.lower())
                if match:
                    selected_sites[match[0]] = match[1]

            for name, site in list(all_sites.items())[:GENERAL_PRIORITY_COUNT]:
                selected_sites.setdefault(name, site)

            logger = logging.getLogger("exposuregraph.maigret.fast")
            logger.setLevel(logging.CRITICAL)
            logger.disabled = True
            results = await asyncio.wait_for(
                scan_username(
                    username=username,
                    site_dict=dict(selected_sites),
                    logger=logger,
                    timeout=1.5,
                    is_parsing_enabled=True,
                    is_enrich_enabled=False,
                    max_connections=70,
                    no_progressbar=True,
                    retries=0,
                    dns_resolver="threaded",
                ),
                timeout=9,
            )

            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            social_found = 0
            for site_name, item in results.items():
                status = item.get("status")
                if not (status and getattr(status, "is_found", lambda: False)()):
                    continue

                url = str(item.get("url_user") or getattr(status, "site_url_user", "") or "").strip()
                if not url:
                    continue
                site_obj = selected_sites.get(site_name)
                tags = list(getattr(site_obj, "tags", []) or [])
                is_social = "social" in {str(tag).lower() for tag in tags} or site_name in SOCIAL_PRIORITY
                if is_social:
                    social_found += 1
                node_id = f"maigret-fast:{_hid(url.lower())}"
                nodes.append(GraphNode(
                    id=node_id,
                    type="socialaccount",
                    label=str(site_name),
                    properties={
                        "platform": str(site_name),
                        "username": username,
                        "profile_url": url,
                        "social_network": is_social,
                        "site_category": "social" if is_social else "public_profile",
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
                    name=self.name,
                    status="ok",
                    message=(
                        f"{len(selected_sites)} priority/social sites checked, "
                        f"{len(nodes)} candidate profile(s), {social_found} social network(s)"
                    ),
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
