import hashlib
import time
import httpx

from app.config import settings
from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


class GravatarConnector:
    name = "Gravatar"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if not settings.enable_gravatar or kind != "email":
            return ConnectorResult(run=SourceRun(
                name=self.name, status="skipped", message="Email only"
            ))
        digest = hashlib.sha256(query.strip().lower().encode()).hexdigest()
        avatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404&s=256"
        try:
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                resp = await client.get(avatar_url)
            elapsed = int((time.perf_counter() - started) * 1000)
            if resp.status_code != 200:
                return ConnectorResult(run=SourceRun(
                    name=self.name, status="ok", message="No public avatar", duration_ms=elapsed
                ))
            node_id = f"gravatar:{digest}"
            return ConnectorResult(
                nodes=[GraphNode(
                    id=node_id,
                    type="gravatar",
                    label="Public Gravatar",
                    properties={"avatarUrl": avatar_url, "hash": digest},
                    source="Gravatar",
                    confidence=1.0,
                    risk=5,
                )],
                edges=[GraphEdge(
                    id=f"{root_id}->{node_id}",
                    source=root_id,
                    target=node_id,
                    label="HAS_PUBLIC_AVATAR",
                    source_name="Gravatar",
                    confidence=1.0,
                )],
                run=SourceRun(
                    name=self.name, status="ok", message="Public avatar found", duration_ms=elapsed
                ),
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status="error", message=str(exc), duration_ms=elapsed
            ))
