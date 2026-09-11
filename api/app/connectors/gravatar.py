import asyncio
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
        profile_api = f"https://www.gravatar.com/{digest}.json"
        avatar_url = f"https://www.gravatar.com/avatar/{digest}?d=404&s=256"
        try:
            async with httpx.AsyncClient(timeout=12, follow_redirects=True) as client:
                profile_resp, avatar_resp = await asyncio.gather(
                    client.get(profile_api), client.get(avatar_url)
                )
            profile = {}
            if profile_resp.status_code == 200:
                body = profile_resp.json() or {}
                entries = body.get("entry") or []
                if entries and isinstance(entries[0], dict):
                    profile = entries[0]
            has_avatar = avatar_resp.status_code == 200
            if not profile and not has_avatar:
                elapsed = int((time.perf_counter() - started) * 1000)
                return ConnectorResult(run=SourceRun(
                    name=self.name, status="ok", message="No public Gravatar profile", duration_ms=elapsed
                ))

            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            preferred = str(profile.get("preferredUsername") or "").strip()
            display_name = str(profile.get("displayName") or "").strip()
            profile_url = str(profile.get("profileUrl") or "").strip()
            if preferred:
                username_id = f"gravatar:username:{digest}:{preferred.lower()}"
                nodes.append(GraphNode(
                    id=username_id,
                    type="username",
                    label=preferred,
                    properties={
                        "username": preferred,
                        "evidence_level": "confirmed",
                        "match_reason": "Gravatar profile resolved from the exact email hash",
                    },
                    source=self.name,
                    confidence=0.99,
                    risk=5,
                ))
                edges.append(GraphEdge(
                    id=f"{root_id}->{username_id}",
                    source=root_id,
                    target=username_id,
                    label="USES_USERNAME",
                    source_name=self.name,
                    confidence=0.99,
                ))

            profile_id = f"gravatar:profile:{digest}"
            props = {
                "platform": "Gravatar",
                "profile_url": profile_url or (f"https://gravatar.com/{preferred}" if preferred else ""),
                "preferredUsername": preferred,
                "display_name": display_name,
                "avatarUrl": avatar_url if has_avatar else profile.get("thumbnailUrl"),
                "thumbnailUrl": profile.get("thumbnailUrl"),
                "aboutMe": profile.get("aboutMe"),
                "currentLocation": profile.get("currentLocation"),
                "urls": profile.get("urls"),
                "accounts": profile.get("accounts"),
                "hash": digest,
                "evidence_level": "confirmed",
                "match_reason": "Public Gravatar profile resolved from the exact email hash",
            }
            nodes.append(GraphNode(
                id=profile_id,
                type="socialaccount",
                label=display_name or preferred or "Public Gravatar",
                properties={k: v for k, v in props.items() if v not in (None, "", [], {})},
                source=self.name,
                confidence=0.99,
                risk=5,
            ))
            if preferred:
                edges.append(GraphEdge(
                    id=f"gravatar:username:{digest}:{preferred.lower()}->{profile_id}",
                    source=f"gravatar:username:{digest}:{preferred.lower()}",
                    target=profile_id,
                    label="HAS_PUBLIC_PROFILE",
                    source_name=self.name,
                    confidence=0.99,
                ))
            else:
                edges.append(GraphEdge(
                    id=f"{root_id}->{profile_id}",
                    source=root_id,
                    target=profile_id,
                    label="HAS_PUBLIC_PROFILE",
                    source_name=self.name,
                    confidence=0.99,
                ))

            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(
                nodes=nodes,
                edges=edges,
                run=SourceRun(
                    name=self.name,
                    status="ok",
                    message=f"Public profile found{f' as {preferred}' if preferred else ''}",
                    duration_ms=elapsed,
                ),
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status="error", message=str(exc), duration_ms=elapsed
            ))
