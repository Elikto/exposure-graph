import asyncio
import hashlib
import re
import shutil
import time

from app.models import GraphEdge, GraphNode, SourceRun
from .base import ConnectorResult


def _hid(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:16]


def _clean_ansi(value: str) -> str:
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value)


class HoleheConnector:
    name = "Holehe"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if kind != "email":
            return ConnectorResult(run=SourceRun(name=self.name, status="skipped", message="Email only"))
        executable = shutil.which("holehe")
        if not executable:
            return ConnectorResult(run=SourceRun(
                name=self.name, status="skipped", message="Holehe executable unavailable"
            ))
        try:
            proc = await asyncio.create_subprocess_exec(
                executable,
                query.strip(),
                "--only-used",
                "--no-color",
                "--no-clear",
                "--no-password-recovery",
                "--timeout", "8",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            try:
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=35)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                raise RuntimeError("Holehe scan timed out")
            text = _clean_ansi(stdout.decode(errors="replace"))
            domains: list[str] = []
            checked = 0
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("[+]"):
                    domain = line[3:].strip().split()[0].strip().lower()
                    if domain and "." in domain and domain not in domains:
                        domains.append(domain)
                match = re.search(r"(\d+) websites checked", line)
                if match:
                    checked = int(match.group(1))

            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            for domain in domains[:100]:
                node_id = f"holehe:{_hid(domain)}"
                url = f"https://{domain}"
                nodes.append(GraphNode(
                    id=node_id,
                    type="website",
                    label=domain,
                    properties={
                        "domain": domain,
                        "profile_url": url,
                        "account_exists": True,
                        "evidence_level": "probable",
                        "match_reason": "Account-existence check for the exact email; password recovery disabled",
                    },
                    source=self.name,
                    confidence=0.90,
                    risk=10,
                ))
                edges.append(GraphEdge(
                    id=f"{root_id}->{node_id}",
                    source=root_id,
                    target=node_id,
                    label="EMAIL_REGISTERED_AT",
                    source_name=self.name,
                    confidence=0.90,
                ))

            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(
                nodes=nodes,
                edges=edges,
                run=SourceRun(
                    name=self.name,
                    status="ok",
                    message=f"{checked or 'multiple'} sites checked, {len(nodes)} positive(s); recovery disabled",
                    duration_ms=elapsed,
                ),
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status="error", message=str(exc), duration_ms=elapsed
            ))
