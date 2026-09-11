import time
from urllib.parse import quote
import httpx

from app.config import settings
from app.models import BreachRecord, GraphEdge, GraphNode, SourceRun
from app.storage import get_integration
from .base import ConnectorResult


class HIBPConnector:
    name = "Have I Been Pwned"
    base_url = "https://haveibeenpwned.com/api/v3"

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        integration = get_integration("email_osint") or {}
        api_key = str(integration.get("hibp_api_key") or settings.hibp_api_key or "").strip()
        if not api_key:
            return ConnectorResult(run=SourceRun(
                name=self.name, status="needs_key", message="HIBP_API_KEY required"
            ))
        if kind not in {"email", "phone", "username"}:
            return ConnectorResult(run=SourceRun(
                name=self.name, status="skipped", message="Account lookup not applicable"
            ))

        headers = {
            "hibp-api-key": api_key,
            "user-agent": "ExposureGraph-self-monitoring/0.1",
        }
        account = quote(query.strip(), safe="")

        result = ConnectorResult()
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(
                    f"{self.base_url}/breachedaccount/{account}",
                    headers=headers,
                    params={"truncateResponse": "false", "includeUnverified": "true"},
                )
                if resp.status_code == 404:
                    breaches = []
                else:
                    resp.raise_for_status()
                    breaches = resp.json()

                for item in breaches:
                    breach_id = f"breach:{item.get('Name', 'unknown')}"
                    result.breaches.append(BreachRecord(
                        id=breach_id,
                        name=item.get("Name", "Unknown"),
                        title=item.get("Title", item.get("Name", "Unknown")),
                        domain=item.get("Domain"),
                        breach_date=item.get("BreachDate"),
                        added_date=item.get("AddedDate"),
                        data_classes=item.get("DataClasses") or [],
                        description=item.get("Description"),
                        pwn_count=item.get("PwnCount"),
                        verified=item.get("IsVerified"),
                        source="HIBP",
                    ))
                    result.nodes.append(GraphNode(
                        id=breach_id,
                        type="breach",
                        label=item.get("Title", item.get("Name", "Breach")),
                        properties={
                            "domain": item.get("Domain"),
                            "breachDate": item.get("BreachDate"),
                            "addedDate": item.get("AddedDate"),
                            "dataClasses": item.get("DataClasses") or [],
                            "pwnCount": item.get("PwnCount"),
                            "verified": item.get("IsVerified"),
                            "malware": item.get("IsMalware"),
                            "stealerLog": item.get("IsStealerLog"),
                        },
                        source="HIBP",
                        confidence=1.0,
                        risk=90 if "Passwords" in (item.get("DataClasses") or []) else 65,
                    ))
                    result.edges.append(GraphEdge(
                        id=f"{root_id}->{breach_id}", source=root_id, target=breach_id,
                        label="EXPOSED_IN", source_name="HIBP", confidence=1.0,
                    ))

                if kind == "email":
                    await self._append_pastes(client, query, root_id, headers, result)
                    await self._append_stealer_domains(client, query, root_id, headers, result)

            elapsed = int((time.perf_counter() - started) * 1000)
            result.run = SourceRun(
                name=self.name,
                status="ok",
                message=f"{len(result.breaches)} breach(es)",
                duration_ms=elapsed,
            )
            return result
        except httpx.HTTPStatusError as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            result.run = SourceRun(
                name=self.name,
                status="error",
                message=f"HIBP HTTP {exc.response.status_code}",
                duration_ms=elapsed,
            )
            return result
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            result.run = SourceRun(
                name=self.name, status="error", message=str(exc), duration_ms=elapsed
            )
            return result

    async def _append_pastes(self, client, query, root_id, headers, result):
        account = quote(query.strip(), safe="")
        resp = await client.get(f"{self.base_url}/pasteaccount/{account}", headers=headers)
        if resp.status_code == 404:
            return
        if resp.status_code != 200:
            return
        for item in resp.json():
            paste_id = f"paste:{item.get('Source','paste')}:{item.get('Id','unknown')}"
            result.nodes.append(GraphNode(
                id=paste_id,
                type="paste",
                label=item.get("Title") or f"{item.get('Source','Paste')} paste",
                properties=item,
                source="HIBP",
                confidence=1.0,
                risk=55,
            ))
            result.edges.append(GraphEdge(
                id=f"{root_id}->{paste_id}", source=root_id, target=paste_id,
                label="MENTIONED_IN", source_name="HIBP", confidence=1.0,
            ))

    async def _append_stealer_domains(self, client, query, root_id, headers, result):
        account = quote(query.strip(), safe="")
        resp = await client.get(
            f"{self.base_url}/stealerlogsbyemail/{account}", headers=headers
        )
        if resp.status_code != 200:
            return
        for domain in resp.json():
            node_id = f"stealer-domain:{domain.lower()}"
            result.nodes.append(GraphNode(
                id=node_id, type="stealer_domain", label=domain,
                properties={"domain": domain, "note": "Credential-capture domain reported by HIBP"},
                source="HIBP", confidence=1.0, risk=95,
            ))
            result.edges.append(GraphEdge(
                id=f"{root_id}->{node_id}", source=root_id, target=node_id,
                label="SEEN_IN_STEALER_LOG_FOR", source_name="HIBP", confidence=1.0,
            ))
