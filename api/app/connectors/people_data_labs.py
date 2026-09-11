import hashlib
import time

import httpx

from app.models import GraphEdge, GraphNode, SourceRun
from app.storage import get_integration
from .base import ConnectorResult


def _hid(value: object) -> str:
    return hashlib.sha256(str(value or '').encode()).hexdigest()[:16]


def _phone_query(value: str) -> str:
    cleaned = value.strip().replace(' ', '')
    if cleaned.startswith('00'):
        return '+' + cleaned[2:]
    return cleaned


class PeopleDataLabsConnector:
    name = 'People Data Labs'

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if kind != 'phone':
            return ConnectorResult(run=SourceRun(name=self.name, status='skipped', message='Phone only'))
        integration = get_integration('identity_osint') or {}
        api_key = str(integration.get('pdl_api_key') or '').strip()
        if not api_key:
            return ConnectorResult(run=SourceRun(name=self.name, status='needs_key', message='PDL_API_KEY required'))
        phone = _phone_query(query)
        if not phone.startswith('+'):
            return ConnectorResult(run=SourceRun(
                name=self.name,
                status='skipped',
                message='Use international phone format, e.g. +33…',
            ))
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                resp = await client.get(
                    'https://api.peopledatalabs.com/v5/person/enrich',
                    params={
                        'phone': phone,
                        'min_likelihood': 5,
                        'include_if_matched': 'true',
                    },
                    headers={'X-Api-Key': api_key, 'User-Agent': 'ExposureGraph/0.4'},
                )
            if resp.status_code == 404:
                return ConnectorResult(run=SourceRun(name=self.name, status='ok', message='No person match'))
            resp.raise_for_status()
            payload = resp.json()
            data = payload.get('data') or {}
            likelihood = max(1, min(10, int(payload.get('likelihood') or 5)))
            confidence = likelihood / 10.0
            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            person_id = f'pdl:person:{_hid(data.get("id") or data.get("full_name") or phone)}'
            person_props = {
                'pdl_id': data.get('id'),
                'first_name': data.get('first_name'),
                'middle_initial': data.get('middle_initial'),
                'last_name': data.get('last_name'),
                'sex': data.get('sex'),
                'birth_year': data.get('birth_year'),
                'job_title': data.get('job_title'),
                'job_company_name': data.get('job_company_name'),
                'likelihood': likelihood,
                'matched': payload.get('matched') or {},
            }
            person_props = {k: v for k, v in person_props.items() if v not in (None, '', [], {})}
            full_name = str(data.get('full_name') or 'Associated person')
            nodes.append(GraphNode(
                id=person_id,
                type='person',
                label=full_name,
                properties=person_props,
                source=self.name,
                confidence=confidence,
                risk=20,
            ))
            edges.append(GraphEdge(
                id=f'{root_id}->{person_id}',
                source=root_id,
                target=person_id,
                label='ASSOCIATED_PERSON',
                source_name=self.name,
                confidence=confidence,
            ))
            emails = data.get('emails') or []
            if data.get('work_email'):
                emails = [*emails, {'address': data.get('work_email'), 'type': 'work'}]
            for item in emails[:20]:
                value = str(item.get('address') if isinstance(item, dict) else item).strip()
                if not value:
                    continue
                email_id = f'pdl:email:{_hid(value.lower())}'
                props = item if isinstance(item, dict) else {'email': value}
                nodes.append(GraphNode(
                    id=email_id, type='email', label=value, properties=props,
                    source=self.name, confidence=confidence, risk=20,
                ))
                edges.append(GraphEdge(
                    id=f'{person_id}->{email_id}', source=person_id, target=email_id,
                    label='ASSOCIATED_EMAIL', source_name=self.name, confidence=confidence,
                ))

            addresses = data.get('street_addresses') or []
            for item in addresses[:15]:
                if not isinstance(item, dict):
                    continue
                label = ', '.join(str(item.get(k)) for k in ('street_address', 'locality', 'region', 'postal_code', 'country') if item.get(k))
                if not label:
                    continue
                addr_id = f'pdl:address:{_hid(label.lower())}'
                nodes.append(GraphNode(
                    id=addr_id, type='address', label=label, properties=item,
                    source=self.name, confidence=confidence, risk=20,
                ))
                edges.append(GraphEdge(
                    id=f'{person_id}->{addr_id}', source=person_id, target=addr_id,
                    label='ASSOCIATED_ADDRESS', source_name=self.name, confidence=confidence,
                ))
            profiles = data.get('profiles') or []
            for item in profiles[:25]:
                if not isinstance(item, dict):
                    continue
                url = str(item.get('url') or item.get('profile_url') or '').strip()
                if not url:
                    continue
                platform = str(item.get('network') or item.get('service') or 'social')
                profile_id = f'pdl:social:{_hid(url.lower())}'
                props = dict(item)
                props['profile_url'] = url
                props['platform'] = platform
                nodes.append(GraphNode(
                    id=profile_id, type='socialaccount', label=platform,
                    properties=props, source=self.name,
                    confidence=confidence, risk=15,
                ))
                edges.append(GraphEdge(
                    id=f'{person_id}->{profile_id}', source=person_id, target=profile_id,
                    label='HAS_PUBLIC_PROFILE', source_name=self.name,
                    confidence=confidence,
                ))

            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(
                nodes=nodes,
                edges=edges,
                run=SourceRun(
                    name=self.name,
                    status='ok',
                    message=f'{len(nodes)} identity node(s), likelihood {likelihood}/10',
                    duration_ms=elapsed,
                ),
            )
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(
                name=self.name, status='error', message=str(exc), duration_ms=elapsed,
            ))
