import hashlib
import time

import httpx

from app.models import GraphEdge, GraphNode, SourceRun
from app.storage import get_integration
from .base import ConnectorResult


def _hid(value: object) -> str:
    return hashlib.sha256(str(value or '').encode()).hexdigest()[:16]


def _address_label(item: dict) -> str:
    parts = [item.get('street_line_1'), item.get('street_line_2'), item.get('city'), item.get('postal_code'), item.get('state_code'), item.get('country_code')]
    return ', '.join(str(x) for x in parts if x)


class TrestleConnector:
    name = 'Trestle Identity'

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        started = time.perf_counter()
        if kind != 'phone':
            return ConnectorResult(run=SourceRun(name=self.name, status='skipped', message='Phone only'))
        integration = get_integration('identity_osint') or {}
        api_key = str(integration.get('trestle_api_key') or '').strip()
        if not api_key:
            return ConnectorResult(run=SourceRun(name=self.name, status='needs_key', message='TRESTLE_API_KEY required'))
        try:
            async with httpx.AsyncClient(timeout=25) as client:
                resp = await client.get(
                    'https://api.trestleiq.com/3.2/phone',
                    params={'phone': query},
                    headers={'x-api-key': api_key, 'User-Agent': 'ExposureGraph/0.3'},
                )
            if resp.status_code == 404:
                return ConnectorResult(run=SourceRun(name=self.name, status='ok', message='No identity match'))
            resp.raise_for_status()
            data = resp.json()
            nodes: list[GraphNode] = []
            edges: list[GraphEdge] = []
            phone_meta_id = f'trestle:phone:{_hid(query)}'
            phone_props = {k: data.get(k) for k in ('is_valid', 'country_calling_code', 'line_type', 'carrier', 'is_prepaid', 'is_commercial') if data.get(k) is not None}
            nodes.append(GraphNode(id=phone_meta_id, type='phone_metadata', label='Trestle phone identity', properties=phone_props, source=self.name, confidence=0.9, risk=10))
            edges.append(GraphEdge(id=f'{root_id}->{phone_meta_id}', source=root_id, target=phone_meta_id, label='HAS_IDENTITY_LOOKUP', source_name=self.name, confidence=1.0))
            owners = data.get('owners') or ([data.get('belongs_to')] if data.get('belongs_to') else [])
            for owner in [o for o in owners if isinstance(o, dict)]:
                name = owner.get('name') or 'Associated owner'
                owner_id = f'trestle:owner:{_hid(owner.get("id") or name)}'
                props = {k: owner.get(k) for k in ('firstname', 'middlename', 'lastname', 'alternate_names', 'age_range', 'gender', 'type', 'industry', 'link_to_phone_start_date') if owner.get(k) is not None}
                nodes.append(GraphNode(id=owner_id, type='person' if str(owner.get('type', '')).lower() != 'business' else 'business', label=str(name), properties=props, source=self.name, confidence=0.85, risk=20))
                edges.append(GraphEdge(id=f'{phone_meta_id}->{owner_id}', source=phone_meta_id, target=owner_id, label='ASSOCIATED_OWNER', source_name=self.name, confidence=0.85))

                addresses = owner.get('current_addresses') or []
                if owner.get('current_address'):
                    addresses = [owner.get('current_address'), *addresses]
                for address in [a for a in addresses if isinstance(a, dict)]:
                    label = _address_label(address)
                    if not label:
                        continue
                    addr_id = f'trestle:address:{_hid(label)}'
                    nodes.append(GraphNode(id=addr_id, type='address', label=label, properties=address, source=self.name, confidence=0.8, risk=20))
                    edges.append(GraphEdge(id=f'{owner_id}->{addr_id}', source=owner_id, target=addr_id, label='ASSOCIATED_ADDRESS', source_name=self.name, confidence=0.8))
                for email in owner.get('emails') or []:
                    email_value = str(email.get('email') if isinstance(email, dict) else email).strip()
                    if not email_value:
                        continue
                    email_id = f'trestle:email:{_hid(email_value.lower())}'
                    nodes.append(GraphNode(id=email_id, type='email', label=email_value, properties={'email': email_value}, source=self.name, confidence=0.8, risk=20))
                    edges.append(GraphEdge(id=f'{owner_id}->{email_id}', source=owner_id, target=email_id, label='ASSOCIATED_EMAIL', source_name=self.name, confidence=0.8))

            for email in data.get('emails') or []:
                email_value = str(email.get('email') if isinstance(email, dict) else email).strip()
                if email_value:
                    email_id = f'trestle:email:{_hid(email_value.lower())}'
                    if not any(n.id == email_id for n in nodes):
                        nodes.append(GraphNode(id=email_id, type='email', label=email_value, properties={'email': email_value}, source=self.name, confidence=0.8, risk=20))
                        edges.append(GraphEdge(id=f'{phone_meta_id}->{email_id}', source=phone_meta_id, target=email_id, label='ASSOCIATED_EMAIL', source_name=self.name, confidence=0.8))

            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(nodes=nodes, edges=edges, run=SourceRun(name=self.name, status='ok', message=f'{len(nodes)} identity node(s)', duration_ms=elapsed))
        except Exception as exc:
            elapsed = int((time.perf_counter() - started) * 1000)
            return ConnectorResult(run=SourceRun(name=self.name, status='error', message=str(exc), duration_ms=elapsed))
