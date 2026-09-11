import type { ConnectorStatus, MonitoredIdentity, RemovalLink, SearchResponse } from './types'

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const response = await fetch(url, init)
  if (!response.ok) {
    const body = await response.json().catch(() => ({}))
    throw new Error(body.detail || `HTTP ${response.status}`)
  }
  return response.json() as Promise<T>
}

export function fetchConnectors(): Promise<ConnectorStatus[]> {
  return json('/api/connectors')
}

export function runSearch(query: string, kind = 'auto', owned = true): Promise<SearchResponse> {
  return json('/api/search', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      query,
      kind,
      owned_or_authorized: owned,
    }),
  })
}

export function fetchSearches(): Promise<Array<{id: string; created_at: string; query: string; kind: string}>> {
  return json('/api/searches')
}

export function fetchSearch(id: string): Promise<SearchResponse> {
  return json(`/api/searches/${encodeURIComponent(id)}`)
}

export function fetchMonitoredIdentities(): Promise<MonitoredIdentity[]> {
  return json('/api/monitored-identities')
}

export function addMonitoredIdentity(value: string): Promise<MonitoredIdentity> {
  return json('/api/monitored-identities', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ value, kind: 'email', owned_or_authorized: true }),
  })
}

export async function removeMonitoredIdentity(id: string): Promise<void> {
  const response = await fetch(`/api/monitored-identities/${encodeURIComponent(id)}`, { method: 'DELETE' })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
}

export function fetchFlowsintStatus() {
  return json<import('./types').FlowsintStatus>('/api/integrations/flowsint')
}

export function loginFlowsint(email: string, password: string) {
  return json<import('./types').FlowsintStatus>('/api/integrations/flowsint/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password }),
  })
}

export async function logoutFlowsint(): Promise<void> {
  const response = await fetch('/api/integrations/flowsint', { method: 'DELETE' })
  if (!response.ok) throw new Error(`HTTP ${response.status}`)
}

export function fetchFlowsintEnrichers(): Promise<Array<Record<string, unknown>>> {
  return json('/api/integrations/flowsint/enrichers')
}
export function fetchRemovalLinks(domains: string[]): Promise<RemovalLink[]> {
  return json('/api/removal-links', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ domains }),
  })
}
export function fetchThreatIntelStatus(): Promise<{virustotal:boolean; shodan:boolean}> {
  return json('/api/integrations/threat-intel')
}

export function saveThreatIntelKeys(vt_api_key: string, shodan_api_key: string): Promise<{virustotal:boolean; shodan:boolean}> {
  return json('/api/integrations/threat-intel', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vt_api_key, shodan_api_key }),
  })
}


export function fetchIdentityOsintStatus(): Promise<{trestle:boolean; pdl:boolean}> {
  return json('/api/integrations/identity-osint')
}

export function saveIdentityOsintKey(trestle_api_key: string, pdl_api_key: string): Promise<{trestle:boolean; pdl:boolean}> {
  return json('/api/integrations/identity-osint', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ trestle_api_key, pdl_api_key }),
  })
}
