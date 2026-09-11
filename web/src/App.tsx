import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, Database, ExternalLink, History, Link2, Loader2, Network,
  Search, ShieldCheck, Sparkles, Trash2, UserRound
} from 'lucide-react'
import { addMonitoredIdentity, fetchConnectors, fetchFlowsintStatus, fetchMonitoredIdentities, fetchRemovalLinks, fetchSearch, fetchSearches, fetchThreatIntelStatus, fetchIdentityOsintStatus, loginFlowsint, logoutFlowsint, removeMonitoredIdentity, runSearch, saveThreatIntelKeys, saveIdentityOsintKey } from './api'
import { GraphView } from './components/GraphView'
import type { ConnectorStatus, FlowsintStatus, MonitoredIdentity, RemovalLink, SearchResponse, SelectedItem } from './types'
import './styles.css'

const kinds = [
  ['auto', 'Auto detect'],
  ['email', 'Email'],
  ['phone', 'Phone'],
  ['username', 'Username'],
  ['domain', 'Domain'],
  ['ip', 'IP address'],
  ['person', 'Name / person'],
  ['address', 'Postal address'],
]

function cleanText(value: string | null | undefined) {
  if (!value) return ''
  return value.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim()
}


const REMOVAL_LINKS = [
  { match: ['reddit.com'], url: 'https://support.reddithelp.com/hc/en-us/articles/204579509-How-do-I-delete-my-account' },
  { match: ['tiktok.com'], url: 'https://support.tiktok.com/en/account-and-privacy/manage-account/delete-account' },
  { match: ['twitch.tv', 'twitchtracker.com'], url: 'https://help.twitch.tv/s/article/delete-twitch-account' },
  { match: ['discord.com', 'discords.com'], url: 'https://support.discord.com/hc/fr/articles/212500837-Comment-supprimer-votre-compte-Discord' },
  { match: ['wordpress.com'], url: 'https://wordpress.com/fr/support/fermer-compte/' },
  { match: ['vimeo.com'], url: 'https://help.vimeo.com/hc/fr/articles/12425669379601-Comment-supprimer-mon-compte' },
  { match: ['paypal.com'], url: 'https://www.paypal.com/fr/cshelp/article/comment-fermer-mon-compte-paypal%C2%A0-help247' },
  { match: ['apple.com'], url: 'https://privacy.apple.com/' },
]

function removalLinkFor(profileUrl: string, platform: string) {
  const haystack = `${profileUrl} ${platform}`.toLowerCase()
  return REMOVAL_LINKS.find((item) => item.match.some((term) => haystack.includes(term)))?.url || null
}


function domainFor(url: string) {
  try { return new URL(url).hostname.toLowerCase().replace(/^www\./, '') } catch { return '' }
}

function asText(value: unknown): string[] {
  if (value == null || value === '') return []
  if (typeof value === 'string' || typeof value === 'number') return [String(value)]
  if (Array.isArray(value)) return value.flatMap(asText)
  if (typeof value === 'object') return Object.values(value as Record<string, unknown>).flatMap(asText)
  return []
}

export default function App() {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('auto')
  const [authorized, setAuthorized] = useState(true)
  const [result, setResult] = useState<SearchResponse | null>(null)
  const [selected, setSelected] = useState<SelectedItem>(null)
  const [connectors, setConnectors] = useState<ConnectorStatus[]>([])
  const [history, setHistory] = useState<Array<{id: string; created_at: string; query: string; kind: string}>>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [monitored, setMonitored] = useState<MonitoredIdentity[]>([])
  const [monitorEmail, setMonitorEmail] = useState('')
  const [flowsintStatus, setFlowsintStatus] = useState<FlowsintStatus>({ connected: false })
  const [flowsintEmail, setFlowsintEmail] = useState('')
  const [flowsintPassword, setFlowsintPassword] = useState('')
  const [flowsintBusy, setFlowsintBusy] = useState(false)
  const [removalLinks, setRemovalLinks] = useState<Record<string, RemovalLink>>({})
  const [intelStatus, setIntelStatus] = useState({ virustotal: false, shodan: false })
  const [vtKey, setVtKey] = useState('')
  const [shodanKey, setShodanKey] = useState('')
  const [intelBusy, setIntelBusy] = useState(false)
  const [identityStatus, setIdentityStatus] = useState({ trestle: false })
  const [trestleKey, setTrestleKey] = useState('')
  const [identityBusy, setIdentityBusy] = useState(false)

  const refreshMeta = useCallback(async () => {
    const [connectorData, historyData] = await Promise.all([
      fetchConnectors().catch(() => []),
      fetchSearches().catch(() => []),
    ])
    setConnectors(connectorData)
    setHistory(historyData)
  }, [])

  useEffect(() => {
    refreshMeta()
    fetchMonitoredIdentities().then(setMonitored).catch(() => setMonitored([]))
    fetchFlowsintStatus().then(setFlowsintStatus).catch(() => setFlowsintStatus({ connected: false }))
    fetchThreatIntelStatus().then(setIntelStatus).catch(() => setIntelStatus({ virustotal: false, shodan: false }))
    fetchIdentityOsintStatus().then(setIdentityStatus).catch(() => setIdentityStatus({ trestle: false }))
  }, [refreshMeta])

  useEffect(() => {
    if (!result) { setRemovalLinks({}); return }
    const domains = [...new Set(result.nodes
      .filter((node) => node.type.toLowerCase() === 'socialaccount')
      .map((node) => domainFor(String(node.properties?.profile_url || '')))
      .filter(Boolean))]
    if (!domains.length) { setRemovalLinks({}); return }
    fetchRemovalLinks(domains).then((items) => {
      const mapped: Record<string, RemovalLink> = {}
      items.forEach((item) => { mapped[item.domain.replace(/^www\./, '')] = item })
      setRemovalLinks(mapped)
    }).catch(() => setRemovalLinks({}))
  }, [result])

  async function addMonitor() {
    if (!monitorEmail.trim()) return
    try {
      await addMonitoredIdentity(monitorEmail.trim())
      setMonitorEmail('')
      setMonitored(await fetchMonitoredIdentities())
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to add email')
    }
  }

  async function removeMonitor(id: string) {
    await removeMonitoredIdentity(id)
    setMonitored(await fetchMonitoredIdentities())
  }

  async function connectFlowsint() {
    if (!flowsintEmail.trim() || !flowsintPassword) return
    setFlowsintBusy(true)
    setError('')
    try {
      const status = await loginFlowsint(flowsintEmail.trim(), flowsintPassword)
      setFlowsintStatus(status)
      setFlowsintPassword('')
      await refreshMeta()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Flowsint connection failed')
    } finally {
      setFlowsintBusy(false)
    }
  }

  async function disconnectFlowsint() {
    await logoutFlowsint()
    setFlowsintStatus({ connected: false })
    await refreshMeta()
  }

  async function saveIntelKeys() {
    setIntelBusy(true)
    setError('')
    try {
      const status = await saveThreatIntelKeys(vtKey.trim(), shodanKey.trim())
      setIntelStatus(status)
      setVtKey('')
      setShodanKey('')
      await refreshMeta()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to save API keys')
    } finally {
      setIntelBusy(false)
    }
  }

  async function saveIdentityKey() {
    if (!trestleKey.trim()) return
    setIdentityBusy(true)
    setError('')
    try {
      const status = await saveIdentityOsintKey(trestleKey.trim())
      setIdentityStatus(status)
      setTrestleKey('')
      await refreshMeta()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to save identity API key')
    } finally {
      setIdentityBusy(false)
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault()
    if (!query.trim()) return
    setLoading(true)
    setError('')
    try {
      const data = await runSearch(query.trim(), kind, authorized)
      setResult(data)
      setSelected(data.nodes[0] ? { kind: 'node', data: data.nodes[0] } : null)
      await refreshMeta()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Search failed')
    } finally {
      setLoading(false)
    }
  }

  async function openHistory(id: string) {
    setLoading(true)
    setError('')
    try {
      const data = await fetchSearch(id)
      setResult(data)
      setQuery(data.query)
      setKind(data.kind)
      setSelected(data.nodes[0] ? { kind: 'node', data: data.nodes[0] } : null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load search')
    } finally {
      setLoading(false)
    }
  }

  const stats = useMemo(() => ({
    nodes: result?.nodes.length ?? 0,
    links: result?.edges.length ?? 0,
    breaches: result?.breaches.length ?? 0,
    highRisk: result?.nodes.filter((node) => node.risk >= 80).length ?? 0,
  }), [result])

  const discoveredSites = useMemo(() => {
    if (!result) return []
    const byKey = new Map<string, any>()
    for (const node of result.nodes.filter((item) => item.type.toLowerCase() === 'socialaccount')) {
      const props = node.properties || {}
      const profileUrl = String(props.profile_url || '')
      const platform = String(props.platform || node.label)
      if (!profileUrl) continue
      const score = (props.profile_picture_url ? 2 : 0) + (props.followers_count != null ? 2 : 0) + (props.display_name ? 1 : 0)
      const domain = domainFor(profileUrl)
      const directory = removalLinks[domain]
      const key = profileUrl.toLowerCase().replace(/\/$/, '')
      const item = {
        node, profileUrl, platform, domain, score,
        removalUrl: directory?.url || removalLinkFor(profileUrl, platform),
        removalDifficulty: directory?.difficulty || 'unknown',
        removalNotes: directory?.notes || null,
      }
      const previous = byKey.get(key)
      if (!previous || score > previous.score) byKey.set(key, item)
    }
    return [...byKey.values()].sort((a, b) => b.score - a.score || a.platform.localeCompare(b.platform))
  }, [result, removalLinks])

  const personalData = useMemo(() => {
    if (!result) return []
    const displayNames = new Set<string>()
    const fullNames = new Set<string>()
    const usernames = new Set<string>()
    const phones = new Set<string>()
    const postalAddresses = new Set<string>()
    const publicLocations = new Set<string>()
    const avatars = new Set<string>()
    for (const node of result.nodes) {
      const type = node.type.toLowerCase()
      const p = node.properties || {}
      if (type === 'gravatar' && p.display_name) displayNames.add(String(p.display_name))
      if (type === 'socialaccount' && p.display_name) displayNames.add(String(p.display_name))
      if ((type === 'person' || type === 'individual') && node.label) fullNames.add(node.label)
      if (type === 'username') asText(p.value || node.label).forEach((v) => usernames.add(v))
      if (type === 'phone') phones.add(node.label)
      if (['person', 'individual', 'phone', 'socialaccount'].includes(type))
        asText(p.phone || p.phone_number || p.phone_numbers || p.associated_phones).forEach((v) => phones.add(v))
      if (type === 'address') postalAddresses.add(node.label)
      if (['person', 'individual', 'address'].includes(type))
        asText(p.address || p.current_address || p.previous_addresses).forEach((v) => postalAddresses.add(v))
      if (type === 'location') publicLocations.add(node.label)
      if (['gravatar', 'socialaccount', 'person', 'individual'].includes(type))
        asText(p.location).forEach((v) => publicLocations.add(v))
      if (['gravatar', 'socialaccount'].includes(type))
        asText(p.avatarUrl || p.src || p.profile_picture_url).forEach((v) => avatars.add(v))
    }
    const identityLabel = ({
      email: 'Email', phone: 'Phone', username: 'Username', domain: 'Domain',
      ip: 'IP address', person: 'Person', address: 'Postal address'
    } as Record<string, string>)[result.kind] || 'Search identifier'
    const linkedEmails = new Set<string>()
    for (const node of result.nodes) {
      if (node.type.toLowerCase() === 'email' && node.label.toLowerCase() !== result.query.toLowerCase()) linkedEmails.add(node.label)
    }
    return [
      { label: identityLabel, values: [result.query], state: 'confirmed' },
      ...(result.kind !== 'email' ? [{ label: 'Linked email', values: [...linkedEmails], state: linkedEmails.size ? 'found' : 'none' }] : []),
      { label: 'Name / display name', values: [...displayNames], state: displayNames.size ? 'found' : 'none' },
      { label: 'Full name', values: [...fullNames], state: fullNames.size ? 'found' : 'none' },
      { label: 'Username', values: [...usernames], state: usernames.size ? 'found' : 'none' },
      { label: 'Phone', values: [...phones], state: phones.size ? 'found' : 'none' },
      { label: 'Postal address', values: [...postalAddresses], state: postalAddresses.size ? 'found' : 'none' },
      { label: 'Public location', values: [...publicLocations], state: publicLocations.size ? 'found' : 'none' },
      { label: 'Public avatar / profile image', values: [...avatars], state: avatars.size ? 'found' : 'none' },
    ]
  }, [result])

  const configuredCount = connectors.filter((c) => c.configured).length

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><Network size={20} /></div>
          <div><strong>ExposureGraph</strong><span>self-OSINT exposure monitor</span></div>
        </div>
        <div className="privacy-pill"><ShieldCheck size={15} /> Local-first • public code, private local data</div>
      </header>

      <main className="workspace">
        <aside className="left-panel panel">
          <form onSubmit={submit} className="search-card">
            <div className="eyebrow"><Sparkles size={14} /> New investigation</div>
            <div className="search-row">
              <Search size={18} />
              <input
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="email, phone, username, domain, IP…"
                autoComplete="off"
              />
            </div>
            <select value={kind} onChange={(e) => setKind(e.target.value)}>
              {kinds.map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
            <label className="authorization">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
              />
              <span>I own this identifier or have explicit authorization to assess it.</span>
            </label>
            <button className="primary" disabled={loading || !query.trim()}>
              {loading ? <Loader2 className="spin" size={17} /> : <Search size={17} />}
              Investigate
            </button>
            {error && <div className="error"><AlertTriangle size={15} /> {error}</div>}
          </form>
          <section className="side-section">
            <div className="section-title">
              <Database size={15} /> Connectors
              <span>{configuredCount}/{connectors.length}</span>
            </div>
            <div className="connector-list">
              {connectors.map((connector) => (
                <div className="connector" key={connector.name} title={connector.note}>
                  <i className={connector.configured ? 'online' : 'offline'} />
                  <div><b>{connector.name}</b><small>{connector.category}</small></div>
                  {connector.requires_key && !connector.configured && <em>API key</em>}
                </div>
              ))}
            </div>
          </section>

          <section className="side-section intel-section">
            <div className="section-title"><ShieldCheck size={15} /> Threat intelligence</div>
            <div className="intel-status-row">
              <span className={intelStatus.virustotal ? 'intel-on' : ''}>VirusTotal</span>
              <span className={intelStatus.shodan ? 'intel-on' : ''}>Shodan</span>
            </div>
            <input type="password" value={vtKey} onChange={(e) => setVtKey(e.target.value)} placeholder="VirusTotal API key" />
            <input type="password" value={shodanKey} onChange={(e) => setShodanKey(e.target.value)} placeholder="Shodan API key" />
            <button type="button" onClick={saveIntelKeys} disabled={intelBusy || (!vtKey.trim() && !shodanKey.trim())}>
              {intelBusy ? 'Saving…' : 'Connect intelligence sources'}
            </button>
            <small>Keys stay in the local ExposureGraph database and are never returned to the browser after saving.</small>
          </section>

          <section className="side-section intel-section">
            <div className="section-title"><UserRound size={15} /> Phone identity</div>
            <div className="intel-status-row">
              <span className={identityStatus.trestle ? 'intel-on' : ''}>Trestle Identity</span>
              <span className="intel-on">Flowsint active</span>
            </div>
            <input type="password" value={trestleKey} onChange={(e) => setTrestleKey(e.target.value)} placeholder="Trestle API key" />
            <button type="button" onClick={saveIdentityKey} disabled={identityBusy || !trestleKey.trim()}>
              {identityBusy ? 'Saving…' : 'Connect phone identity'}
            </button>
            <a href="https://www.truecaller.com/fr-fr/reverse-phone-number-lookup" target="_blank" rel="noreferrer">Manual Truecaller check <ExternalLink size={12} /></a>
            <small>Authorized phone searches actively launch Flowsint enrichers. Trestle can add owner names, addresses and associated emails when its coverage returns a match.</small>
          </section>

          <section className="side-section watch-services">
            <div className="section-title"><ShieldCheck size={15} /> External monitors</div>
            <a href="https://my.nordaccount.com/" target="_blank" rel="noreferrer">NordVPN Dark Web Monitor <ExternalLink size={12} /></a>
            <a href="https://pass.proton.me/" target="_blank" rel="noreferrer">Proton Pass Monitor <ExternalLink size={12} /></a>
            <a href="https://central.bitdefender.com/" target="_blank" rel="noreferrer">Bitdefender Digital Identity <ExternalLink size={12} /></a>
            <small>These services do not expose a supported public API for importing your personal alerts, so ExposureGraph links to their dashboards instead of scraping sessions or cookies.</small>
          </section>

          <section className="side-section flowsint-section">
            <div className="section-title"><Network size={15} /> Flowsint bridge</div>
            {flowsintStatus.connected ? (
              <div className="flowsint-connected">
                <span><i className="online" /> Connected as <b>{flowsintStatus.email}</b></span>
                <small>Graph + local enrichers available. Your password is not stored.</small>
                <button type="button" onClick={disconnectFlowsint}>Disconnect</button>
              </div>
            ) : (
              <div className="flowsint-login">
                <input type="email" value={flowsintEmail} onChange={(e) => setFlowsintEmail(e.target.value)} placeholder="Flowsint email" />
                <input type="password" value={flowsintPassword} onChange={(e) => setFlowsintPassword(e.target.value)} placeholder="Flowsint password" />
                <button type="button" onClick={connectFlowsint} disabled={flowsintBusy || !flowsintPassword}>
                  {flowsintBusy ? 'Connecting…' : 'Connect local Flowsint'}
                </button>
                <small>Password goes only to your local Flowsint API; ExposureGraph stores only the temporary access token.</small>
              </div>
            )}
          </section>

          <section className="side-section monitor-section">
            <div className="section-title"><ShieldCheck size={15} /> Monitored emails <span>{monitored.length}</span></div>
            <div className="monitor-add">
              <input
                value={monitorEmail}
                onChange={(e) => setMonitorEmail(e.target.value)}
                placeholder="another@email.com"
                type="email"
              />
              <button type="button" onClick={addMonitor}>Add</button>
            </div>
            <div className="monitor-list">
              {monitored.map((item) => (
                <div className="monitor-item" key={item.id}>
                  <button className="monitor-open" onClick={() => { setQuery(item.value); setKind('email') }}>
                    <b>{item.label || item.value}</b><small>{item.value}</small>
                  </button>
                  <button className="monitor-remove" onClick={() => removeMonitor(item.id)} aria-label="Remove">×</button>
                </div>
              ))}
              {!monitored.length && <p className="muted">Add every email you own and want to monitor.</p>}
            </div>
          </section>

          <section className="side-section history-section">
            <div className="section-title"><History size={15} /> Recent searches</div>
            <div className="history-list">
              {history.slice(0, 12).map((item) => (
                <button key={item.id} onClick={() => openHistory(item.id)}>
                  <span>{item.query}</span>
                  <small>{item.kind} · {new Date(item.created_at).toLocaleString()}</small>
                </button>
              ))}
              {!history.length && <p className="muted">No searches yet.</p>}
            </div>
          </section>
        </aside>

        <section className="graph-panel panel">
          <div className="graph-header">
            <div>
              <span className="eyebrow">Investigation graph</span>
              <h1>{result ? result.query : 'Start with one of your identifiers'}</h1>
            </div>
            <div className="stats">
              <span><b>{stats.nodes}</b> nodes</span>
              <span><b>{stats.links}</b> links</span>
              <span className={stats.breaches ? 'danger-stat' : ''}><b>{stats.breaches}</b> breaches</span>
              <span className={stats.highRisk ? 'danger-stat' : ''}><b>{stats.highRisk}</b> high risk</span>
            </div>
          </div>

          <div className="graph-area">
            {result ? (
              <GraphView nodes={result.nodes} edges={result.edges} onSelect={setSelected} />
            ) : (
              <div className="empty-state">
                <div className="empty-orbit"><Network size={40} /></div>
                <h2>Build your exposure map</h2>
                <p>Search an authorized identifier to correlate public OSINT, breach intelligence and your Flowsint graph.</p>
              </div>
            )}
          </div>

          {result?.warnings.length ? (
            <div className="warning-bar">
              <AlertTriangle size={15} /> {result.warnings.join(' Ãƒâ€šÃ‚Â· ')}
            </div>
          ) : null}
        </section>

        <aside className="right-panel panel">
          <section className="personal-data-section">
            <div className="section-title"><UserRound size={15} /> Personal data linked to this search</div>
            <div className="personal-data-list">
              {personalData.map((item) => (
                <div className="personal-data-row" key={item.label}>
                  <span>{item.label}</span>
                  <b className={item.state === 'none' ? 'missing-value' : ''}>
                    {item.state === 'none'
                      ? 'Not found in current sources'
                      : item.label.startsWith('Public avatar')
                        ? `${item.values.length} image source(s) detected`
                        : item.values.slice(0, 3).join(' · ')}
                  </b>
                  <em>{item.state === 'confirmed' ? 'confirmed' : item.state === 'found' ? 'found' : 'not found'}</em>
                </div>
              ))}
            </div>
            {result && <p className="privacy-note">“Not found” means not returned by the currently configured sources; it does not prove the data is absent from the internet.</p>}
          </section>

          <section className="site-removal-section">
            <div className="section-title"><Trash2 size={15} /> Detected sites & removal <span>{discoveredSites.length}</span></div>
            <p className="privacy-note">Username-only matches remain candidates until another signal confirms ownership.</p>
            <div className="site-removal-list">
              {discoveredSites.map((site: any) => (
                <article className="site-removal-card" key={`${site.platform}|${site.profileUrl}`}>
                  <button className="site-select" onClick={() => setSelected({ kind: 'node', data: site.node })}>
                    <b>{site.platform}</b>
                    <small>{site.score >= 2 ? 'probable match' : 'candidate match'} · {site.domain}</small>
                  </button>
                  <div className="site-actions">
                    <a href={site.profileUrl} target="_blank" rel="noreferrer"><ExternalLink size={12} /> Profile</a>
                    {site.removalUrl ? (
                      <a className="delete-link" href={site.removalUrl} target="_blank" rel="noreferrer"><Trash2 size={12} /> Remove my data</a>
                    ) : (
                      <a className="delete-link" href={`https://yourdigitalrights.org/d/${site.domain}`} target="_blank" rel="noreferrer"><Trash2 size={12} /> Request data deletion</a>
                    )}
                  </div>
                  <small className="delete-meta">{site.removalUrl ? `Removal: ${site.removalDifficulty}` : 'Independent privacy-request fallback (not the site itself)'}</small>
                </article>
              ))}
              {result && !discoveredSites.length && <p className="muted">No profile sites detected yet.</p>}
            </div>
          </section>

          <div className="inspector-title">
            <Link2 size={16} /> Inspector
          </div>

          {selected?.kind === 'node' && (
            <div className="inspector-card">
              <div className="type-badge">{selected.data.type}</div>
              <h2>{selected.data.label}</h2>
              <div className="meter-row">
                <span>Confidence <b>{Math.round(selected.data.confidence * 100)}%</b></span>
                <span>Risk <b className={selected.data.risk >= 80 ? 'risk-high' : ''}>{selected.data.risk}/100</b></span>
              </div>
              <div className="source-tag">Source: {selected.data.source}</div>
              <div className="property-list">
                {Object.entries(selected.data.properties || {}).map(([key, value]) => (
                  <div className="property" key={key}>
                    <span>{key}</span>
                    <b>{typeof value === 'string' ? value : JSON.stringify(value)}</b>
                  </div>
                ))}
              </div>
            </div>
          )}

          {selected?.kind === 'edge' && (
            <div className="inspector-card">
              <div className="type-badge edge-badge">relationship</div>
              <h2>{selected.data.label}</h2>
              <div className="property-list">
                <div className="property"><span>From</span><b>{selected.data.source}</b></div>
                <div className="property"><span>To</span><b>{selected.data.target}</b></div>
                <div className="property"><span>Source</span><b>{selected.data.source_name}</b></div>
                <div className="property"><span>Confidence</span><b>{Math.round(selected.data.confidence * 100)}%</b></div>
              </div>
            </div>
          )}
          {!selected && (
            <div className="inspector-card muted-card">
              <Network size={26} />
              <p>Select a node or a relationship to inspect all of its source data.</p>
            </div>
          )}

          <section className="breach-section">
            <div className="section-title">
              <AlertTriangle size={15} /> Exposure timeline
              <span>{result?.breaches.length ?? 0}</span>
            </div>
            <div className="breach-list">
              {result?.breaches.map((breach) => (
                <article className="breach-card" key={breach.id}>
                  <div className="breach-dot" />
                  <div>
                    <header>
                      <b>{breach.title}</b>
                      <time>{breach.breach_date || 'Unknown date'}</time>
                    </header>
                    {breach.domain && <div className="breach-domain">{breach.domain}</div>}
                    <div className="chips">
                      {breach.data_classes.slice(0, 8).map((item) => <span key={item}>{item}</span>)}
                    </div>
                    {breach.description && <p>{cleanText(breach.description).slice(0, 220)}</p>}
                  </div>
                </article>
              ))}
              {result && !result.breaches.length && <p className="muted">No breach returned by configured sources.</p>}
              {!result && <p className="muted">Breach results will appear here.</p>}
            </div>
          </section>
        </aside>
      </main>
    </div>
  )
}
