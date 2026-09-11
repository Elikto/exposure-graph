import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, Database, History, Link2, Loader2, Network,
  Search, ShieldCheck, Sparkles
} from 'lucide-react'
import { fetchConnectors, fetchSearch, fetchSearches, runSearch } from './api'
import { GraphView } from './components/GraphView'
import type { ConnectorStatus, SearchResponse, SelectedItem } from './types'
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
  }, [refreshMeta])

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

  const configuredCount = connectors.filter((c) => c.configured).length

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <div className="brand-mark"><Network size={20} /></div>
          <div><strong>ExposureGraph</strong><span>self-OSINT exposure monitor</span></div>
        </div>
        <div className="privacy-pill"><ShieldCheck size={15} /> Local-first • private repo</div>
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
              <AlertTriangle size={15} /> {result.warnings.join(' · ')}
            </div>
          ) : null}
        </section>

        <aside className="right-panel panel">
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
