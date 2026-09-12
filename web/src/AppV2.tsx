import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, AtSign, CalendarDays, ChevronRight, Database, ExternalLink, Globe2,
  History, KeyRound, Link2, Loader2, Menu, Network, PanelRightOpen, Search, ShieldCheck, Trash2, UserRound, X
} from 'lucide-react'
import {
  addMonitoredIdentity, fetchConnectors, fetchEmailOsintStatus, fetchFlowsintStatus, fetchIdentityOsintStatus,
  fetchMonitoredIdentities, fetchRemovalLinks, fetchSearch, fetchSearches, fetchThreatIntelStatus,
  loginFlowsint, logoutFlowsint, removeMonitoredIdentity, runSearch, saveEmailOsintKeys, saveIdentityOsintKey,
  saveThreatIntelKeys,
} from './api'
import { GraphViewV2 } from './components/GraphViewV2'
import type { ConnectorStatus, FlowsintStatus, GraphNode, MonitoredIdentity, RemovalLink, SearchResponse, SelectedItem } from './types'
import './dark-v2.css'
import './responsive.css'
import './ergonomics.css'

const kinds = [
  ['auto', 'Détection automatique'], ['email', 'E-mail'], ['phone', 'Téléphone'],
  ['username', 'Pseudo'], ['domain', 'Domaine'], ['ip', 'Adresse IP'],
  ['person', 'Personne'], ['address', 'Adresse postale'],
]

type RightTab = 'sites' | 'inspect' | 'exposure'
type SiteAppearance = {
  node: GraphNode; url: string; domain: string; platform: string; username: string;
  displayName: string; createdAt: string; source: string; confidence: number; evidenceLevel: string;
  removal?: RemovalLink;
}

function clean(value: unknown): string {
  if (value == null) return ''
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value)
  return JSON.stringify(value)
}
function first(props: Record<string, unknown>, keys: string[]) {
  for (const key of keys) { const v = props[key]; if (v != null && clean(v).trim()) return clean(v).trim() }
  return ''
}
function domainFor(value: string) {
  if (!value) return ''
  try { return new URL(value.startsWith('http') ? value : `https://${value}`).hostname.toLowerCase().replace(/^www\./, '') } catch { return '' }
}
function nodeUrl(node: GraphNode) {
  const p = node.properties || {}
  const raw = first(p, ['profile_url', 'profileUrl', 'url', 'website', 'link', 'homepage', 'site'])
  if (raw) return raw.startsWith('http') ? raw : `https://${raw}`
  if (node.type.toLowerCase() === 'domain' && node.label.includes('.')) return `https://${node.label}`
  return ''
}
function usernameFrom(node: GraphNode, url = nodeUrl(node)) {
  const p = node.properties || {}
  const explicit = first(p, ['username', 'handle', 'screen_name', 'screenName', 'user', 'account_name', 'login'])
  if (explicit) return explicit.replace(/^@/, '')
  if (node.type.toLowerCase() === 'username') return node.label.replace(/^@/, '')
  try {
    const path = new URL(url).pathname.split('/').filter(Boolean)
    return path.length ? decodeURIComponent(path[path.length - 1]).replace(/^@/, '') : ''
  } catch { return '' }
}
function createdFrom(node: GraphNode) {
  return first(node.properties || {}, [
    'created_at', 'createdAt', 'creation_date', 'creationDate', 'account_created', 'accountCreated',
    'registered_at', 'registeredAt', 'registration_date', 'joined_at', 'joinedAt', 'join_date', 'first_seen',
  ])
}
function platformFrom(node: GraphNode, url: string) {
  return first(node.properties || {}, ['platform', 'service', 'site_name', 'network']) || domainFor(url) || node.label
}
function displayNameFrom(node: GraphNode) {
  return first(node.properties || {}, ['display_name', 'displayName', 'full_name', 'fullName', 'name', 'fullname']) || node.label
}
function evidenceFrom(node: GraphNode) {
  const explicit = first(node.properties || {}, ['evidence_level']).toLowerCase()
  if (explicit === 'confirmed') return 'confirmé'
  if (explicit === 'candidate') return 'candidat'
  if (explicit === 'probable') return 'probable'
  if (explicit) return explicit
  if (node.confidence >= .92) return 'confirmé'
  if (node.confidence >= .68) return 'probable'
  return 'candidat'
}
function cleanHtml(value: string | null | undefined) {
  return (value || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim()
}

export default function AppV2() {
  const [query, setQuery] = useState('')
  const [kind, setKind] = useState('auto')
  const [result, setResult] = useState<SearchResponse | null>(null)
  const [selected, setSelected] = useState<SelectedItem>(null)
  const [rightTab, setRightTab] = useState<RightTab>('sites')
  const [mobilePanel, setMobilePanel] = useState<'left'|'right'|null>(null)
  const [connectors, setConnectors] = useState<ConnectorStatus[]>([])
  const [history, setHistory] = useState<Array<{id:string; created_at:string; query:string; kind:string}>>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [removalLinks, setRemovalLinks] = useState<Record<string, RemovalLink>>({})

  const [monitored, setMonitored] = useState<MonitoredIdentity[]>([])
  const [monitorEmail, setMonitorEmail] = useState('')
  const [flowsintStatus, setFlowsintStatus] = useState<FlowsintStatus>({ connected: false })
  const [flowsintEmail, setFlowsintEmail] = useState('')
  const [flowsintPassword, setFlowsintPassword] = useState('')
  const [flowsintBusy, setFlowsintBusy] = useState(false)
  const [intelStatus, setIntelStatus] = useState({ virustotal: false, shodan: false })
  const [vtKey, setVtKey] = useState('')
  const [shodanKey, setShodanKey] = useState('')
  const [intelBusy, setIntelBusy] = useState(false)
  const [emailStatus, setEmailStatus] = useState({ hibp: false, brave: false })
  const [hibpKey, setHibpKey] = useState('')
  const [braveKey, setBraveKey] = useState('')
  const [emailBusy, setEmailBusy] = useState(false)
  const [identityStatus, setIdentityStatus] = useState({ trestle: false, pdl: false })
  const [trestleKey, setTrestleKey] = useState('')
  const [pdlKey, setPdlKey] = useState('')
  const [identityBusy, setIdentityBusy] = useState(false)

  const refresh = useCallback(async () => {
    const [c, h] = await Promise.all([fetchConnectors().catch(() => []), fetchSearches().catch(() => [])])
    setConnectors(c); setHistory(h)
  }, [])

  useEffect(() => {
    refresh()
    fetchMonitoredIdentities().then(setMonitored).catch(() => setMonitored([]))
    fetchFlowsintStatus().then(setFlowsintStatus).catch(() => setFlowsintStatus({ connected: false }))
    fetchThreatIntelStatus().then(setIntelStatus).catch(() => setIntelStatus({ virustotal:false, shodan:false }))
    fetchEmailOsintStatus().then(setEmailStatus).catch(() => setEmailStatus({ hibp:false, brave:false }))
    fetchIdentityOsintStatus().then(setIdentityStatus).catch(() => setIdentityStatus({ trestle:false, pdl:false }))
  }, [refresh])

  const siteAppearances = useMemo<SiteAppearance[]>(() => {
    if (!result) return []
    const map = new Map<string, SiteAppearance>()
    for (const node of result.nodes) {
      const type = node.type.toLowerCase()
      const url = nodeUrl(node)
      const looksLikeSite = ['socialaccount','website','domain','profile','account'].includes(type) || !!url
      if (!looksLikeSite || (!url && type !== 'domain')) continue
      const resolvedUrl = url || `https://${node.label}`
      const domain = domainFor(resolvedUrl)
      const username = usernameFrom(node, resolvedUrl)
      const appearance: SiteAppearance = {
        node, url: resolvedUrl, domain, platform: platformFrom(node, resolvedUrl), username,
        displayName: displayNameFrom(node), createdAt: createdFrom(node), source: node.source,
        confidence: node.confidence, evidenceLevel: evidenceFrom(node), removal: removalLinks[domain],
      }
      const key = `${domain}|${username || appearance.displayName}`.toLowerCase()
      const old = map.get(key)
      if (!old || appearance.confidence > old.confidence) map.set(key, appearance)
    }
    return [...map.values()].sort((a,b) => b.confidence - a.confidence || a.platform.localeCompare(b.platform))
  }, [result, removalLinks])

  const linkedUsernames = useMemo(() => {
    if (!result) return []
    const values = new Set<string>()
    for (const node of result.nodes) {
      const type = node.type.toLowerCase()
      const u = usernameFrom(node)
      if (type === 'username' && node.label) values.add(node.label.replace(/^@/, ''))
      if (u && ['socialaccount','website','profile','account'].includes(type)) values.add(u)
    }
    return [...values].sort()
  }, [result])

  useEffect(() => {
    if (!result) { setRemovalLinks({}); return }
    const domains = [...new Set(siteAppearances.map(s => s.domain).filter(Boolean))]
    if (!domains.length) return
    fetchRemovalLinks(domains).then(items => {
      const map: Record<string, RemovalLink> = {}
      items.forEach(item => { map[item.domain.replace(/^www\./,'')] = item })
      setRemovalLinks(map)
    }).catch(() => {})
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [result?.search_id])

  async function submit(e: FormEvent) {
    e.preventDefault(); if (!query.trim()) return
    setLoading(true); setError('')
    try {
      // Personal searches remain restricted server-side; the UI no longer asks for a repetitive checkbox.
      const data = await runSearch(query.trim(), kind, true)
      setResult(data); setSelected(null); setRightTab('sites'); setMobilePanel(null); await refresh()
    } catch (err) { setError(err instanceof Error ? err.message : 'Recherche impossible') }
    finally { setLoading(false) }
  }
  async function openHistory(id:string) {
    setLoading(true); setError('')
    try { const data = await fetchSearch(id); setResult(data); setQuery(data.query); setKind(data.kind); setSelected(null); setRightTab('sites'); setMobilePanel(null) }
    catch (err) { setError(err instanceof Error ? err.message : 'Impossible de charger la recherche') }
    finally { setLoading(false) }
  }
  function selectGraph(item: SelectedItem) {
    setSelected(item)
    if (item?.kind === 'node' && nodeUrl(item.data)) setRightTab('sites')
    else if (item) setRightTab('inspect')
    if (item && window.matchMedia('(max-width: 900px)').matches) setMobilePanel('right')
  }
  async function connectFlowsint() {
    if (!flowsintEmail.trim() || !flowsintPassword) return
    setFlowsintBusy(true); setError('')
    try { setFlowsintStatus(await loginFlowsint(flowsintEmail.trim(), flowsintPassword)); setFlowsintPassword(''); await refresh() }
    catch (err) { setError(err instanceof Error ? err.message : 'Connexion Flowsint impossible') }
    finally { setFlowsintBusy(false) }
  }
  async function saveIntel() {
    setIntelBusy(true); setError('')
    try { setIntelStatus(await saveThreatIntelKeys(vtKey.trim(), shodanKey.trim())); setVtKey(''); setShodanKey(''); await refresh() }
    catch (err) { setError(err instanceof Error ? err.message : 'Clés non enregistrées') }
    finally { setIntelBusy(false) }
  }
  async function saveEmailOsint() {
    setEmailBusy(true); setError('')
    try { setEmailStatus(await saveEmailOsintKeys(hibpKey.trim(), braveKey.trim())); setHibpKey(''); setBraveKey(''); await refresh() }
    catch (err) { setError(err instanceof Error ? err.message : 'Clés e-mail OSINT non enregistrées') }
    finally { setEmailBusy(false) }
  }
  async function saveIdentity() {
    setIdentityBusy(true); setError('')
    try { setIdentityStatus(await saveIdentityOsintKey(trestleKey.trim(), pdlKey.trim())); setTrestleKey(''); setPdlKey(''); await refresh() }
    catch (err) { setError(err instanceof Error ? err.message : 'Clés non enregistrées') }
    finally { setIdentityBusy(false) }
  }
  async function addMonitor() {
    if (!monitorEmail.trim()) return
    try { await addMonitoredIdentity(monitorEmail.trim()); setMonitorEmail(''); setMonitored(await fetchMonitoredIdentities()) }
    catch (err) { setError(err instanceof Error ? err.message : 'E-mail non ajouté') }
  }

  const stats = useMemo(() => ({
    nodes: result?.nodes.length || 0, links: result?.edges.length || 0,
    breaches: result?.breaches.length || 0, sites: siteAppearances.length,
    socials: siteAppearances.filter(site => site.node.type.toLowerCase() === 'socialaccount' || site.node.properties?.social_network === true).length,
  }), [result, siteAppearances])
  const configured = connectors.filter(c => c.configured).length
  const selectedNode = selected?.kind === 'node' ? selected.data : null
  const selectedUrl = selectedNode ? nodeUrl(selectedNode) : ''
  const selectedAppearance = selectedNode ? siteAppearances.find(s => s.node.id === selectedNode.id) : undefined

  return <div className="eg2-shell">
    <header className="eg2-topbar">
      <div className="eg2-brand"><span className="eg2-logo"><Network size={19}/></span><div><b>ExposureGraph</b><small>OSINT exposure intelligence</small></div></div>
      <div className="eg2-top-status"><span><i className="dot green"/> {configured}/{connectors.length} sources</span><span><ShieldCheck size={14}/> accès protégé</span></div>
      <div className="eg2-mobile-actions"><button type="button" aria-label="Ouvrir la recherche" onClick={()=>setMobilePanel(mobilePanel==='left'?null:'left')}><Menu size={18}/><span>Recherche</span></button><button type="button" aria-label="Ouvrir les résultats" onClick={()=>setMobilePanel(mobilePanel==='right'?null:'right')}><PanelRightOpen size={18}/><span>Résultats</span></button></div>
    </header>

    {mobilePanel&&<button className="eg2-mobile-backdrop" aria-label="Fermer le panneau" onClick={()=>setMobilePanel(null)}/>}
    <main className="eg2-workspace">
      <aside className={`eg2-left eg2-panel eg2-scroll ${mobilePanel==='left'?'mobile-open':''}`}>
        <div className="eg2-mobile-panel-head"><b>Recherche & réglages</b><button type="button" onClick={()=>setMobilePanel(null)} aria-label="Fermer"><X size={18}/></button></div>
        <form className="eg2-search" onSubmit={submit}>
          <div className="eg2-kicker">Nouvelle recherche</div>
          <div className="eg2-searchbox"><Search size={18}/><input value={query} onChange={e=>setQuery(e.target.value)} placeholder="e-mail, téléphone, pseudo, domaine, IP…" autoComplete="off"/></div>
          <select value={kind} onChange={e=>setKind(e.target.value)}>{kinds.map(([v,l])=><option value={v} key={v}>{l}</option>)}</select>
          <button className="eg2-primary" disabled={loading || !query.trim()}>{loading?<Loader2 className="spin" size={17}/>:<Search size={17}/>}{loading?'Scan complet en cours…':'Lancer le scan complet'}</button>
          {error && <div className="eg2-error"><AlertTriangle size={14}/>{error}</div>}
        </form>

        <details className="eg2-menu" open><summary><Database size={15}/> Sources <span>{configured}/{connectors.length}</span></summary><div className="eg2-menu-body eg2-source-list">
          {connectors.map(c=><div className="eg2-source" key={c.name} title={c.note}><i className={`dot ${c.configured?'green':'grey'}`}/><div><b>{c.name}</b><small>{c.category}</small></div>{c.requires_key&&!c.configured&&<em>clé</em>}</div>)}
        </div></details>

        <details className="eg2-menu"><summary><KeyRound size={15}/> API & identité</summary><div className="eg2-menu-body eg2-form-stack">
          <div className="eg2-status-pills"><span className={emailStatus.hibp?'on':''}>HIBP</span><span className={emailStatus.brave?'on':''}>Brave Web</span><span className={intelStatus.virustotal?'on':''}>VirusTotal</span><span className={intelStatus.shodan?'on':''}>Shodan</span><span className={identityStatus.trestle?'on':''}>Trestle</span><span className={identityStatus.pdl?'on':''}>PDL</span></div>
          <input type="password" value={hibpKey} onChange={e=>setHibpKey(e.target.value)} placeholder="Have I Been Pwned API key"/><input type="password" value={braveKey} onChange={e=>setBraveKey(e.target.value)} placeholder="Brave Search API key"/>
          <button onClick={saveEmailOsint} type="button" disabled={emailBusy}>{emailBusy?'Enregistrement…':'Enregistrer Email OSINT'}</button>
          <input type="password" value={vtKey} onChange={e=>setVtKey(e.target.value)} placeholder="VirusTotal API key"/><input type="password" value={shodanKey} onChange={e=>setShodanKey(e.target.value)} placeholder="Shodan API key"/>
          <button onClick={saveIntel} type="button" disabled={intelBusy}>{intelBusy?'Enregistrement…':'Enregistrer Threat Intel'}</button>
          <input type="password" value={trestleKey} onChange={e=>setTrestleKey(e.target.value)} placeholder="Trestle API key"/><input type="password" value={pdlKey} onChange={e=>setPdlKey(e.target.value)} placeholder="People Data Labs API key"/>
          <button onClick={saveIdentity} type="button" disabled={identityBusy}>{identityBusy?'Enregistrement…':'Enregistrer Identity OSINT'}</button>
        </div></details>

        <details className="eg2-menu"><summary><Network size={15}/> Flowsint</summary><div className="eg2-menu-body eg2-form-stack">
          {flowsintStatus.connected?<><div className="eg2-connected"><i className="dot green"/> Connecté {flowsintStatus.email||''}</div><button type="button" onClick={async()=>{await logoutFlowsint();setFlowsintStatus({connected:false});await refresh()}}>Déconnecter</button></>:<><input type="email" value={flowsintEmail} onChange={e=>setFlowsintEmail(e.target.value)} placeholder="E-mail Flowsint"/><input type="password" value={flowsintPassword} onChange={e=>setFlowsintPassword(e.target.value)} placeholder="Mot de passe Flowsint"/><button type="button" onClick={connectFlowsint} disabled={flowsintBusy}>{flowsintBusy?'Connexion…':'Connecter Flowsint'}</button></>}
        </div></details>

        <details className="eg2-menu"><summary><AtSign size={15}/> E-mails surveillés <span>{monitored.length}</span></summary><div className="eg2-menu-body">
          <div className="eg2-inline"><input value={monitorEmail} onChange={e=>setMonitorEmail(e.target.value)} placeholder="moi@exemple.fr"/><button type="button" onClick={addMonitor}>+</button></div>
          <div className="eg2-mini-list">{monitored.map(m=><div key={m.id}><button onClick={()=>{setQuery(m.value);setKind('email')}}><b>{m.label||m.value}</b><small>{m.value}</small></button><button aria-label="Supprimer" onClick={async()=>{await removeMonitoredIdentity(m.id);setMonitored(await fetchMonitoredIdentities())}}>×</button></div>)}</div>
        </div></details>

        <details className="eg2-menu"><summary><History size={15}/> Historique</summary><div className="eg2-menu-body eg2-history">{history.slice(0,20).map(h=><button key={h.id} onClick={()=>openHistory(h.id)}><b>{h.query}</b><small>{h.kind} · {new Date(h.created_at).toLocaleString()}</small></button>)}</div></details>
      </aside>

      <section className="eg2-center eg2-panel">
        <div className="eg2-graph-head"><div><span>Investigation</span><h1>{result?.query||'Choisis un identifiant à analyser'}</h1></div><div className="eg2-stats"><span><b>{stats.nodes}</b> nœuds</span><span><b>{stats.links}</b> liens</span><span><b>{stats.sites}</b> sites</span><span><b>{stats.socials}</b> réseaux</span><span className={stats.breaches?'warn':''}><b>{stats.breaches}</b> fuites</span></div></div>
        <div className="eg2-graph">{result?<GraphViewV2 nodes={result.nodes} edges={result.edges} onSelect={selectGraph}/>:<div className="eg2-empty"><div><Network size={42}/></div><h2>Cartographie ton exposition numérique</h2><p>Les résultats publics, profils, pseudos, domaines, fuites et relations apparaîtront ici.</p></div>}</div>
        {!!result?.warnings.length&&<div className="eg2-warning"><AlertTriangle size={14}/>{result.warnings.join(' · ')}</div>}
      </section>

      <aside className={`eg2-right eg2-panel ${mobilePanel==='right'?'mobile-open':''}`}>
        <div className="eg2-mobile-panel-head"><b>Résultats & détails</b><button type="button" onClick={()=>setMobilePanel(null)} aria-label="Fermer"><X size={18}/></button></div>
        <nav className="eg2-tabs"><button className={rightTab==='sites'?'active':''} onClick={()=>setRightTab('sites')}><Globe2 size={14}/> Présence web <b>{siteAppearances.length}</b></button><button className={rightTab==='inspect'?'active':''} onClick={()=>setRightTab('inspect')}><Link2 size={14}/> Inspecteur</button><button className={rightTab==='exposure'?'active':''} onClick={()=>setRightTab('exposure')}><AlertTriangle size={14}/> Expositions</button></nav>
        <div className="eg2-right-scroll eg2-scroll">
          {rightTab==='sites'&&<section className="eg2-tab-content">
            <div className="eg2-section-head"><div><span>Présence de l’identifiant</span><h2>Sites & profils détectés</h2></div><Globe2 size={20}/></div>
            {result&&<details className="eg2-scan-report eg2-band" open><summary>Rapport du scan · {result.sources.filter(s=>s.status==='ok').length} sources exécutées</summary><div>{result.sources.map((s,i)=><div key={`${s.name}-${i}`}><span className={`scan-dot ${s.status}`}/><div><b>{s.name}</b><small>{s.message||s.status}</small></div><em>{s.status}</em></div>)}</div></details>}
            {linkedUsernames.length>0&&<details className="eg2-band" open><summary><span><AtSign size={14}/> Pseudos liés</span><b>{linkedUsernames.length}</b></summary><div className="eg2-band-body"><div className="eg2-username-strip"><div>{linkedUsernames.map(u=><button key={u} onClick={()=>{setQuery(u);setKind('username')}}>@{u}</button>)}</div></div></div></details>}
            {selectedAppearance&&<article className="eg2-selected-site"><div className="eg2-selected-icon"><Globe2 size={19}/></div><div><span>Nœud sélectionné</span><h3>{selectedAppearance.platform}</h3><p>{selectedAppearance.username?`@${selectedAppearance.username}`:selectedAppearance.displayName}</p><a className="eg2-selected-url" href={selectedAppearance.url} target="_blank" rel="noreferrer" onClick={e=>e.stopPropagation()}>{selectedAppearance.url}</a></div><a href={selectedAppearance.url} target="_blank" rel="noreferrer">Ouvrir <ExternalLink size={13}/></a></article>}
            <details className="eg2-band eg2-results-band" open>
              <summary><span><Globe2 size={14}/> Sites & profils détectés</span><b>{siteAppearances.length}</b></summary>
              <div className="eg2-band-body"><div className="eg2-site-list">{siteAppearances.map(site=><article className={`eg2-site-card ${selectedNode?.id===site.node.id?'selected':''}`} key={`${site.node.id}|${site.url}`} onClick={()=>{setSelected({kind:'node',data:site.node});setRightTab('sites')}}>
              <header><div><b>{site.platform}</b><small>{site.domain}</small></div><div className="eg2-card-badges">{site.node.properties?.social_network === true&&<span className="social">Réseau social</span>}<span>{site.evidenceLevel} · {Math.round(site.confidence*100)}%</span></div></header>
              <a className="eg2-site-url" href={site.url} target="_blank" rel="noreferrer" title={site.url} onClick={e=>e.stopPropagation()}><Globe2 size={12}/><span>{site.url}</span><ExternalLink size={11}/></a>
              <div className="eg2-site-grid"><div><span>Pseudo</span><b>{site.username?`@${site.username}`:'—'}</b></div><div><span>Nom affiché</span><b>{site.displayName||'—'}</b></div><div><span>Création / 1re trace</span><b>{site.createdAt||'Non fournie'}</b></div><div><span>Source</span><b>{site.source}</b></div></div>
              <div className="eg2-card-actions"><a href={site.url} target="_blank" rel="noreferrer" onClick={e=>e.stopPropagation()}><ExternalLink size={12}/> Ouvrir le profil</a>{site.removal?.url&&<a className="danger" href={site.removal.url} target="_blank" rel="noreferrer" onClick={e=>e.stopPropagation()}><Trash2 size={12}/> Suppression</a>}</div>
              <details className="eg2-raw" onClick={e=>e.stopPropagation()}><summary>Toutes les informations <ChevronRight size={12}/></summary><div>{Object.entries(site.node.properties||{}).map(([k,v])=><div key={k}><span>{k}</span><b>{clean(v)||'—'}</b></div>)}</div></details>
            </article>)}{result&&!siteAppearances.length&&<div className="eg2-none">Aucun site/profil n’a encore été retourné par les sources configurées.</div>}</div></div></details>
          </section>}

          {rightTab==='inspect'&&<section className="eg2-tab-content">
            <div className="eg2-section-head"><div><span>Données source</span><h2>Inspecteur</h2></div><Link2 size={20}/></div>
            {selected?.kind==='node'?<article className="eg2-inspector"><div className="eg2-badges"><span>{selected.data.type}</span><span>{selected.data.source}</span></div><h3>{selected.data.label}</h3><div className="eg2-meters"><span>Confiance <b>{Math.round(selected.data.confidence*100)}%</b></span><span>Risque <b>{selected.data.risk}/100</b></span></div>{selectedUrl&&<a className="eg2-open-site" href={selectedUrl} target="_blank" rel="noreferrer"><Globe2 size={14}/> Ouvrir le site associé <ExternalLink size={13}/></a>}<div className="eg2-property-list">{Object.entries(selected.data.properties||{}).map(([k,v])=><div key={k}><span>{k}</span><b>{clean(v)||'—'}</b></div>)}</div></article>:selected?.kind==='edge'?<article className="eg2-inspector"><div className="eg2-badges"><span>relation</span><span>{selected.data.source_name}</span></div><h3>{selected.data.label}</h3><div className="eg2-property-list"><div><span>Source</span><b>{selected.data.source}</b></div><div><span>Cible</span><b>{selected.data.target}</b></div><div><span>Confiance</span><b>{Math.round(selected.data.confidence*100)}%</b></div>{Object.entries(selected.data.properties||{}).map(([k,v])=><div key={k}><span>{k}</span><b>{clean(v)}</b></div>)}</div></article>:<div className="eg2-none">Clique sur un cercle ou une relation du graphe pour afficher toutes ses informations.</div>}
          </section>}

          {rightTab==='exposure'&&<section className="eg2-tab-content">
            <div className="eg2-section-head"><div><span>Historique connu</span><h2>Fuites & expositions</h2></div><AlertTriangle size={20}/></div>
            <details className="eg2-band" open>
              <summary><span><AlertTriangle size={14}/> Expositions détectées</span><b>{result?.breaches.length||0}</b></summary>
              <div className="eg2-band-body"><div className="eg2-breach-list">{result?.breaches.map(b=><article key={b.id}><div className="eg2-breach-dot"/><div><header><b>{b.title}</b><time>{b.breach_date||'Date inconnue'}</time></header>{b.domain&&<a href={`https://${b.domain}`} target="_blank" rel="noreferrer">{b.domain}</a>}<div className="eg2-chips">{b.data_classes.map(x=><span key={x}>{x}</span>)}</div>{b.description&&<p>{cleanHtml(b.description).slice(0,320)}</p>}</div></article>)}{result&&!result.breaches.length&&<div className="eg2-none">Aucune fuite retournée par les sources configurées.</div>}</div></div></details>
          </section>}
        </div>
      </aside>
    </main>
  </div>
}
