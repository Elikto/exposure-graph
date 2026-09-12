import { useEffect, useMemo, useState } from 'react'
import { createPortal } from 'react-dom'
import { Gauge, Loader2, Radar } from 'lucide-react'
import './scan-mode.css'

type ScanMode = 'fast' | 'full'
type ScanEventDetail = { mode: ScanMode; estimateSeconds: number; ok?: boolean }

export function ScanModeController() {
  const [target, setTarget] = useState<HTMLFormElement | null>(null)
  const [mode, setMode] = useState<ScanMode>('fast')
  const [running, setRunning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [elapsed, setElapsed] = useState(0)
  const [estimate, setEstimate] = useState(10)

  useEffect(() => {
    ;(window as any).__exposureScanMode = mode
  }, [mode])

  useEffect(() => {
    const findTarget = () => setTarget(document.querySelector('.eg2-search') as HTMLFormElement | null)
    findTarget()
    const observer = new MutationObserver(findTarget)
    observer.observe(document.body, { childList: true, subtree: true })
    return () => observer.disconnect()
  }, [])

  useEffect(() => {
    let timer: number | undefined
    let startedAt = 0
    const onStart = (event: Event) => {
      const detail = (event as CustomEvent<ScanEventDetail>).detail
      startedAt = Date.now()
      setEstimate(detail.estimateSeconds)
      setElapsed(0)
      setProgress(4)
      setRunning(true)
      window.clearInterval(timer)
      timer = window.setInterval(() => {
        const seconds = (Date.now() - startedAt) / 1000
        const ratio = seconds / Math.max(1, detail.estimateSeconds)
        setElapsed(seconds)
        setProgress(Math.min(94, 4 + ratio * 86))
      }, 250)
    }
    const onEnd = () => {
      window.clearInterval(timer)
      setProgress(100)
      setTimeout(() => setRunning(false), 850)
    }
    window.addEventListener('exposure:scan-start', onStart)
    window.addEventListener('exposure:scan-end', onEnd)
    return () => {
      window.clearInterval(timer)
      window.removeEventListener('exposure:scan-start', onStart)
      window.removeEventListener('exposure:scan-end', onEnd)
    }
  }, [])

  const remaining = Math.max(0, Math.ceil(estimate - elapsed))
  const status = useMemo(() => {
    if (!running) return mode === 'fast' ? '≈ 10 s' : '≈ 30–40 s'
    if (progress >= 100) return 'Terminé'
    if (remaining > 0) return `≈ ${remaining} s restantes`
    return 'Finalisation…'
  }, [running, mode, progress, remaining])

  if (!target) return null
  const form = target

  function launch(nextMode: ScanMode) {
    if (running) return
    setMode(nextMode)
    ;(window as any).__exposureScanMode = nextMode
    form.requestSubmit()
  }

  return createPortal(
    <div className="scan-mode-panel">
      <div className="scan-mode-actions">
        <button type="button" className={`scan-mode-button ${mode === 'fast' ? 'active' : ''}`} disabled={running} onClick={() => launch('fast')}>
          {running && mode === 'fast' ? <Loader2 size={16} className="spin"/> : <Gauge size={16}/>} Scan rapide
        </button>
        <button type="button" className={`scan-mode-button full ${mode === 'full' ? 'active' : ''}`} disabled={running} onClick={() => launch('full')}>
          {running && mode === 'full' ? <Loader2 size={16} className="spin"/> : <Radar size={16}/>} Scan complet
        </button>
      </div>
      <div className="scan-mode-meta"><span>{mode === 'fast' ? 'Sources essentielles + profils prioritaires' : 'Toutes les sources + enrichissements approfondis'}</span><b>{status}</b></div>
      {running && <div className="scan-progress-wrap">
        <div className="scan-progress-track"><span style={{ width: `${progress}%` }}/></div>
        <div className="scan-progress-label"><span>{Math.round(progress)} % · {elapsed.toFixed(1)} s écoulées</span><span>Estimation</span></div>
      </div>}
    </div>,
    form,
  )
}
