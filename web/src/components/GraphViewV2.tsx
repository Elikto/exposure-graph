import { useEffect, useMemo, useRef } from 'react'
import cytoscape, { Core } from 'cytoscape'
import type { GraphEdge, GraphNode, SelectedItem } from '../types'

const COLORS: Record<string, string> = {
  email: '#8b5cf6', phone: '#0ea5e9', username: '#06b6d4', person: '#ec4899',
  individual: '#ec4899', address: '#f43f5e', domain: '#10b981', website: '#10b981',
  socialaccount: '#7c3aed', ip: '#3b82f6', breach: '#ef4444', paste: '#f59e0b',
  stealer_domain: '#dc2626', gravatar: '#a855f7', rdap: '#14b8a6', business: '#f97316',
}

function colorFor(type: string) { return COLORS[type.toLowerCase()] || '#64748b' }
function sizeFor(node: GraphNode) {
  if (node.id.startsWith('target:')) return 78
  if (['breach', 'stealer_domain'].includes(node.type.toLowerCase())) return 64
  return Math.max(44, Math.min(62, 44 + node.risk / 7))
}

type Props = { nodes: GraphNode[]; edges: GraphEdge[]; onSelect: (item: SelectedItem) => void }

export function GraphViewV2({ nodes, edges, onSelect }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const elements = useMemo(() => [
    ...nodes.map((node) => ({ data: { id: node.id, label: node.label, nodeType: node.type, color: colorFor(node.type), size: sizeFor(node), original: node } })),
    ...edges.map((edge) => ({ data: { id: edge.id, source: edge.source, target: edge.target, label: edge.label, original: edge } })),
  ], [nodes, edges])

  useEffect(() => {
    if (!containerRef.current) return
    cyRef.current?.destroy()
    const cy = cytoscape({
      container: containerRef.current,
      elements,
      minZoom: .12,
      maxZoom: 4,
      wheelSensitivity: .16,
      boxSelectionEnabled: false,
      style: [
        { selector: 'node', style: {
          'background-color': 'data(color)', 'width': 'data(size)', 'height': 'data(size)',
          label: 'data(label)', 'font-family': '-apple-system, BlinkMacSystemFont, Inter, sans-serif',
          'font-size': 11, 'font-weight': 650, color: '#e5e7eb', 'text-wrap': 'ellipsis',
          'text-max-width': 135, 'text-valign': 'bottom', 'text-margin-y': 11,
          'text-background-color': '#090b12', 'text-background-opacity': .88, 'text-background-padding': 5,
          'border-width': 2, 'border-color': '#ffffff24', 'overlay-opacity': 0,
        } },
        { selector: 'node:selected', style: {
          'border-width': 5, 'border-color': '#ffffff', 'shadow-blur': 30,
          'shadow-color': 'data(color)', 'shadow-opacity': .9,
        } },
        { selector: 'node:active', style: { 'overlay-opacity': .08, 'overlay-color': '#ffffff' } },
        { selector: 'edge', style: {
          width: 3, 'line-color': '#47556988', 'target-arrow-color': '#64748b',
          'target-arrow-shape': 'triangle', 'arrow-scale': .8, 'curve-style': 'bezier',
          label: 'data(label)', 'font-size': 8, color: '#94a3b8', 'text-rotation': 'autorotate',
          'text-background-color': '#090b12', 'text-background-opacity': .82, 'text-background-padding': 3,
        } },
        { selector: 'edge:selected', style: { width: 6, 'line-color': '#22d3ee', 'target-arrow-color': '#22d3ee', color: '#cffafe' } },
      ] as any,
      layout: { name: 'cose', animate: false, fit: true, padding: 56, nodeRepulsion: () => 200000, idealEdgeLength: () => 155, edgeElasticity: () => 80, gravity: .35, numIter: 1200 },
    })

    cy.on('tap', 'node', (event) => onSelect({ kind: 'node', data: event.target.data('original') as GraphNode }))
    cy.on('tap', 'edge', (event) => onSelect({ kind: 'edge', data: event.target.data('original') as GraphEdge }))
    cy.on('tap', (event) => { if (event.target === cy) onSelect(null) })
    const observer = new ResizeObserver(() => cy.resize())
    observer.observe(containerRef.current)
    cy.one('layoutstop', () => { cy.resize(); cy.fit(cy.elements(), 60) })
    requestAnimationFrame(() => { cy.resize(); cy.fit(cy.elements(), 60) })
    cyRef.current = cy
    return () => { observer.disconnect(); cy.destroy(); cyRef.current = null }
  }, [elements, onSelect])

  return <div className="graph-shell-v2"><div ref={containerRef} className="graph-canvas-v2" /><div className="graph-hint-v2">Cliquer sur un nœud pour ouvrir sa fiche · molette = zoom · glisser = déplacer</div></div>
}
