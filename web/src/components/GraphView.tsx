import { useEffect, useMemo, useRef } from 'react'
import cytoscape, { Core } from 'cytoscape'
import type { GraphEdge, GraphNode, SelectedItem } from '../types'

const COLORS: Record<string, string> = {
  email: '#a78bfa',
  phone: '#38bdf8',
  username: '#22d3ee',
  person: '#f472b6',
  address: '#fb7185',
  domain: '#34d399',
  ip: '#60a5fa',
  breach: '#fb7185',
  paste: '#f59e0b',
  stealer_domain: '#ef4444',
  gravatar: '#c084fc',
  rdap: '#14b8a6',
  socialaccount: '#8b5cf6',
  website: '#10b981',
}

function colorFor(type: string): string {
  return COLORS[type.toLowerCase()] || '#64748b'
}

function sizeFor(node: GraphNode): number {
  if (node.type === 'breach' || node.type === 'stealer_domain') return 64
  if (node.id.startsWith('target:')) return 76
  return Math.max(42, Math.min(58, 42 + node.risk / 8))
}

type Props = {
  nodes: GraphNode[]
  edges: GraphEdge[]
  onSelect: (item: SelectedItem) => void
}

export function GraphView({ nodes, edges, onSelect }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)

  const elements = useMemo(() => [
    ...nodes.map((node) => ({
      data: {
        id: node.id,
        label: node.label,
        nodeType: node.type,
        color: colorFor(node.type),
        size: sizeFor(node),
        risk: node.risk,
        original: node,
      },
    })),
    ...edges.map((edge) => ({
      data: {
        id: edge.id,
        source: edge.source,
        target: edge.target,
        label: edge.label,
        original: edge,
      },
    })),
  ], [nodes, edges])

  useEffect(() => {
    if (!containerRef.current) return
    cyRef.current?.destroy()

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      minZoom: 0.12,
      maxZoom: 4,
      wheelSensitivity: 0.16,
      boxSelectionEnabled: false,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            'width': 'data(size)',
            'height': 'data(size)',
            'label': 'data(label)',
            'font-family': 'Inter, ui-sans-serif, system-ui',
            'font-size': 11,
            'font-weight': 600,
            'color': '#e5e7eb',
            'text-wrap': 'ellipsis',
            'text-max-width': 120,
            'text-valign': 'bottom',
            'text-margin-y': 10,
            'text-background-color': '#090d16',
            'text-background-opacity': 0.82,
            'text-background-padding': 4,
            'border-width': 2,
            'border-color': '#ffffff22',
            'overlay-opacity': 0,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 5,
            'border-color': '#f8fafc',
            'shadow-blur': 28,
            'shadow-color': 'data(color)',
            'shadow-opacity': 0.9,
          },
        },
        {
          selector: 'edge',
          style: {
            'width': 4,
            'line-color': '#64748b88',
            'target-arrow-color': '#94a3b8',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.85,
            'curve-style': 'bezier',
            'label': 'data(label)',
            'font-size': 9,
            'color': '#94a3b8',
            'text-rotation': 'autorotate',
            'text-background-color': '#070b14',
            'text-background-opacity': 0.75,
            'text-background-padding': 2,
          },
        },
        {
          selector: 'edge:selected',
          style: {
            'width': 8,
            'line-color': '#f97316',
            'target-arrow-color': '#f97316',
            'color': '#fed7aa',
          },
        },
      ] as any,
      layout: {
        name: 'cose',
        animate: false,
        fit: true,
        padding: 50,
        nodeRepulsion: () => 180000,
        idealEdgeLength: () => 150,
        edgeElasticity: () => 80,
        gravity: 0.4,
        numIter: 1200,
      },
    })

    cy.on('tap', 'node', (event) => {
      const original = event.target.data('original') as GraphNode
      onSelect({ kind: 'node', data: original })
    })
    cy.on('tap', 'edge', (event) => {
      const original = event.target.data('original') as GraphEdge
      onSelect({ kind: 'edge', data: original })
    })
    cy.on('tap', (event) => {
      if (event.target === cy) onSelect(null)
    })

    const observer = new ResizeObserver(() => {
      cy.resize()
    })
    observer.observe(containerRef.current)
    cy.one('layoutstop', () => {
      cy.resize()
      cy.fit(cy.elements(), 56)
    })
    requestAnimationFrame(() => {
      cy.resize()
      cy.fit(cy.elements(), 56)
    })
    cyRef.current = cy

    return () => {
      observer.disconnect()
      cy.destroy()
      cyRef.current = null
    }
  }, [elements, onSelect])

  return (
    <div className="graph-shell">
      <div ref={containerRef} className="graph-canvas" />
      <div className="graph-hint">Click nodes or links • Scroll to zoom • Drag to pan</div>
    </div>
  )
}
