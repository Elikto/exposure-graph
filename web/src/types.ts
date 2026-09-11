export type GraphNode = {
  id: string
  type: string
  label: string
  properties: Record<string, unknown>
  source: string
  confidence: number
  risk: number
}

export type GraphEdge = {
  id: string
  source: string
  target: string
  label: string
  properties: Record<string, unknown>
  source_name: string
  confidence: number
}

export type BreachRecord = {
  id: string
  name: string
  title: string
  domain?: string | null
  breach_date?: string | null
  added_date?: string | null
  data_classes: string[]
  description?: string | null
  pwn_count?: number | null
  verified?: boolean | null
  source: string
}

export type SourceRun = {
  name: string
  status: 'ok' | 'disabled' | 'needs_key' | 'error' | 'skipped'
  message: string
  duration_ms: number
}

export type SearchResponse = {
  search_id: string
  query: string
  kind: string
  created_at: string
  nodes: GraphNode[]
  edges: GraphEdge[]
  breaches: BreachRecord[]
  sources: SourceRun[]
  warnings: string[]
}

export type ConnectorStatus = {
  name: string
  configured: boolean
  category: string
  requires_key: boolean
  note: string
}

export type SelectedItem =
  | { kind: 'node'; data: GraphNode }
  | { kind: 'edge'; data: GraphEdge }
  | null
