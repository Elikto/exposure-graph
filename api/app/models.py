from datetime import datetime
from typing import Any, Literal
from pydantic import BaseModel, Field


SearchKind = Literal[
    "auto", "email", "domain", "ip", "username", "phone", "person", "address"
]


class SearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=500)
    kind: SearchKind = "auto"
    owned_or_authorized: bool = False


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)
    source: str = "local"
    confidence: float = 1.0
    risk: int = 0


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    properties: dict[str, Any] = Field(default_factory=dict)
    source_name: str = "local"
    confidence: float = 1.0


class BreachRecord(BaseModel):
    id: str
    name: str
    title: str
    domain: str | None = None
    breach_date: str | None = None
    added_date: str | None = None
    data_classes: list[str] = Field(default_factory=list)
    description: str | None = None
    pwn_count: int | None = None
    verified: bool | None = None
    source: str


class SourceRun(BaseModel):
    name: str
    status: Literal["ok", "disabled", "needs_key", "error", "skipped"]
    message: str = ""
    duration_ms: int = 0


class SearchResponse(BaseModel):
    search_id: str
    query: str
    kind: str
    created_at: datetime
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    breaches: list[BreachRecord] = Field(default_factory=list)
    sources: list[SourceRun] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ConnectorStatus(BaseModel):
    name: str
    configured: bool
    category: str
    requires_key: bool = False
    note: str = ""
