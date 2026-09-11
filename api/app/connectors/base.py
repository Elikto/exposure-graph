from dataclasses import dataclass, field
from typing import Protocol
from app.models import GraphNode, GraphEdge, BreachRecord, SourceRun


@dataclass
class ConnectorResult:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    breaches: list[BreachRecord] = field(default_factory=list)
    run: SourceRun | None = None


class Connector(Protocol):
    name: str

    async def run(self, query: str, kind: str, root_id: str) -> ConnectorResult:
        ...
