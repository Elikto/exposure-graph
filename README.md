# ExposureGraph

ExposureGraph is a local-first self-OSINT and exposure-monitoring web app built around an interactive graph.

It is designed for identifiers you own or are explicitly authorized to assess. The app correlates supported public OSINT and legitimate breach-intelligence sources, preserves provenance, and makes both nodes and relationships clickable.

## Current MVP

- React + Cytoscape interactive graph
- FastAPI backend
- Search by email, phone, username, domain, IP, person name or postal address
- Clickable nodes and edges with an inspector panel
- Exposure/breach timeline
- Search history stored locally in SQLite
- Gravatar, RDAP and Certificate Transparency connectors
- Have I Been Pwned connector (API key required)
- Flowsint graph connector (local token + sketch id required)
- Docker Compose deployment

## Run locally

```bash
cp .env.example .env
docker compose up -d --build
```

Open `http://localhost:5180`.
