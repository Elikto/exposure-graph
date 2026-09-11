# ExposureGraph

ExposureGraph is a local-first self-OSINT and exposure-monitoring web app built around an interactive graph.

It is designed for identifiers you own or are explicitly authorized to assess. The app correlates public OSINT and legitimate breach/threat-intelligence sources, preserves provenance, and makes both nodes and relationships clickable.

## Current capabilities

- React + Cytoscape interactive graph with clickable nodes and edges
- FastAPI backend and local SQLite history
- Search by email, phone, username, domain, IP, person name or postal address
- Multiple monitored email identities
- Exposure/breach timeline and per-source status
- Gravatar, RDAP, Certificate Transparency and urlscan.io connectors
- Have I Been Pwned connector when an HIBP API key is available
- VirusTotal and Shodan connectors ready for optional API keys
- Local Flowsint bridge with password-safe login from the localhost UI
- Flowsint graph import plus access to local enrichers such as Maigret, Sherlock and Holehe
- Docker Compose deployment bound to localhost for private local data

## Security model

The GitHub repository can be public, but `.env`, the SQLite database and local investigation data are ignored. The web UI is bound to `127.0.0.1`. Flowsint credentials are submitted only from the local browser to the local API; the password is never stored, only the temporary Flowsint access token.

ExposureGraph does not retrieve raw stolen passwords or directly connect to criminal credential dumps. Breach and stealer intelligence is limited to legitimate providers and the user's verified notifications.

## Run locally

```bash
cp .env.example .env
docker compose up -d --build
```

Open `http://localhost:5180`. Add the identifiers you own, then connect the local Flowsint instance from the **Flowsint bridge** panel to unlock its installed enrichers without putting your password in Git or chat.

## Privacy cleanup

- The right-hand panel summarizes personal attributes actually returned by configured sources (display name, username, phone, postal address/location and public avatars).
- Detected profile sites are listed next to the graph with clickable profile links.
- Removal actions prefer current official account/privacy pages for major services, then the open-source JustDeleteMe directory; uncatalogued sites get an independent privacy-request fallback.
- Username-only matches remain candidates and must not be treated as confirmed account ownership without corroborating evidence.
