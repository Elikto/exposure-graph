import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from app.config import settings
from app.models import SearchResponse


def _connect() -> sqlite3.Connection:
    path: Path = settings.db_path
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS searches (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                query TEXT NOT NULL,
                kind TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS monitored_identities (
                id TEXT PRIMARY KEY,
                value TEXT NOT NULL UNIQUE,
                kind TEXT NOT NULL,
                label TEXT,
                owned_or_authorized INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS integrations (
                provider TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.commit()


def save_search(result: SearchResponse) -> None:
    payload = json.dumps(result.model_dump(mode="json"), ensure_ascii=False)
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO searches (id, created_at, query, kind, payload) VALUES (?, ?, ?, ?, ?)",
            (result.search_id, result.created_at.isoformat(), result.query, result.kind, payload),
        )
        conn.commit()


def list_searches(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, created_at, query, kind FROM searches ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def get_search(search_id: str) -> SearchResponse | None:
    with _connect() as conn:
        row = conn.execute("SELECT payload FROM searches WHERE id = ?", (search_id,)).fetchone()
    if not row:
        return None
    return SearchResponse.model_validate(json.loads(row["payload"]))


def list_monitored_identities() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT id, value, kind, label, owned_or_authorized, created_at, enabled "
            "FROM monitored_identities ORDER BY created_at DESC"
        ).fetchall()
    return [
        {
            **dict(row),
            "owned_or_authorized": bool(row["owned_or_authorized"]),
            "enabled": bool(row["enabled"]),
        }
        for row in rows
    ]

def add_monitored_identity(value: str, kind: str, label: str | None, owned: bool) -> dict:
    item_id = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        conn.execute(
            "INSERT INTO monitored_identities "
            "(id, value, kind, label, owned_or_authorized, created_at, enabled) VALUES (?, ?, ?, ?, ?, ?, 1)",
            (item_id, value, kind, label, int(owned), created_at),
        )
        conn.commit()
    return {
        "id": item_id,
        "value": value,
        "kind": kind,
        "label": label,
        "owned_or_authorized": owned,
        "created_at": created_at,
        "enabled": True,
    }


def delete_monitored_identity(identity_id: str) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM monitored_identities WHERE id = ?", (identity_id,))
        conn.commit()
    return cur.rowcount > 0


def set_integration(provider: str, payload: dict) -> None:
    updated_at = datetime.now(timezone.utc).isoformat()
    encoded = json.dumps(payload, ensure_ascii=False)
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO integrations (provider, payload, updated_at) VALUES (?, ?, ?)",
            (provider, encoded, updated_at),
        )
        conn.commit()


def get_integration(provider: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT payload, updated_at FROM integrations WHERE provider = ?",
            (provider,),
        ).fetchone()
    if not row:
        return None
    payload = json.loads(row["payload"])
    payload["updated_at"] = row["updated_at"]
    return payload


def delete_integration(provider: str) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM integrations WHERE provider = ?", (provider,))
        conn.commit()
    return cur.rowcount > 0
