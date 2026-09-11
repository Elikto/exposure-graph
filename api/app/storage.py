import json
import sqlite3
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
