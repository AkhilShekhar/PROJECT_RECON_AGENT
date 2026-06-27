"""SQLite repository for persisting recon findings across sessions."""
import json
import sqlite3
from datetime import datetime, timezone

DB_FILE = "recon.db"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # rows behave like dicts: row["column"]
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS targets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                domain     TEXT UNIQUE NOT NULL,
                first_seen TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                target_id  INTEGER NOT NULL REFERENCES targets(id),
                tool_name  TEXT NOT NULL,
                data       TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
        """)


def _get_or_create_target(conn: sqlite3.Connection, domain: str) -> int:
    row = conn.execute("SELECT id FROM targets WHERE domain = ?", (domain,)).fetchone()
    if row:
        return row["id"]
    cur = conn.execute(
        "INSERT INTO targets (domain, first_seen) VALUES (?, ?)",
        (domain, _now()),
    )
    return cur.lastrowid


def save_finding(domain: str, tool_name: str, data: dict) -> None:
    with _connect() as conn:
        target_id = _get_or_create_target(conn, domain)
        conn.execute(
            "INSERT INTO findings (target_id, tool_name, data, created_at) VALUES (?, ?, ?, ?)",
            (target_id, tool_name, json.dumps(data), _now()),
        )


def get_findings(domain: str, tool_name: str | None = None) -> list[dict]:
    query = """
        SELECT f.tool_name, f.data, f.created_at
        FROM findings f
        JOIN targets t ON f.target_id = t.id
        WHERE t.domain = ?
    """
    params = [domain]
    if tool_name:
        query += " AND f.tool_name = ?"
        params.append(tool_name)
    query += " ORDER BY f.created_at DESC"

    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()

    return [
        {"tool": r["tool_name"], "data": json.loads(r["data"]), "at": r["created_at"]}
        for r in rows
    ]


def get_targets() -> list[str]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT domain FROM targets ORDER BY first_seen DESC"
        ).fetchall()
    return [r["domain"] for r in rows]


def query_findings(domain: str, tool_name: str = "") -> dict:
    """Tool-callable wrapper: returns the most recent result per tool for a domain."""
    rows = get_findings(domain, tool_name or None)
    if not rows:
        return {"success": False, "error": f"No findings for {domain!r} in the database"}

    # Keep only the most recent result per tool to avoid token bloat
    seen = {}
    for row in rows:
        if row["tool"] not in seen:
            seen[row["tool"]] = row

    return {
        "success": True,
        "data": {
            "domain": domain,
            "tools_run": list(seen.keys()),
            "findings": list(seen.values()),
        },
    }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()
