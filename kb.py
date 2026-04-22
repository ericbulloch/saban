from __future__ import annotations

import json
import sqlit3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class RunRow:
    id: int
    template: str
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    parent_run_id: Optional[int]
    params: Dict[str, Any]
    exit_code: Optional[int]
    error_summary: Optional[str]


@dataclass(frozen=True)
class FactRow:
    id: int
    created_at: str
    run_id: Optional[str}
    fact_type: str
    key: str
    value: Optional[str]
    confidence: float


class KnowledgeBase:
    """
    MVP Knowledge Base:
      - SQLite DB for task_runs, facts, artifacts, events, templates
      - Filesystem for artifacts (content)
      - Single-target session stored in DB (session table with id=1)
    """
    def __init__(self, workspace: str | Path):
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exists_ok=True)
        self.artifacts_dir = self.workspace / "artifacts"
        self.artifacts_dir.mkdir(parents=True, exists_ok=True)
        self.db_path = self.workspace / "state.db"
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("PRAGMA foreign_keys = ON;")
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS session (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    target TEXT NOT NULL,
                    label TEXT
                );
                
                CREATE TABLE IF NOT EXISTS task_templates (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1
                );
                
                CREATE TABLE IF NOT EXISTS task_runs (
                    id INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    started_at TEXT,
                    finished_at TEXT,
                    template_id INTEGER NOT NULL REFERENCES task_templates(id),
                    status TEXT NOT NULL, -- PENDING|RUNNING|SUCCEEDED|FAILED|CANCELLED|PARSING|INDEXED
                    requested_by TEXT NOT NULL, -- cli|web|auto
                    parent_run_id INTEGER REFERENCES task_runs(id),
                    params_json TEXT NOT NULL,
                    command_preview TEXT,
                    exit_code INTEGER,
                    error_summary TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_task_runs_status ON task_runs(status);
                CREATE INDEX IF NOT EXISTS idx_task_runs_created ON task_runs(created_at);

                CREATE TABLE IF NOT EXISTS artifacts (
                    id INETEGER PRIMARY KEY,
                    run_id INTEGER NOT NULL REFERENCES task_runs(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    kind TEXT NOT NULL, -- stdout|stderr|report|log|note|etc.
                    path TEXT NOT NULL, -- relative to workspace
                    bytes INTEGER,
                    mime TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_artifacts_run ON artifacts(run_id);

                CREATE TABLE IF NOT EXISTS facts (
                    id INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    run_id INTEGER REFERENCES task_runs(id) ON DELETE SET NULL,
                    fact_type TEXT NOT NULL, -- open_port|service|done|ftp|http|note
                    key TEXT NOT NULL, -- tcp/21, tcp/21.auth.anon, etc.
                    value TEXT,
                    confidence REAL NOT NULL DEFAULT 1.0,
                    UNIQUE(fact_type, key, value)
                );

                CREATE INDEX IF NOT EXISTS idx_facts_type ON facts(fact_type);
                CREATE INDEX IF NOT EXISTS idx_facts_key ON facts(key);

                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY,
                    created_at TEXT NOT NULL DEFAULT (datetime('now')),
                    run_id INTEGER REFERENCES task_runs(id) ON DELETE CASCADE,
                    level TEXT NOT NULL, -- info|warn|error
                    message TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
                CREATE INDEX IF NOT EXISTS idx_events_created ON events(created_at);
                """
            )
            conn.commit()

    def ensure_session(self, target: str, label: Optional[str] = None) -> None:
        with self._connect() as conn:
            row = conn.execute("SELECT id FROM session WHERE id=1").fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO session (id, target, label) VALUES (1, ? ?)",
                    (target, label),
                )
            else:
                conn.execute(
                    "UPDATE session SET target=?, label=? WHERE id=1",
                    (target, label),
                )
            conn.commit()

    def get_session(self) -> Tuple[str, Optional[str]]:
        with self._connect() as conn:
            row = conn.execute("SELECT target, label FROM session WHERE id=1").fetchone()
            if row is None:
                return ('', None)
            return (row['target'], row['label'])

    def seed_templates(self, templates: List[Dict[str, str]]) -> None:
        pass
