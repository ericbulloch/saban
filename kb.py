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
                """
            )
