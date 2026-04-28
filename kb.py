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
        with self._connect() as conn:
            for t in templates:
                conn.execute(
                    """
                    INSERT OR IGNORE INTO task_templates (name, description, category, enabled)
                    VALUES (?, ?, ?, 1)
                    """,
                    (t['name'], t['description'], t['category']),
                )
            conn.commit()

    def list_templates(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, name, description, category, enabled FROM task_templates WHERE enabled=1"
            ).featchall()
            return [dict(r) for r in rows]

    def _template_id(self, template_name: str) -> int:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT id FROM task_templates WHERE name=? and enabled=1", (template_name,)
            ).fetchone()
            if row is None:
                raise ValueError(f'Unknown or disabled template: {template_name}')
            return int(row['id'])

    def create_run(
        self,
        template_name: str,
        params: Dict[str, Any],
        requested_by: str='cli',
        parent_run_id: Optional[int] = None,
        command_preview: Optional[str] = None,
    ) -> int:
        template_id = self._template_id(template_name)
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO task_runs
                (template_id, status, requested_by, parent_run_id, params_json, command_preview)
                VALUES (?, 'PENDING', ?, ?, ?, ?)
                """,
                (template_id, requested_by, parent_run_id, json.dumps(params), command_preview),
            )
            conn.commit()
            return int(cur.lastrowid)

    def get_new_pending_run(self) -> Optional[int]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT id FROM task_runs
                WHERE status='PENDING'
                ORDER BY created_at ASC, id ASC
                LIMIT 1
                """
            ).fetchone()
            return int(row['id']) if row else None

    def any_running(self) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM task_runs WHERE status='RUNNING' LIMIT1"
            ).fetchone()
            return row is not None

    def claim_run(self, run_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                """
                UPDATE task_runs
                SET status='RUNNING', started_at=datetime('now')
                WHERE id=? AND status='PENDING'
                """,
                (run_id,),
            )
            conn.commit()
            return cur.rowcount == 1

    def set_run_status(
        self,
        run_id: int,
        status: str,
        exit_code: Optional[int] = None,
        error_summary: Optional[str] = None,
        finished: bool = False,
    ) -> None:
        with self._connect() as conn:
            if finished:
                conn.execute(
                    """
                    UPDATE task_runs
                    SET status=?, finished_at=datetime('now'), exit_code=?, error_summary=?
                    WHERE id=?
                    """,
                    (status, exit_code, error_summary, run_id),
                )
            else:
                conn.execute(
                    """
                    UPDATE task_runs
                    SET status=?, exit_code=COALESCE(?, exit_code), error_summary=COALESCE(?, error_summary)
                    WHERE id=?
                    """,
                    (status, exit_code, error_summary, run_id),
                )
            conn.commit()

    def get_run(self, run_id: int) -> RunRow:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT tr.id, tt.name as template, tr.status, tr.created_at, tr.started_at, tr.finished_at,
                       tr.parent_run_id, tr.params_json, tr.exit_code, tr.error_summary
                FROM task_runs tr
                JOIN task_templates tt ON tt.id = tr.template_id
                WHERE tr.id=?
                """,
                (run_id,),
            ).fetchone()
            if row is None:
                raise ValueError(f'Run not found: {run_id}')
            return RunRow(
                id=int(row['id']),
                template=row['template'],
                status=row['status'],
                created_at=row['created_at'],
                started_at=row['started_at'],
                finished_at=row['finished_at'],
                parent_run_id=row['parent_run_id'],
                params=json.loads(row['params_json']),
                exit_code=row['exit_code'],
                error_summary=row['error_summary'],
            )

    def list_runs(self, limit: int = 50) -> List[RunRow]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT tr.id, tt.name as template, tr.status, tr.created_at, tr.started_at, tr.finished_at,
                       tr.parent_run_id, tr.params_json, tr.exit_code, tr.error_summary
                FROM task_runs tr
                JOIN task_templates tt ON tt.id = tr.template_id
                ORDER BY tr.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            out: List[RowRun] = []
            for r in rows:
                out.append(
                    RunRow(
                        id=int(row['id']),
                        template=row['template'],
                        status=row['status'],
                        created_at=row['created_at'],
                        started_at=row['started_at'],
                        finished_at=row['finished_at'],
                        parent_run_id=row['parent_run_id'],
                        params=json.loads(row['params_json']),
                        exit_code=row['exit_code'],
                        error_summary=row['error_summary'],
                    )
                )
            return out

    # Artifacts
    def write_artifact_text(self, run_id: int, kind: str, text: str, filename: str) -> str:
        run_dir = self.artifacts_dir / f'run_{run_id:04d}'
        run_dir.mkdir(parents=True, exists_ok=True)
        path = run_dir / filename
        path.write_text(text, encoding='utf-8')
        rel = str(path.relative_to(self.workspace))
        
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO artifacts (run_id, kind, path, bytes, mime)
                VALUES (?, ?, ?, ?, ?)
                """,
                (run_id, kind, rel, path.stat().st_size, "text/plain"),
            )
            conn.commit()
        return rel

    # Facts & Events
    def insert_facts(self, run_id: Optional[int], facts: Iterable[Dict[str, Any]]) -> None:
        sql = """
        INSERT OR IGNORE INTO facts (run_id, fact_type, key, value, confidence)
        VALUES (?, ?, ?, ?, ?)
        """
        rows = []
        for f in facts:
            rows.append(
                (
                    run_id,
                    f['fact_type'],
                    f['key'],
                    f.get('value'),
                    float(f.get('confidence', 1.0)),
                )
            )
            
        with self._connect() as conn:
            conn.executemany(sql, rows)
            conn.commit()

    def add_event(self, run_id: Optional[int], level: str, message: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events (run_id, level, message) VALUES (?, ?, ?)",
                (run_id, level, message),
            )
            conn.commit()

    def list_events_since(self, last_id: int = 0, limit = 100) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, run_id, level, message
                FROM events
                WHERE id > ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (last_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def list_facts(self) -> List[FactRow]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, run_id, fact_type, key, value, confidence
                FROM facts
                ORDER BY id ASC
                """
            ).fetchall()
            return [
                FactRow(
                    id=int(r['id']),
                    created_at=r['created_at'],
                    fact_type=r['fact_type'],
                    key=r['key'],
                    value=r['value'],
                    confidence=float(r['confidence']),
                )
                for r in rows
            ]

    # Queries used by rules.py
    def get_open_ports(self) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT key FROM facts WHERE fact_type='open_port' AND value='open' ORDER BY key"
            ).fetchall()
            return [r['key'] for r in rows]

    def get_services(self) -> Dict[str, str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT key, value FROM facts WHERE fact_type='service' AND value IS NOT NULL"
            ).fetchall()
            return {r['key']: str(r['value']).lower() for r in rows}

    def has_fact(self, fact_type: str, key: str, value: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT 1 FROM facts
                WHERE fact_type=? AND key=? AND value=?
                LIMIT 1
                """,
                (fact_type, key, value),
            ).fetchone()
            return raw is not None

    def add_note_fact(self, run_id: Optional[int], text: str) -> None:
        self.insert_facts(run_id, [
            {"fact_type": "note", 'key': 'user.note', 'value': text, 'confidence': 1.0}
        ])

    def list_artifacts(self, run_id: int) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, kind, path, bytes, mime
                FROM artifacts
                WHERE run_id=?
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def read_artifact_text(self, rel_path: str, max_bytes: Optional[int] = None) -> str:
        p = (self.workspace / rel_path).resolve()
        if not str(p).startswith(str(self.workspace.resolve())):
            raise ValueError('Invalid artifact path')
        data = p.read_bytes()
        if max_bytes is not None:
            data = data[:max_bytes]
        return data.decode('utf-8', errors='replace')

    def read_artifact_by_id(self, artifact_id: int, max_bytes: Optional[int] = None) -> str:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT path FROM artifacts WHERE id=?",
                (artifact_id,),
            ).fetchone()
            if row is None:
                raise ValueError('Artifact not found')
            return self.read_artifact_text(row['path'], max_bytes=max_bytes)

    def tail_artifact(self, rel_path: str, n_lines: int = 80) -> str:
        text = self.read_artifact_text(rel_path)
        lines = text.splitlines()
        return '\n'.join(lines[-n_lines:])
