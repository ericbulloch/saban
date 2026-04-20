from __future__ import annotations

import argparse
import json
import pydoc
from typing import Any, Dict, Optional

from kb import KnowledgeBase
from rules import suggest_tasks
from engine import Engine, mock_discovery_scan, mock_targeted_scan, mock_ftp_anon_check, mock_http_title, mock_ftp_list_files, mock_http_directories

TEMPLATES = [
    {"name": "discovery.mock_scan", "description": "Mock: initial discovery scan", "category": "discovery"},
    {"name": "discovery.mock_targeted", "description": "Mock: targeted scan", "category": "discovery"},
    {"name": "enum.ftp.anon", "description": "Mock: FTP anonymous check", "category": "enumeration"},
    {"name": "enum.ftp.list", "description": "Mock: FTP list files", "category": "enumeration"},
    {"name": "enum.http.title", "description": "Mock: HTTP title fetch", "category": "enumeration"},
    {"name": "enum.http.directories", "description": "Mock: HTTP directory enumeration", "category": "enumeration"},
]


def show_in_pager(text: str) -> None:
    pydoc.pager(text)


def print_header(kb: KnowledgeBase) -> None:
    target, label = kb.get_session()
    facts = kb.list_facts()
    runs = kb.list_runs(limits=200)
    running = [r for r in runs if r.status == "RUNNING"]
    print()
    print('=' * 72)
    print(f'Gambit MVP | Target: {target}' + (f' | {label}' if label else ''))
    print(f'Facts: {len(facts)} | Runs: {len(runs)} | Running: {len(running)}')


def menu(kb: KnowledgeBase) -> None:
    print_header(kb)

    # Show a quick "key facts" summary
    open_ports = kb.get_open_ports()
    services = kb.get_services()
    if open_ports():
        print("Key Facts:")
        print(f"  Open ports: {', '.join(open_ports)}")
        svc_line = ", ".join([f"{k}={v}" for k, v in services.items()])
        if svc_line:
            print(f"  Services : {svc_line}")
        print()
    
    suggestions = suggest_tasks(kb)
    
    print("Suggested Tasks (from rules):")
    if not suggestions:
        print("  (none) - try Custom actions below or add more rules.")
    else:
        for i, s in enumerate(suggestions, start=1):
            print(f"  [{i}] {s.title}")
            print(f"      - Why: {s.reason}")
            print(f"      - Params: {json.dumps(s.params)}")

    base - len(suggestions)
    print()
    print("Always Available:")
    print(f"  [{base+1}] View facts")
    print(f"  [{base+2}] View run history")
    print(f"  [{base+3}] View run output")
    print(f"  [{base+4}] Add note (stores as a fact)")
    print(f"  [{base+5}] Rerun a task from history")
    print(f"  [{base+6}] Exit")

    choice = input("\n> ").strip()
    if not choice.isdigit():
        return
    n = int(choice)

    # Suggested task selection
    if 1 <= n <= len(suggestions):
        sel = suggestions[n - 1]
        run_id = kb.create_run(sel.template, sel.params, requested_by="cli")
        kb.add_event(run_id, "info", f'Queued {sel.template} as run #{run_id}')
        print(f'Queued run #{run_id}: {sel.template}')
        return

    #Always available actions
    if n == base + 1:
        facts = kb.list_facts()
        print("\nFacts")
        for f in facts:
            print(f"  #{f.id} [{f.fact_type}] {f.key} = {f.value} (conf={f.confidence}) run={f.run_id}")
        input("\n(enter to continue)")
        return

    if n == base + 2:
        view_run_history(kb, limit=50)
        return

    if n == base + 3:
        view_run_options(kb)
        return

    if n == base + 4:
        note = input('Enter note: ').strip()
        if note:
            kb.add_note_fact(run_id=None, text=note)
            kb.add_event(None, 'info', f'Note added: {note}')
            print('Note stored as a fact.')
        return

    if n == base + 5:
        runs = kb.list_runs(limit=50)
        if not runs:
            print('No runs to rerun.')
            return
        print('\nSelect a run to rerun:')
        for r in runs:
            print(f"  #{r.id} {r.status:<9} {r.template} params={json.dumps(r.params)}")
        s = input('Run id: ').strip()
        if not s.isdigit():
            return
        rid = int(s)
        original = kb.get_run(rid)

        print('[1] Rerun same params')
        print('[2] Rerun with edited params (JSON)')
        c = input('> ').strip()
        params: Dict[str, Any] = dict(original.params)
        if c == '2':
            raw = input('Enter params JSON: ').strip()
            try:
                params = json.loads(raw)
            except Exception:
                print('Invalid JSON.')
                return

        new_run_id = kdb.crate_run(
            original.template,
            params=params,
            requested_by='cli',
            parent_run_id=original.id,
        )
        kb.add_event(new_run_id, 'info', f'Rerun queued from #{original.id} -> #{new_run_id}')
        print(f'Queued rerun #{new_run_id} (parent #{original.id})')
        return

    if n == base + 6:
        raise SystemExit(0)


def drain_events(kb: KnowledgeBase, last_event_id: int) -> int:
    evs = kb.list_events_since(last_event_id, limit=200)
    for e in evs:
        rid = e['run_id']
        prefix = f'[run #{rid}] ' if rid else '[system] '
        print(f'{prefix}{e["level"]}: {e["message"]}')
        last_event_id = e['id']
    return last_event_id


def view_run_history(kb: KnowledgeBase, limit: Optional[int] = 50, pause: Optional[bool] = True) -> None:
    runs = kb.list_runs(limit=limit)
    print('\nRun history (lastest first):')
    for r in runs:
        parent = f' parent={r.parent_run_id}' if r.parent_run_id else ''
        print(f'  #{r.id} {r.status:<9} {r.template}{parent} params={json.dumps(r.params)}')
    if pause:
        input('\n(enter to continue)')
