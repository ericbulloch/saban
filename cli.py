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
