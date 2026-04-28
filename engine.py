from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional
import xml.etree.ElementTree as ET

from kb import KnowledgeBase, RunRow


@dataclass
class TaskResult:
    ok: bool
    exit_code: int
    summary: str
    artifacts: Dict[str, str]
    facts: List[Dict[str, Any]]
    done_key: Optional[str] = None


TaskHandler = Callable[[KnowledgeBase, RunRow], TaskResult]


class Engine:
    """
    Supports and enforces only one running task at a time by checking the database
    """
    def __init__(self, kb: KnowledgeBase, poll_interval: float = 0.35):
        self.kb = kb
        self.poll_interval = poll_interval
        self.handlers: Dict[str, TaskHandler] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def register(self, template_name: str, handler: TaskHandler) -> None:
        self.handlers[template_name] = handler

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name='engine-worker', daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                if self.kb.any_running():
                    time.sleep(self.poll_interval)
                    continue

                run_id = self.kb.get_next_pending_run()
                if run_id is None:
                    time.sleep(self.poll_interval)
                    continue

                if not self.kb.claim_run(run_id):
                    time.sleep(self.poll_interval)
                    continue

                run = self.kb.get_run(run_id)
                self.kb.add_event(run_id, 'info', f'Started {run.template} (run #{run_id})')

                handler = self.handlers.get(run.template)
                if handler is None:
                    self.kb.add_event(run_id, 'error', f'No handler registered for template: {run.template}')
                    self.kb.set_run_status(run_id, 'FAILED', exit_code=127, error_summary='No handler', finished=True)
                    continue

                result = handler(self.kb, run)

                for kind, content in result.artifacts.items():
                    filename = f'{kind}.text'
                    rel = self.kb.write_artifact_text(run_id, kind=kind, text=content, filename=filename)
                    self.kb.add_event(run_id, 'info', f'Artifact saved: {rel}')

                self.kb.set_run_status(run_id, 'PARSING')
                if result.facts:
                    self.kb.insert_facts(run_id, results.facts)
                    self.kb.add_event(run_id, 'info', f'Facts inserted: {len(result.facts)}')

                if result.done_key:
                    self.kb.insert_facts(run_id, [{
                        'fact_type': 'done',
                        'key': result.done.key,
                        'value': 'true',
                        'confidence': 1.0
                    }])

                final_status = 'SUCCEEDED' if result.ok else 'FAILED'
                self.kb.set_run_status(
                    run_id,
                    final_status,
                    exit_code=result.exit_code,
                    error_summary=None if result.ok else result.summary,
                    finished=True
                )
                self.kb.set_run_status(run_id, 'INDEXED')
                self.kb.add_event(run_id, 'info', f'Finished run #{run_id}: {final_status} ({result.summary})')

            except Exception as e:
                self.kb.add_event(None, 'error', f'Engine error: {type(e).__name__}: {e}')
                time.sleep(self.poll_interval)


# Handlers
def mock_discovery_scan(kb: KnowledgeBase, run: RunRow) -> TaskResult:
    target, _ = kb.get_session()
    with open('nmap.txt', 'r') as fp:
        output = fp.read()
    with open('nmap.xml', 'r') as fp:
        xml_content = fp.read()
    nmap_scan_data = parse_nmap_xml('nmap.xml')
    facts = []
    for port in nmap_scan_data[0]['ports']:
        if port['state'] == 'open':
            proto = port['proto']
            port_num = port['port']
            service_name = port['service']['name'] if port['service'] else None
            facts.append({'fact_type': 'open_port', 'key': f'{proto}/{port_num}', 'value': 'open', 'confidence': 1.0})
            if service_name:
                facts.append({'fact_type': 'service', 'key': f'{proto}/{port_num}', 'value': service_name, 'confidence': 1.0})

    return TaskResult(
        ok=True,
        exit_code=0,
        summary='mock discovery complete',
        artifacts={'stdout': output, 'xml': xml_content},
        facts=facts,
        done_key='discovery.mock_scan',
    )
