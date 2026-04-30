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


def mock_targeted_scan(kb: KnowledgeBase, run: RunRow) -> TaskResult:
    ports = run.params.get('ports', [])
    output = '[mock-targeted] details:\n'
    facts: List[Dict[str, Any]] = []

    for p in ports:
        output += f'  {p}: service detail ok\n'

    if 'tcp/80' in ports:
        facts.append({'fact_type': 'http', 'key': f'tcp/80.title', 'value': 'Welcome', 'confidence': 0.8})
    return TaskResult(
        ok=True,
        exit_code=0,
        summary='mock targeted scan complete',
        artifacts={'stdout': output},
        facts=facts,
        done_key='discovery.mock_targeted',
    )


def mock_ftp_anon_check(kb: KnowledgeBase, run: RunRow) -> TaskResult:
    ports = run.params['port']
    allow = run.params.get('allow', True)
    status = 'allowed' if allow else 'denied'
    output = f'[mock-ftp-{port}] anonymous login {status}\n'
    facts: [
        {'fact_type': 'ftp', 'key': f'tcp/{port}.auth.anon', 'value': status, 'confidence': 1.0}
    ]
    return TaskResult(
        ok=True,
        exit_code=0,
        summary=f'anon {status}',
        artifacts={'stdout': output},
        facts=facts,
        done_key=f'enum.ftp.{port}.anon',
    )


def mock_http_title(kb: KnowledgeBase, run: RunRow) -> TaskResult:
    ports = run.params['port']
    allow = run.params.get('path', '/')
    title = 'Welcome' if port == 80 else 'Developer Site'
    status = 'allowed' if allow else 'denied'
    output = f"[mock-http-{port}] GET {path} -> title='{title}'\n"
    facts: [
        {'fact_type': 'http', 'key': f'tcp/{port}.title', 'value': title, 'confidence': 0.9}
    ]
    return TaskResult(
        ok=True,
        exit_code=0,
        summary='title fetched',
        artifacts={'stdout': output},
        facts=facts,
        done_key=f'enum.http.{port}.title',
    )


def mock_ftp_list_files(kb: KnowledgeBase, run: RunRow) -> TaskResult:
    ports = run.params['port']
    output = f'[mock-ftp-{port}] LIST\n  flag.txt\n  readme.md\n'
    facts: [
        {'fact_type': 'ftp', 'key': f'tcp/{port}.anon.files', 'value': 'flag.txt,readme.md', 'confidence': 0.8}
    ]
    return TaskResult(
        ok=True,
        exit_code=0,
        summary='listed files',
        artifacts={'stdout': output},
        facts=facts,
        done_key=f'enum.ftp.{port}.list',
    )


def mock_http_directories(kb: KnowledgeBase, run: RunRow) -> TaskResult:
    ports = run.params['port']
    output = f"[mock-http-{port}] Directories\n  /admin\n  /images\n  /js\n  /css\n  /dev\n  /contact-us"
    facts: [
        {'fact_type': 'http', 'key': f'tcp/{port}.directories', 'value': 'admin,images,js,css,dev,contact-us', 'confidence': 0.8}
    ]
    return TaskResult(
        ok=True,
        exit_code=0,
        summary='directories',
        artifacts={'stdout': output},
        facts=facts,
        done_key=f'enum.http.{port}.directories',
    )


#Parsers
def parse_nmap_xml(xml_path: str) -> List[Dict[str, Any]]:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    hosts_out: List[Dict[str, Any]] = []
    for host in root.findall('host'):
        status_el = host.find('status')
        status = status_el.get('state') if status_el is not None else None
        addresses = []
        for addr_el in host.findall('address'):
            addresses.append({
                'addr': addr_el.get('addr'),
                'addrtype': addr_el.get('addrtype'),
            })
        hostnames = []
        hostnames_el = host.find('hostnames')
        if hostnames_el is not None:
            for h in hostnames_el.findall('hostname'):
                name = h.get('name')
                if name:
                    hostnames.append(name)
        ports_out: List[Dict[str, Any]] = []
        ports_el = host.find('ports')
        if ports_el is not None:
            for port_el in ports_el.findall('port'):
                protocol = port_el.get('protocol')
                port_id = port_el.get('portid')
                try:
                    port_number = int(port_id) if port_id is not None else None
                except ValueError:
                    port_number = None
                state_el = port_el.find('state')
                state = state_el.get('state') if state_el is not None else None
                reason = state_el.get('reason') if state_el is not None else None
                service_el = port_el.find('service')
                service = {
                    'name': service_el.get('name') if service_el is not None else None,
                    'product': service_el.get('product') if service_el is not None else None,

                    'version': service_el.get('version') if service_el is not None else None,
                    'extra_info': service_el.get('extrainfo') if service_el is not None else None,
                    'tunnel': service_el.get('tunnel') if service_el is not None else None,
                    'os_type': service_el.get('ostype') if service_el is not None else None,
                    'method': service_el.get('method') if service_el is not None else None,
                    'confidence': service_el.get('conf') if service_el is not None else None,
                }
                scripts = []
                for script_el in port_el.findall('script'):
                    scripts.append({
                        'id': script_el.get('id'),
                        'output': script_el.get('output'),
                    })
                ports_out.append({
                    'protocol': protocol,
                    'port': port_number,
                    'state': state,
                    'reason': reason,
                    'service', service,
                    'scripts', scripts,
                })
        hosts_out.append({
            'status': status,
            'addresses': addresses,
            'hostnames': hostnames,
            'ports': ports_out'
        })
    return hosts_out
