from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from kb import KnowledgeBase


@dataclass
class Suggestion:
    template: str
    title: str
    reason: str
    params: Dict[str, Any]


def suggest_tasks(kb: KnowledgeBase) -> List[Suggestion]:
    suggestions: List[Suggestion] = []
    open_ports = kb.get_open_ports()
    services = kb.get_services()
    current_runs = [r for r in kb.list_runs() if r.status in ['RUNNING', 'PENDING']]

    # 1) New box: no facts -> discovery
    if not open_ports and not kb.has_fact('done', 'discovery.mock_scan', 'true') and not any(r.template == 'discovery.mock_scan' for r in current_runs):
        suggestions.append(Suggestion(
            template='discovery.mock_scan',
            title='Discovery (Mock): Quick scan',
            reason='No open ports discovered yet - run an initial discovery scan.',
            params={'profile': 'quick'},
        ))

    # 2) If we have open ports, suggest a targeted scan of discovered ports (mock)
    if open_ports and not kb.has_fact('done', 'discovery.mock_targeted', 'true') and not any(r.template == 'discovery.mock_targeted' for r in current_runs):
        suggestions.append(Suggestion(
            template='discovery.mock_targeted',
            title='Discovery (Mock): Targeted scan of discovered ports',
            reason=f"Open ports detected ({', '.join(open_ports)}) - gather more detail.",
            params={'ports': open_ports},
        ))

    # 3) Service-driven suggestions
    for key, service_type in services.items():
        port = key.split('/')[1]
        if service_type == 'ftp' and not kb.has_fact('done', f'enum.ftp.{port}.anon', 'true') and not any(r.template == f'enum.ftp.{port}.anon' for r in current_runs):
            suggestions.append(Suggestion(
                template='enum.ftp.anon',
                title='Enum (Mock): FTP anonymous login check',
                reason=f"FTP detected on tcp/{port} - check if anonymous login is allowed.",
                params={'port': int(port)},
            ))

        if service_type == 'http' and not kb.has_fact('done', f'enum.http.{port}.title', 'true') and not any(r.template == f'enum.http.{port}.title' for r in current_runs):
            suggestions.append(Suggestion(
                template='enum.http.anon',
                title='Enum (Mock): HTTP title fetch',
                reason=f"HTTP detected on tcp/{port} - fetch a simple page title (toy enum).",
                params={'port': int(port), 'path': '/'},
            ))

        # 4) Follow-on based on capability facts
        # Example: if FTP anonymous login is allowed, suggest listing files
        if kb.has_fact('ftp', f'tcp/{port}.auth.anon', 'allowed') and not kb.has_fact('done', f'enum.ftp.{port}.list', 'true') and not any(r.template == f'enum.ftp.{port}.list' for r in current_runs):
            suggestions.append(Suggestion(
                template='enum.ftp.list',
                title='Enum (Mock): FTP list files',
                reason="Anonymous FTP appears allowed - list files to look for flags or hints.",
                params={'port': int(port)},
            ))

        if service_type == 'http' and not kb.has_fact('done', f'enum.http.{port}.directories', 'true') and not any(r.template == f'enum.http.{port}.directories' for r in current_runs):
            suggestions.append(Suggestion(
                template='enum.http.directories',
                title='Enum (Mock): HTTP directories enumeration',
                reason=f"HTTP detected on tcp/{port} - enumerate directories (toy enum).",
                params={'port': int(port), 'path': '/'},
            ))
