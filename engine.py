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
