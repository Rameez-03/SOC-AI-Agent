from __future__ import annotations
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Shared data models
# ---------------------------------------------------------------------------

@dataclass
class IOC:
    type: str   # ip | domain | hash | url | email | filename
    value: str


@dataclass
class Observable:
    id: str
    type: str
    value: str
    tags: list[str] = field(default_factory=list)


@dataclass
class Alert:
    id: str
    title: str
    severity: int           # 1-4
    timestamp: datetime
    source: str             # e.g. "Wazuh"
    rule_id: Optional[str] = None
    rule_level: Optional[int] = None
    agent_name: Optional[str] = None
    agent_ip: Optional[str] = None
    description: str = ""
    mitre_ids: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class LogEntry:
    id: str
    timestamp: datetime
    rule_id: Optional[str] = None
    rule_name: Optional[str] = None
    rule_level: Optional[int] = None
    agent_name: Optional[str] = None
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    process: Optional[str] = None
    command_line: Optional[str] = None
    mitre_ids: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


@dataclass
class Case:
    id: str
    title: str
    severity: int           # 1-4
    status: str             # Open | InProgress | Resolved | Deleted
    created_at: datetime
    updated_at: datetime
    description: str = ""
    tags: list[str] = field(default_factory=list)
    observables: list[Observable] = field(default_factory=list)
    source: str = ""        # e.g. "Wazuh"
    source_ref: str = ""    # original alert sourceRef


@dataclass
class CaseUpdate:
    status: Optional[str] = None        # Open | InProgress | Resolved
    severity: Optional[int] = None      # 1-4
    tags_to_add: list[str] = field(default_factory=list)


@dataclass
class EnrichmentResult:
    ioc: IOC
    source: str             # virustotal | abuseipdb | abuse_finder | cortex
    verdict: str            # clean | malicious | suspicious | unknown
    score: Optional[int] = None     # 0-100 where available
    details: dict = field(default_factory=dict)


@dataclass
class WorkflowResult:
    success: bool
    workflow_name: str
    response: dict = field(default_factory=dict)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# Abstract connector interfaces
# ---------------------------------------------------------------------------

class SIEMConnector(ABC):
    """Reads alerts and raw logs from a SIEM."""

    @abstractmethod
    async def get_alerts(
        self,
        limit: int = 100,
        min_level: int = 3,
        hours_back: int = 24,
    ) -> list[Alert]: ...

    @abstractmethod
    async def get_logs_for_case(
        self,
        case: Case,
        hours_back: int = 24,
    ) -> list[LogEntry]: ...

    @abstractmethod
    async def is_available(self) -> bool: ...

    @property
    @abstractmethod
    def name(self) -> str: ...


class CaseConnector(ABC):
    """Reads and writes cases in a case management platform."""

    @abstractmethod
    async def get_open_cases(self) -> list[Case]: ...

    @abstractmethod
    async def get_case(self, case_id: str) -> Case: ...

    @abstractmethod
    async def add_note(self, case_id: str, note: str) -> None: ...

    @abstractmethod
    async def update_case(self, case_id: str, update: CaseUpdate) -> None: ...

    @abstractmethod
    async def close_case(self, case_id: str, resolution: str) -> None: ...

    @abstractmethod
    async def is_available(self) -> bool: ...

    @property
    @abstractmethod
    def name(self) -> str: ...


class EnrichmentConnector(ABC):
    """Enriches IOCs via threat intelligence."""

    @abstractmethod
    async def enrich(self, ioc: IOC) -> EnrichmentResult: ...

    @abstractmethod
    async def is_available(self) -> bool: ...

    @property
    @abstractmethod
    def name(self) -> str: ...


class SOARConnector(ABC):
    """Triggers automated response workflows."""

    @abstractmethod
    async def trigger(self, action: str, payload: dict) -> WorkflowResult: ...

    @abstractmethod
    async def is_available(self) -> bool: ...

    @property
    @abstractmethod
    def name(self) -> str: ...
