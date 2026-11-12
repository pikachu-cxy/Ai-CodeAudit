from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScannerInfo:
    id: str
    name: str
    description: str
    category: str  # sast | secrets | sca
    install_hint: str
    available: bool = False
    enabled: bool = True
    supported_languages: list[str] = field(default_factory=list)
    setup_hint: str | None = None
    requires_build: bool = False
    availability_reason: str | None = None


@dataclass
class ScannerRunResult:
    scanner_id: str
    version: str | None = None
    findings: list[dict] = field(default_factory=list)
    detail: dict | None = None
    skipped: bool = False
    skip_reason: str | None = None
    error: str | None = None


class BaseScanner(ABC):
    id: str
    name: str
    description: str
    category: str = "sast"
    install_hint: str = ""
    supported_languages: list[str] = []
    setup_hint: str | None = None
    requires_build: bool = False

    @abstractmethod
    async def is_available(self) -> bool:
        ...

    @abstractmethod
    async def scan(self, project_path: Path) -> ScannerRunResult:
        ...

    def info(self, enabled: bool) -> ScannerInfo:
        return ScannerInfo(
            id=self.id,
            name=self.name,
            description=self.description,
            category=self.category,
            install_hint=self.install_hint,
            enabled=enabled,
            supported_languages=list(self.supported_languages),
            setup_hint=self.setup_hint,
            requires_build=self.requires_build,
        )

    async def availability_reason(self) -> str | None:
        return None

    async def timeout_seconds(self, project_path: Path) -> int:
        from app.config import settings

        return settings.scanner_timeout
