import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

from app.config import settings
from app.services.scanners.base import BaseScanner, ScannerRunResult
from app.services.scanners.common import finding, parse_json_output


class PipAuditScanner(BaseScanner):
    id = "pip_audit"
    name = "pip-audit"
    description = "Python 依赖漏洞扫描（requirements.txt / pyproject.toml）"
    category = "sca"
    install_hint = "pip install pip-audit"

    def _cmd(self, req_file: Path) -> list[str]:
        base = ["-m", "pip_audit", "-r", str(req_file), "--format", "json"]
        if shutil.which("pip-audit"):
            return ["pip-audit", "-r", str(req_file), "--format", "json"]
        return [sys.executable] + base

    async def is_available(self) -> bool:
        if shutil.which("pip-audit"):
            return True
        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, "-m", "pip_audit", "--version"],
                capture_output=True, timeout=10,
            )
            return proc.returncode == 0
        except Exception:
            return False

    def _find_requirements(self, project_path: Path) -> list[Path]:
        candidates = []
        for name in ("requirements.txt", "requirements-dev.txt", "requirements/base.txt"):
            p = project_path / name
            if p.is_file():
                candidates.append(p)
        if not candidates:
            for p in project_path.rglob("requirements*.txt"):
                if "node_modules" not in p.parts and ".venv" not in p.parts:
                    candidates.append(p)
        return candidates[:3]

    async def scan(self, project_path: Path) -> ScannerRunResult:
        req_files = self._find_requirements(project_path)
        if not req_files:
            return ScannerRunResult(scanner_id=self.id, skipped=True, skip_reason="未找到 requirements.txt")

        all_findings = []
        for req_file in req_files:
            def _run(rf=req_file):
                return subprocess.run(
                    self._cmd(rf),
                    capture_output=True, text=True,
                    encoding="utf-8", errors="replace",
                    timeout=settings.scanner_timeout,
                )

            proc = await asyncio.to_thread(_run)
            if proc.returncode not in (0, 1):
                continue

            data = parse_json_output(proc.stdout or "{}", self.id)
            if not isinstance(data, dict):
                continue

            for item in data.get("dependencies", []):
                vulns = item.get("vulns", [])
                pkg = item.get("name", "unknown")
                version = item.get("version", "")
                for vuln in vulns:
                    vid = vuln.get("id", "CVE-unknown")
                    fix_versions = vuln.get("fix_versions", [])
                    message = f"Python 依赖漏洞: {pkg}@{version} — {vid}"
                    if fix_versions:
                        message += f" (修复版本: {', '.join(fix_versions[:3])})"

                    all_findings.append(finding(
                        tool=self.id,
                        rule_id=f"pip.{vid}",
                        check_id=vid,
                        severity="HIGH",
                        message=message,
                        file_path=str(req_file),
                        line_start=0,
                        project_path=project_path,
                        metadata={
                            "package": pkg,
                            "version": version,
                            "fix_versions": fix_versions,
                            "description": vuln.get("description", "")[:500],
                        },
                    ))

        return ScannerRunResult(scanner_id=self.id, findings=all_findings)
