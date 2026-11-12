import asyncio
import shutil
import subprocess
import sys
from pathlib import Path

from app.config import settings
from app.services.path_filters import bandit_exclude_args
from app.services.scanners.base import BaseScanner, ScannerRunResult
from app.services.scanners.common import finding, parse_json_output, read_code_snippet, resolve_file_path


class BanditScanner(BaseScanner):
    id = "bandit"
    name = "Bandit"
    description = "Python 专用安全 linter，检测常见漏洞模式"
    category = "sast"
    install_hint = "pip install bandit"

    def _cmd(self, project_path: Path) -> list[str]:
        base = (
            ["bandit", "-r", str(project_path), "-f", "json", "-q"]
            if shutil.which("bandit")
            else [sys.executable, "-m", "bandit", "-r", str(project_path), "-f", "json", "-q"]
        )
        return base + bandit_exclude_args()

    async def is_available(self) -> bool:
        if shutil.which("bandit"):
            return True
        try:
            proc = await asyncio.to_thread(
                subprocess.run,
                [sys.executable, "-m", "bandit", "--version"],
                capture_output=True, timeout=10,
            )
            return proc.returncode == 0
        except Exception:
            return False

    async def scan(self, project_path: Path) -> ScannerRunResult:
        py_files = list(project_path.rglob("*.py"))
        if not py_files:
            return ScannerRunResult(scanner_id=self.id, skipped=True, skip_reason="项目中无 Python 文件")

        def _run():
            return subprocess.run(
                self._cmd(project_path),
                capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=settings.scanner_timeout,
            )

        proc = await asyncio.to_thread(_run)
        if proc.returncode not in (0, 1):
            return ScannerRunResult(scanner_id=self.id, error=(proc.stderr or "bandit failed")[:2000])

        data = parse_json_output(proc.stdout or "{}", self.id)
        if not isinstance(data, dict):
            data = {}

        findings = []
        for item in data.get("results", []):
            abs_path = resolve_file_path(project_path, item.get("filename", ""))
            line_start = item.get("line_number", 0)
            test_id = item.get("test_id", "bandit")
            findings.append(finding(
                tool=self.id,
                rule_id=f"bandit.{test_id}",
                check_id=test_id,
                severity=item.get("issue_severity", "MEDIUM"),
                message=item.get("issue_text", "Bandit security issue"),
                file_path=str(abs_path),
                line_start=line_start,
                code_snippet=read_code_snippet(abs_path, line_start),
                metadata={"test_name": item.get("test_name"), "confidence": item.get("issue_confidence")},
                project_path=project_path,
            ))

        metrics = data.get("metrics", {})
        return ScannerRunResult(
            scanner_id=self.id,
            version=str(metrics.get("_totals", {}).get("nosec", "")) or None,
            findings=findings,
        )
