import asyncio
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from app.config import settings
from app.services.scanners.base import BaseScanner, ScannerRunResult
from app.services.scanners.common import finding, read_code_snippet, resolve_file_path


class GitleaksScanner(BaseScanner):
    id = "gitleaks"
    name = "Gitleaks"
    description = "密钥与凭证泄露检测（API Key、密码、Token 等）"
    category = "secrets"
    install_hint = "https://github.com/gitleaks/gitleaks#installing  或 choco install gitleaks"

    async def is_available(self) -> bool:
        return shutil.which("gitleaks") is not None

    async def scan(self, project_path: Path) -> ScannerRunResult:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        cmd = [
            "gitleaks", "detect",
            "--source", str(project_path),
            "--no-git",
            "--report-format", "json",
            "--report-path", report_path,
        ]

        def _run():
            return subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace",
                timeout=settings.scanner_timeout,
            )

        proc = await asyncio.to_thread(_run)
        # gitleaks exit 1 = leaks found
        if proc.returncode not in (0, 1):
            Path(report_path).unlink(missing_ok=True)
            return ScannerRunResult(scanner_id=self.id, error=(proc.stderr or "gitleaks failed")[:2000])

        try:
            raw = Path(report_path).read_text(encoding="utf-8", errors="replace")
            Path(report_path).unlink(missing_ok=True)
            items = json.loads(raw) if raw.strip() else []
        except (json.JSONDecodeError, OSError) as exc:
            return ScannerRunResult(scanner_id=self.id, error=str(exc))

        if not isinstance(items, list):
            items = []

        findings = []
        for item in items:
            rel_file = item.get("File", item.get("file", ""))
            abs_path = resolve_file_path(project_path, rel_file)
            line_start = item.get("StartLine", item.get("startLine", 0))
            rule_id = item.get("RuleID", item.get("ruleID", "gitleaks-secret"))
            secret_preview = item.get("Secret", item.get("secret", ""))
            message = f"检测到潜在密钥泄露: {rule_id}"
            if secret_preview:
                message += f" (***{str(secret_preview)[-4:]})"

            findings.append(finding(
                tool=self.id,
                rule_id=f"gitleaks.{rule_id}",
                check_id=rule_id,
                severity="HIGH",
                message=message,
                file_path=str(abs_path),
                line_start=line_start,
                line_end=item.get("EndLine", item.get("endLine", line_start)),
                code_snippet=read_code_snippet(abs_path, line_start),
                metadata={"description": item.get("Description", item.get("description"))},
                project_path=project_path,
            ))

        return ScannerRunResult(scanner_id=self.id, findings=findings)
