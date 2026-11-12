import asyncio
import subprocess
from pathlib import Path

from app.config import settings
from app.services.scanners.base import BaseScanner, ScannerRunResult
from app.services.scanners.common import finding, parse_json_output, resolve_npm_executable


class NpmAuditScanner(BaseScanner):
    id = "npm_audit"
    name = "npm audit"
    description = "Node.js 依赖漏洞扫描（package.json 项目）"
    category = "sca"
    install_hint = "安装 Node.js 即可使用内置 npm audit"

    async def is_available(self) -> bool:
        return resolve_npm_executable() is not None

    async def availability_reason(self) -> str | None:
        if await self.is_available():
            return None
        return "未检测到 npm（请安装 Node.js）"

    def _find_package_root(self, project_path: Path) -> Path | None:
        if (project_path / "package.json").is_file():
            return project_path
        for pkg in project_path.rglob("package.json"):
            if "node_modules" not in pkg.parts:
                return pkg.parent
        return None

    async def scan(self, project_path: Path) -> ScannerRunResult:
        pkg_root = self._find_package_root(project_path)
        if not pkg_root:
            return ScannerRunResult(scanner_id=self.id, skipped=True, skip_reason="未找到 package.json")

        npm = resolve_npm_executable()
        if not npm:
            return ScannerRunResult(
                scanner_id=self.id,
                skipped=True,
                skip_reason="未检测到 npm（请安装 Node.js）",
            )

        # Absolute path to npm.cmd/npm — works on Windows and Linux without shell=True.
        cmd = [npm, "audit", "--json"]

        def _run():
            return subprocess.run(
                cmd,
                cwd=str(pkg_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=settings.scanner_timeout,
            )

        try:
            proc = await asyncio.to_thread(_run)
        except FileNotFoundError as exc:
            return ScannerRunResult(
                scanner_id=self.id,
                error=f"无法启动 npm（{npm}）: {exc}",
            )
        except subprocess.TimeoutExpired:
            return ScannerRunResult(
                scanner_id=self.id,
                error=f"npm audit 超时（>{settings.scanner_timeout}秒）",
            )

        if proc.returncode not in (0, 1):
            return ScannerRunResult(
                scanner_id=self.id,
                error=(proc.stderr or proc.stdout or "npm audit failed")[:2000],
            )

        data = parse_json_output(proc.stdout or "{}", self.id)
        if not isinstance(data, dict):
            data = {}

        findings = []
        vulnerabilities = data.get("vulnerabilities", {})
        for pkg_name, vuln in vulnerabilities.items():
            if not isinstance(vuln, dict):
                continue
            via = vuln.get("via", [])
            title = vuln.get("name", pkg_name)
            severity = vuln.get("severity", "MEDIUM")

            cve_ids = []
            for v in via:
                if isinstance(v, dict):
                    cve_ids.append(v.get("cve") or v.get("title", ""))
                elif isinstance(v, str):
                    cve_ids.append(v)

            message = f"依赖漏洞: {title} ({severity})"
            if cve_ids:
                message += f" — {', '.join(filter(None, cve_ids[:3]))}"

            findings.append(finding(
                tool=self.id,
                rule_id=f"npm.{pkg_name}",
                check_id=pkg_name,
                severity=severity,
                message=message,
                file_path=str(pkg_root / "package.json"),
                line_start=0,
                project_path=project_path,
                metadata={
                    "range": vuln.get("range"),
                    "fixAvailable": vuln.get("fixAvailable"),
                    "via": cve_ids[:5],
                },
            ))

        return ScannerRunResult(scanner_id=self.id, findings=findings)
