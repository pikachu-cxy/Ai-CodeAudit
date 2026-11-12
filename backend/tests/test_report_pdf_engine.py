"""PDF 导出引擎选择：WeasyPrint 优先、无头浏览器兜底。

本机（Windows + 无 GTK）通常没有 WeasyPrint，因此这里重点覆盖
「WeasyPrint 不可用时自动回退到浏览器」这条路径。
"""

import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from app.config import settings
from app.services import report_service as rs

SAMPLE_HTML = "<!doctype html><html><body><h1>报告</h1></body></html>"


class _FakeWeasyPrintHTML:
    """替身：记录收到的 HTML 并返回一段合法的 PDF 头。"""

    calls: list[str] = []

    def __init__(self, string: str = ""):
        self.string = string

    def write_pdf(self) -> bytes:
        type(self).calls.append(self.string)
        return b"%PDF-1.4\nfake-weasyprint"


def _force_weasyprint(available: bool, loaded=None):
    """把模块级缓存改成指定状态，避免真的去 import。"""
    if available:
        return mock.patch.object(rs, "_weasyprint_cache", (True, loaded or _FakeWeasyPrintHTML))
    return mock.patch.object(rs, "_weasyprint_cache", (False, OSError("cannot load library 'gobject-2.0-0'")))


class FindBrowserTests(unittest.TestCase):
    def test_configured_path_wins_when_it_exists(self):
        with mock.patch.object(settings, "pdf_chrome_path", sys.executable):
            self.assertEqual(rs.find_pdf_browser(), sys.executable)

    def test_missing_configured_path_is_ignored(self):
        bogus = r"C:\definitely\not\here\chrome.exe"
        with mock.patch.object(settings, "pdf_chrome_path", bogus):
            found = rs.find_pdf_browser()
        self.assertNotEqual(found, bogus)

    def test_autodetect_finds_a_browser_on_this_machine(self):
        with mock.patch.object(settings, "pdf_chrome_path", ""):
            found = rs.find_pdf_browser()
        if not found:
            self.skipTest("本机未安装 Chrome/Chromium/Edge")
        self.assertTrue(Path(found).exists())


class EngineSelectionTests(unittest.TestCase):
    def test_engine_weasyprint_unavailable_raises_actionable_error(self):
        with _force_weasyprint(False), mock.patch.object(settings, "pdf_engine", "weasyprint"):
            with self.assertRaises(RuntimeError) as ctx:
                asyncio.run(rs._render_pdf_bytes(SAMPLE_HTML))
        msg = str(ctx.exception)
        self.assertIn("WeasyPrint", msg)
        # 报错要给出可操作的另一条路
        self.assertIn("chrome", msg.lower())

    def test_engine_weasyprint_success_uses_weasyprint(self):
        _FakeWeasyPrintHTML.calls = []
        with _force_weasyprint(True), mock.patch.object(settings, "pdf_engine", "weasyprint"):
            pdf = asyncio.run(rs._render_pdf_bytes(SAMPLE_HTML))
        self.assertTrue(pdf.startswith(b"%PDF"))
        self.assertEqual(_FakeWeasyPrintHTML.calls, [SAMPLE_HTML])

    def test_engine_chrome_skips_weasyprint_entirely(self):
        _FakeWeasyPrintHTML.calls = []
        with _force_weasyprint(True), mock.patch.object(
            settings, "pdf_engine", "chrome"
        ), mock.patch.object(rs, "find_pdf_browser", return_value="chrome.exe"), mock.patch.object(
            rs, "_pdf_via_browser_sync", return_value=b"%PDF-1.4\nfake-browser"
        ) as browser_mock:
            pdf = asyncio.run(rs._render_pdf_bytes(SAMPLE_HTML))
        self.assertTrue(pdf.startswith(b"%PDF"))
        browser_mock.assert_called_once_with(SAMPLE_HTML, "chrome.exe")
        self.assertEqual(_FakeWeasyPrintHTML.calls, [], "engine=chrome 时不应调用 WeasyPrint")

    def test_engine_auto_falls_back_to_browser_when_weasyprint_missing(self):
        with _force_weasyprint(False), mock.patch.object(
            settings, "pdf_engine", "auto"
        ), mock.patch.object(rs, "find_pdf_browser", return_value="chrome.exe"), mock.patch.object(
            rs, "_pdf_via_browser_sync", return_value=b"%PDF-1.4\nfake-browser"
        ) as browser_mock:
            pdf = asyncio.run(rs._render_pdf_bytes(SAMPLE_HTML))
        self.assertTrue(pdf.startswith(b"%PDF"))
        browser_mock.assert_called_once()

    def test_engine_auto_falls_back_when_weasyprint_render_fails(self):
        class _Boom(_FakeWeasyPrintHTML):
            def write_pdf(self):
                raise RuntimeError("pango 崩了")

        with _force_weasyprint(True, _Boom), mock.patch.object(
            settings, "pdf_engine", "auto"
        ), mock.patch.object(rs, "find_pdf_browser", return_value="chrome.exe"), mock.patch.object(
            rs, "_pdf_via_browser_sync", return_value=b"%PDF-1.4\nfake-browser"
        ) as browser_mock:
            pdf = asyncio.run(rs._render_pdf_bytes(SAMPLE_HTML))
        self.assertTrue(pdf.startswith(b"%PDF"))
        browser_mock.assert_called_once()

    def test_engine_weasyprint_render_failure_is_not_silently_swallowed(self):
        class _Boom(_FakeWeasyPrintHTML):
            def write_pdf(self):
                raise RuntimeError("pango 崩了")

        with _force_weasyprint(True, _Boom), mock.patch.object(settings, "pdf_engine", "weasyprint"):
            with self.assertRaises(RuntimeError) as ctx:
                asyncio.run(rs._render_pdf_bytes(SAMPLE_HTML))
        self.assertIn("pango", str(ctx.exception))

    def test_invalid_engine_value_falls_back_to_auto(self):
        with _force_weasyprint(False), mock.patch.object(
            settings, "pdf_engine", "nonsense"
        ), mock.patch.object(rs, "find_pdf_browser", return_value="chrome.exe"), mock.patch.object(
            rs, "_pdf_via_browser_sync", return_value=b"%PDF-1.4\nfake-browser"
        ) as browser_mock:
            pdf = asyncio.run(rs._render_pdf_bytes(SAMPLE_HTML))
        self.assertTrue(pdf.startswith(b"%PDF"))
        browser_mock.assert_called_once()

    def test_no_engine_available_gives_clear_error(self):
        with _force_weasyprint(False), mock.patch.object(
            settings, "pdf_engine", "auto"
        ), mock.patch.object(rs, "find_pdf_browser", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                asyncio.run(rs._render_pdf_bytes(SAMPLE_HTML))
        msg = str(ctx.exception)
        self.assertIn("PDF 导出不可用", msg)
        self.assertIn("PDF_CHROME_PATH", msg)

    def test_browser_failure_is_wrapped_with_browser_path(self):
        with _force_weasyprint(False), mock.patch.object(
            settings, "pdf_engine", "auto"
        ), mock.patch.object(rs, "find_pdf_browser", return_value="/usr/bin/chromium"), mock.patch.object(
            rs, "_pdf_via_browser_sync", side_effect=RuntimeError("超时")
        ):
            with self.assertRaises(RuntimeError) as ctx:
                asyncio.run(rs._render_pdf_bytes(SAMPLE_HTML))
        msg = str(ctx.exception)
        self.assertIn("/usr/bin/chromium", msg)
        self.assertIn("超时", msg)


class RealBrowserPdfTests(unittest.TestCase):
    """真实跑一次无头浏览器，验证端到端能产出合法 PDF。"""

    def test_real_browser_produces_valid_pdf(self):
        browser = rs.find_pdf_browser()
        if not browser:
            self.skipTest("本机未安装 Chrome/Chromium/Edge")
        html = (
            '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"></head>'
            '<body><h1>安全审计报告</h1><p>严重 1 · 高危 3</p></body></html>'
        )
        pdf = asyncio.run(rs._render_pdf_bytes(html))
        self.assertTrue(pdf.startswith(b"%PDF"), "应产出合法 PDF")
        self.assertGreater(len(pdf), 1024)


class BrowserCommandTests(unittest.TestCase):
    """命令参数正确性 —— 这些参数是 Linux/Docker 上能不能跑起来的关键。"""

    def _cmd(self, headless_flag="--headless=new"):
        base = Path(tempfile.gettempdir()) / "ai-audit-pdf-test"
        return rs._build_browser_cmd(
            "/usr/bin/chromium",
            headless_flag,
            base / "report.html",
            base / "report.pdf",
            base / "profile",
        )

    def test_disables_dev_shm_usage_for_docker(self):
        """Docker 默认 /dev/shm 仅 64MB，缺这个参数 Chromium 会崩或挂住。"""
        self.assertIn("--disable-dev-shm-usage", self._cmd())

    def test_no_sandbox_is_present(self):
        """容器里通常以 root 运行，没有它 Chromium 直接拒绝启动。"""
        self.assertIn("--no-sandbox", self._cmd())

    def test_uses_isolated_user_data_dir(self):
        """缺它时本机已有浏览器在跑会导致退出码 0 但不产出文件。"""
        cmd = self._cmd()
        profile_args = [a for a in cmd if a.startswith("--user-data-dir=")]
        self.assertEqual(len(profile_args), 1)
        self.assertTrue(profile_args[0].endswith("profile"))

    def test_uses_file_uri_for_local_html(self):
        last = self._cmd()[-1]
        self.assertTrue(last.startswith("file://"), f"应以 file:// 开头：{last}")
        self.assertTrue(last.endswith("report.html"), f"应指向 HTML 文件：{last}")

    def test_suppresses_default_pdf_header_footer(self):
        self.assertIn("--no-pdf-header-footer", self._cmd())

    def test_headless_flag_is_configurable(self):
        self.assertIn("--headless", self._cmd("--headless"))


class HeadlessFlagFallbackTests(unittest.TestCase):
    def test_falls_back_to_plain_headless_when_new_is_unsupported(self):
        """旧版 Chromium 不认 --headless=new，应自动重试 --headless。"""
        tried: list[str] = []

        def fake_once(browser, headless_flag, *args, **kwargs):
            tried.append(headless_flag)
            # 模拟：只有朴素 --headless 能产出文件
            return b"%PDF-1.4\nok" if headless_flag == "--headless" else None

        with mock.patch.object(rs, "_run_browser_print_once", side_effect=fake_once):
            pdf = rs._pdf_via_browser_sync(SAMPLE_HTML, "/usr/bin/chromium")

        self.assertEqual(tried, ["--headless=new", "--headless"])
        self.assertTrue(pdf.startswith(b"%PDF"))

    def test_stops_after_first_success(self):
        tried: list[str] = []

        def fake_once(browser, headless_flag, *args, **kwargs):
            tried.append(headless_flag)
            return b"%PDF-1.4\nok"

        with mock.patch.object(rs, "_run_browser_print_once", side_effect=fake_once):
            rs._pdf_via_browser_sync(SAMPLE_HTML, "/usr/bin/chromium")

        self.assertEqual(tried, ["--headless=new"], "成功一次后不应继续重试")

    def test_all_attempts_failing_raises_with_linux_hint(self):
        with mock.patch.object(rs, "_run_browser_print_once", return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                rs._pdf_via_browser_sync(SAMPLE_HTML, "/usr/bin/chromium")
        # 提示按当前平台生成；本机是 Windows 时用函数本身验证 Linux 分支
        self.assertIn("fonts-noto-cjk", rs._browser_failure_hint(False))
        self.assertIn("snap", rs._browser_failure_hint(False))

    def test_windows_has_no_linux_hint(self):
        self.assertEqual(rs._browser_failure_hint(True), "")

    def test_linux_hint_is_appended_to_error_on_posix(self):
        with mock.patch.object(rs, "_run_browser_print_once", return_value=None), mock.patch.object(
            rs, "_browser_failure_hint", return_value="。LINUX_HINT"
        ):
            with self.assertRaises(RuntimeError) as ctx:
                rs._pdf_via_browser_sync(SAMPLE_HTML, "/usr/bin/chromium")
        self.assertIn("LINUX_HINT", str(ctx.exception))

    def test_failure_details_are_included_in_error(self):
        def fake_once(browser, headless_flag, *args):
            args[-1].append(f"{headless_flag}: 未产出文件（stderr 诊断）")
            return None

        with mock.patch.object(rs, "_run_browser_print_once", side_effect=fake_once):
            with self.assertRaises(RuntimeError) as ctx:
                rs._pdf_via_browser_sync(SAMPLE_HTML, "/usr/bin/chromium")
        msg = str(ctx.exception)
        self.assertIn("--headless=new", msg, "应带上第一次尝试的标识")
        self.assertIn("stderr 诊断", msg, "应带上浏览器 stderr，便于定位")


if __name__ == "__main__":
    unittest.main()
