"""SSRF controls and curl parsing for PoC HTTP verification."""

from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from app.services.poc_http import (
    PocTargetError,
    assert_public_url,
    ip_is_blocked,
    parse_poc_content,
    seed_from_api_endpoint,
)


class PocHttpSsrfTests(unittest.TestCase):
    def test_literal_loopback_blocked(self):
        with self.assertRaises(PocTargetError):
            assert_public_url("http://127.0.0.1/", resolve_dns=False)
        with self.assertRaises(PocTargetError):
            assert_public_url("http://localhost/admin", resolve_dns=False)

    def test_rfc1918_and_metadata_blocked(self):
        for url in (
            "http://10.0.0.1/x",
            "https://192.168.1.1/",
            "http://172.16.0.8/api",
            "http://169.254.169.254/latest/meta-data",
            "http://100.64.0.1/",
        ):
            with self.assertRaises(PocTargetError, msg=url):
                assert_public_url(url, resolve_dns=False)

    def test_onion_and_local_suffix_blocked(self):
        with self.assertRaises(PocTargetError):
            assert_public_url("http://example.onion/", resolve_dns=False)
        with self.assertRaises(PocTargetError):
            assert_public_url("http://printer.local/", resolve_dns=False)

    def test_ipv6_loopback_blocked(self):
        with self.assertRaises(PocTargetError):
            assert_public_url("http://[::1]/", resolve_dns=False)

    def test_ipv4_mapped_loopback_blocked(self):
        self.assertTrue(ip_is_blocked("::ffff:127.0.0.1"))
        self.assertTrue(ip_is_blocked("::ffff:10.0.0.1"))
        self.assertTrue(ip_is_blocked("127.0.0.1"))
        self.assertTrue(ip_is_blocked("10.1.2.3"))
        self.assertTrue(ip_is_blocked("169.254.169.254"))
        self.assertTrue(ip_is_blocked("::1"))
        self.assertFalse(ip_is_blocked("8.8.8.8"))
        self.assertFalse(ip_is_blocked("1.1.1.1"))

    def test_public_hostname_allowed_when_dns_is_public(self):
        fake = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("8.8.8.8", 0)),
        ]
        with patch("app.services.poc_http.socket.getaddrinfo", return_value=fake):
            out = assert_public_url("https://example.com/path", resolve_dns=True)
        self.assertEqual(out, "https://example.com/path")

    def test_public_hostname_blocked_when_dns_is_private(self):
        fake = [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("10.0.0.5", 0)),
        ]
        with patch("app.services.poc_http.socket.getaddrinfo", return_value=fake):
            with self.assertRaises(PocTargetError):
                assert_public_url("https://evil.example", resolve_dns=True)

    def test_scheme_must_be_http(self):
        with self.assertRaises(PocTargetError):
            assert_public_url("file:///etc/passwd", resolve_dns=False)
        with self.assertRaises(PocTargetError):
            assert_public_url("ftp://example.com/", resolve_dns=False)


class PocParseTests(unittest.TestCase):
    def test_parse_curl(self):
        raw = (
            "curl -X POST https://example.com/login "
            "-H 'Content-Type: application/json' "
            "-d '{\"user\":\"admin\"}'"
        )
        parsed = parse_poc_content(raw)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["method"], "POST")
        self.assertEqual(parsed["url"], "https://example.com/login")
        self.assertIn("Content-Type", parsed["headers"])
        self.assertIn("admin", parsed["body"])

    def test_seed_from_endpoint(self):
        seeded = seed_from_api_endpoint("POST /api/users/{id}")
        self.assertEqual(seeded["method"], "POST")
        self.assertEqual(seeded["url"], "/api/users/{id}")


if __name__ == "__main__":
    unittest.main()
