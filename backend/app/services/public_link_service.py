import base64
import hashlib
import hmac
import json
import time
from typing import Any

from app.config import settings


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _public_token_secret() -> str:
    # Prefer a dedicated secret if configured; otherwise fall back to auth secret.
    return (getattr(settings, "public_link_secret", "") or "").strip() or settings.auth_secret_key


def create_public_token(scan_id: int, finding_id: int, *, ttl_seconds: int = 6 * 3600) -> str:
    exp = int(time.time()) + int(ttl_seconds)
    payload: dict[str, Any] = {"v": 1, "scan_id": int(scan_id), "finding_id": int(finding_id), "exp": exp}
    payload_raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    payload_b64 = _b64url_encode(payload_raw)
    sig = hmac.new(_public_token_secret().encode("utf-8"), payload_b64.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"


def verify_public_token(token: str, scan_id: int, finding_id: int) -> dict[str, Any]:
    payload = decode_public_token(token)
    if int(payload.get("scan_id") or -1) != int(scan_id):
        raise ValueError("token scan_id mismatch")
    if int(payload.get("finding_id") or -1) != int(finding_id):
        raise ValueError("token finding_id mismatch")
    return payload


def decode_public_token(token: str) -> dict[str, Any]:
    if not token:
        raise ValueError("missing token")
    token = str(token).strip()
    if "." not in token:
        raise ValueError("invalid token format")
    payload_b64, sig = token.split(".", 1)
    expected_sig = hmac.new(
        _public_token_secret().encode("utf-8"),
        payload_b64.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(str(sig), expected_sig):
        raise ValueError("invalid token signature")

    payload_raw = _b64url_decode(payload_b64)
    payload = json.loads(payload_raw.decode("utf-8"))

    if payload.get("v") != 1:
        raise ValueError("unsupported token version")
    exp = int(payload.get("exp") or 0)
    if exp <= int(time.time()):
        raise ValueError("token expired")
    return payload

