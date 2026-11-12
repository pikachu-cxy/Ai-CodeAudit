from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import Finding, ScanTask, dt_iso
from app.schemas import CodeLocationOut, DetectedLanguageOut, FileContentOut, FindingOut, ScanDetail, ScanSummary, ScanCoverageOut
from app.services.file_service import locate_text_in_project, read_file_with_context
from app.services.llm_audit_coverage import batch_load_llm_audit_meta
from app.services.project_languages import detected_languages_from_scanner_summary
from app.services.public_link_service import decode_public_token, verify_public_token
from app.services.scan_coverage import build_scan_coverage, ensure_rule_inventory_persisted

router = APIRouter(prefix="/api/public", tags=["public"])


def _scan_status_str(scan: ScanTask) -> str:
    st = scan.status
    return st.value if hasattr(st, "value") else str(st)


async def _scan_summary_from_task(db: AsyncSession, scan: ScanTask) -> ScanSummary:
    meta_map = await batch_load_llm_audit_meta(db, [scan.id])
    new_summary, changed = ensure_rule_inventory_persisted(scan.scanner_summary)
    if changed and new_summary is not None:
        scan.scanner_summary = new_summary
        await db.commit()
        await db.refresh(scan)
    cov = build_scan_coverage(
        scan.scanner_summary,
        scan_status=_scan_status_str(scan),
        llm_audit_meta=meta_map.get(scan.id),
    )
    detected = [
        DetectedLanguageOut(**row)
        for row in detected_languages_from_scanner_summary(scan.scanner_summary)
    ]
    return ScanSummary(
        id=scan.id,
        name=scan.name,
        source=scan.source,
        status=scan.status,
        source_url=scan.source_url,
        branch=scan.branch,
        progress=scan.progress,
        progress_message=scan.progress_message,
        total_findings=scan.total_findings,
        security_score=getattr(scan, "security_score", None),
        semgrep_version=scan.semgrep_version,
        scanner_summary=scan.scanner_summary,
        scan_coverage=ScanCoverageOut(**cov),
        detected_languages=detected,
        error_message=scan.error_message,
        created_at=dt_iso(scan.created_at) or "",
        completed_at=dt_iso(getattr(scan, "completed_at", None)),
    )


@router.get("/scans/{scan_id}/findings/{finding_id}", response_model=FindingOut)
async def get_public_finding(
    scan_id: int,
    finding_id: int,
    token: str,
    db: AsyncSession = None,
):
    if db is None:
        raise HTTPException(500, "db missing")

    try:
        verify_public_token(token, scan_id, finding_id)
    except Exception:
        raise HTTPException(status_code=403, detail="invalid or expired public link")

    finding = await db.get(Finding, finding_id)
    if not finding or finding.scan_id != scan_id:
        raise HTTPException(404, "Finding not found")
    return FindingOut.model_validate(finding)


@router.get("/scans/{scan_id}", response_model=ScanDetail)
async def get_public_scan(
    scan_id: int,
    token: str,
    db: AsyncSession = None,
):
    if db is None:
        raise HTTPException(500, "db missing")

    try:
        payload = decode_public_token(token)
        if int(payload.get("scan_id") or -1) != int(scan_id):
            raise ValueError("scan_id mismatch")
    except Exception:
        raise HTTPException(status_code=403, detail="invalid or expired public link")

    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    summary = await _scan_summary_from_task(db, scan)
    return ScanDetail(**summary.model_dump(), findings=[])


@router.get("/scans/{scan_id}/files/content", response_model=FileContentOut)
async def get_public_file_content(
    scan_id: int,
    path: str,
    line_start: int = 1,
    line_end: int = 1,
    context: int = 40,
    token: str = "",
    db: AsyncSession = None,
):
    if db is None:
        raise HTTPException(500, "db missing")
    if not token:
        raise HTTPException(status_code=403, detail="missing token")

    try:
        payload = decode_public_token(token)
        if int(payload.get("scan_id") or -1) != int(scan_id):
            raise ValueError("scan_id mismatch")
    except Exception:
        raise HTTPException(status_code=403, detail="invalid or expired public link")

    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    try:
        data = read_file_with_context(
            project_path=scan.project_path if hasattr(scan, "project_path") else None,
            file_path=path,
            highlight_start=line_start,
            highlight_end=line_end,
            context_lines=min(context, 120),
        )
    except TypeError:
        from pathlib import Path

        data = read_file_with_context(
            Path(scan.project_path),
            path,
            line_start,
            line_end,
            context_lines=min(context, 120),
        )
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    return FileContentOut(**data)


@router.get("/scans/{scan_id}/files/locate", response_model=list[CodeLocationOut])
async def locate_public_file(
    scan_id: int,
    q: str,
    file_hint: str | None = None,
    limit: int = 8,
    token: str = "",
    db: AsyncSession = None,
):
    if db is None:
        raise HTTPException(500, "db missing")
    if not token:
        raise HTTPException(status_code=403, detail="missing token")

    try:
        payload = decode_public_token(token)
        if int(payload.get("scan_id") or -1) != int(scan_id):
            raise ValueError("scan_id mismatch")
    except Exception:
        raise HTTPException(status_code=403, detail="invalid or expired public link")

    scan = await db.get(ScanTask, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    hits = locate_text_in_project(
        project_path=scan.project_path if hasattr(scan, "project_path") else None,
        query=q,
        file_hint=file_hint,
        limit=min(int(limit), 20),
    )
    return [CodeLocationOut.model_validate(h) for h in hits]
