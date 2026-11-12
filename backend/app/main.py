from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.config import settings, validate_security_config
from app.database import init_db
from app.dependencies.auth import require_auth
from app.routers import accounts, agents, auth, mcp, projects, scans, webhooks
from app.services.scan_service import resume_interrupted_scans_after_restart

_AUDIT_EXECUTOR = ThreadPoolExecutor(max_workers=12, thread_name_prefix="audit-pool")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    import asyncio

    validate_security_config()
    # Keep API (health / polling) responsive while scanners & search_code run in threads.
    asyncio.get_running_loop().set_default_executor(_AUDIT_EXECUTOR)
    await init_db()
    recovery = await resume_interrupted_scans_after_restart()
    if recovery.reconciled:
        import logging

        logging.getLogger(__name__).info(
            "Recovered %s stale scan task(s); auto-resume sast=%s llm=%s",
            recovery.reconciled,
            recovery.sast_resume_ids,
            recovery.llm_resume_ids,
        )
    try:
        yield
    finally:
        _AUDIT_EXECUTOR.shutdown(wait=False, cancel_futures=True)


class NoCacheHtmlMiddleware(BaseHTTPMiddleware):
    """Keep HTML responses uncached when any are served from this API process."""

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path.endswith(".html"):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"
        return response


app = FastAPI(title=settings.app_name, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(dict.fromkeys(settings.cors_origins)),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(NoCacheHtmlMiddleware)

app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(projects.router)
app.include_router(scans.public_router)
app.include_router(webhooks.router)
app.include_router(agents.router)
app.include_router(mcp.router)
app.include_router(accounts.router)


@app.get("/api/health")
async def health():
    """Public liveness check (no sensitive data)."""
    return {"status": "ok", "app": settings.app_name, "auth_enabled": settings.auth_enabled}


@app.get("/api/scanners/status")
async def scanners_status():
    """
    Public scanner availability (for Docker/CI smoke checks).
    Does not expose secrets; only id / available / enabled / reason.
    """
    from app.services.scanners.registry import list_scanners

    scanners = await list_scanners()
    items = [
        {
            "id": s.id,
            "name": s.name,
            "available": s.available,
            "enabled": s.enabled,
            "reason": s.availability_reason,
        }
        for s in scanners
    ]
    available = sum(1 for s in items if s["available"])
    return {
        "status": "ok",
        "available_count": available,
        "total": len(items),
        "scanners": items,
    }


@app.get("/api/build-info")
async def build_info(_user: dict = Depends(require_auth)):
    return {"build_id": "api", "ui": "ai-audit-frontend"}
