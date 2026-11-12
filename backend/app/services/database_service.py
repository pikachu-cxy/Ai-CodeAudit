"""Test database connectivity with arbitrary connection parameters."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import Settings, build_database_url


async def test_database_connection(
    *,
    database_backend: str = "sqlite",
    database_url: str = "",
    mysql_host: str = "127.0.0.1",
    mysql_port: int = 3306,
    mysql_user: str = "ai_audit",
    mysql_password: str = "",
    mysql_database: str = "ai_audit_dev",
    mysql_charset: str = "utf8mb4",
    db_path: str = "",
) -> tuple[bool, str]:
    cfg = Settings(
        database_backend=database_backend,
        database_url=database_url,
        mysql_host=mysql_host,
        mysql_port=mysql_port,
        mysql_user=mysql_user,
        mysql_password=mysql_password,
        mysql_database=mysql_database,
        mysql_charset=mysql_charset,
    )
    if db_path:
        from pathlib import Path

        cfg.db_path = Path(db_path)
    url = build_database_url(cfg)
    engine = create_async_engine(url, echo=False)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
            conn_cs = db_cs = None
            if (database_backend or "sqlite").strip().lower() == "mysql":
                row = (
                    await conn.execute(
                        text(
                            "SELECT @@character_set_connection, @@character_set_database"
                        )
                    )
                ).one()
                conn_cs, db_cs = str(row[0]), str(row[1])
        backend = (database_backend or "sqlite").strip().lower()
        if backend == "mysql":
            target = mysql_database or "ai_audit_dev"
            extra = f"；连接 {conn_cs}，库 {db_cs}" if conn_cs else ""
            return True, f"MySQL 连接成功（{target}{extra}）"
        return True, "SQLite 连接成功"
    except Exception as exc:
        return False, str(exc)
    finally:
        await engine.dispose()
