"""刷新令牌过期判定。

回归的缺陷：``lookup_refresh_token`` 直接拿库里取回的 ``expire_at`` 跟
``datetime.now(timezone.utc)`` 比较。MySQL / SQLite 的 DATETIME 读回来是不带
时区的朴素时间，于是每次调用都抛

    TypeError: can't compare offset-naive and offset-aware datetimes

而它是 ``POST /api/auth/refresh`` 的必经之路，等于整条刷新令牌流程 500。
"""

from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models import RefreshToken
from app.services.auth_service import lookup_refresh_token


async def _make_db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return engine, factory


def _run(coro):
    return asyncio.run(coro)


async def _seed(session, token: str, *, delta: timedelta, username: str = "admin") -> None:
    session.add(
        RefreshToken(
            local_refresh_token=token,
            username=username,
            sso_refresh_token=f"sso-{token}",
            role="admin",
            expire_at=datetime.now(timezone.utc) + delta,
        )
    )
    await session.commit()


class RefreshTokenExpiryTests(unittest.TestCase):
    def test_unexpired_token_is_returned(self):
        """核心回归：未过期的令牌必须正常返回，而不是抛 TypeError。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    await _seed(s, "tok-live", delta=timedelta(days=1))
                    entry = await lookup_refresh_token(s, "tok-live")

                    self.assertIsNotNone(entry)
                    self.assertEqual(entry["username"], "admin")
                    self.assertEqual(entry["role"], "admin")
                    self.assertEqual(entry["sso_refresh_token"], "sso-tok-live")
            finally:
                await engine.dispose()

        _run(go())

    def test_expired_token_is_deleted_and_returns_none(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    await _seed(s, "tok-old", delta=timedelta(days=-1))
                    self.assertIsNone(await lookup_refresh_token(s, "tok-old"))

                    # 过期条目顺手清掉
                    remaining = (
                        await s.execute(select(RefreshToken))
                    ).scalars().all()
                    self.assertEqual(remaining, [])
            finally:
                await engine.dispose()

        _run(go())

    def test_token_expiring_right_now_is_treated_as_expired(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    await _seed(s, "tok-edge", delta=timedelta(seconds=-1))
                    self.assertIsNone(await lookup_refresh_token(s, "tok-edge"))
            finally:
                await engine.dispose()

        _run(go())

    def test_unknown_token_returns_none(self):
        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    self.assertIsNone(await lookup_refresh_token(s, "tok-missing"))
            finally:
                await engine.dispose()

        _run(go())

    def test_aware_datetime_still_works(self):
        """存进去的是带时区的时间时（例如内存里刚构造的对象）同样不能崩。"""

        async def go():
            engine, factory = await _make_db()
            try:
                async with factory() as s:
                    row = RefreshToken(
                        local_refresh_token="tok-aware",
                        username="bob",
                        role="user",
                        expire_at=datetime.now(timezone.utc) + timedelta(hours=2),
                    )
                    s.add(row)
                    await s.commit()
                    entry = await lookup_refresh_token(s, "tok-aware")
                    self.assertIsNotNone(entry)
                    self.assertEqual(entry["username"], "bob")
            finally:
                await engine.dispose()

        _run(go())


if __name__ == "__main__":
    unittest.main()
