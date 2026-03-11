"""TARTARUS Engine — Phase 0: Health & Infrastructure."""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.responses import JSONResponse


# ── Config ──────────────────────────────────────────────
PG_DSN = (
    f"postgresql://{os.getenv('POSTGRES_USER', 'tartarus')}"
    f":{os.getenv('POSTGRES_PASSWORD', 'tartarus_dev_2026')}"
    f"@{os.getenv('POSTGRES_HOST', 'postgres')}"
    f":{os.getenv('POSTGRES_PORT', '5432')}"
    f"/{os.getenv('POSTGRES_DB', 'tartarus')}"
)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")


# ── Lifespan ────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: connect pools. Shutdown: close them."""
    app.state.pg_pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=10)
    app.state.redis = aioredis.from_url(REDIS_URL)
    yield
    await app.state.pg_pool.close()
    await app.state.redis.aclose()


app = FastAPI(
    title="TARTARUS Engine",
    version="0.1.0",
    lifespan=lifespan,
)


# ── Routes ──────────────────────────────────────────────
@app.get("/health")
async def health():
    """Verify all infrastructure connections."""
    checks = {}

    # PostgreSQL
    try:
        async with app.state.pg_pool.acquire() as conn:
            row = await conn.fetchval("SELECT 1")
        checks["postgres"] = "ok" if row == 1 else "fail"
    except Exception as exc:
        checks["postgres"] = f"fail: {exc}"

    # Redis
    try:
        pong = await app.state.redis.ping()
        checks["redis"] = "ok" if pong else "fail"
    except Exception as exc:
        checks["redis"] = f"fail: {exc}"

    all_ok = all(v == "ok" for v in checks.values())
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ok" if all_ok else "degraded", "checks": checks},
    )


@app.get("/")
async def root():
    """Service identification."""
    return {"service": "tartarus-engine", "version": "0.1.0"}
