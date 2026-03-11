"""TARTARUS Engine — Phase 2: Sensors + Events + Scanner API."""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from contextlib import asynccontextmanager

import aio_pika
import asyncpg
import redis.asyncio as aioredis
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from engine.consumer import consume_events

logging.basicConfig(
    level=os.getenv("ENGINE_LOG_LEVEL", "info").upper(),
    format="%(asctime)s %(name)s %(levelname)s  %(message)s",
)
logger = logging.getLogger("tartarus")

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
    """Startup: connect pools + launch consumer. Shutdown: cancel + close."""
    app.state.pg_pool = await asyncpg.create_pool(PG_DSN, min_size=2, max_size=10)
    app.state.redis = aioredis.from_url(REDIS_URL)

    # Launch RabbitMQ consumer as background task
    consumer_task = asyncio.create_task(
        consume_events(app.state.pg_pool, app.state.redis)
    )
    app.state.consumer_task = consumer_task
    logger.info("Consumer task launched")

    yield

    # Graceful shutdown
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass
    await app.state.pg_pool.close()
    await app.state.redis.aclose()


app = FastAPI(
    title="TARTARUS Engine",
    version="0.2.0",
    lifespan=lifespan,
)


# ── Health ──────────────────────────────────────────────
@app.get("/health")
async def health():
    """Verify all infrastructure connections + consumer status."""
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

    # Consumer
    try:
        status = await app.state.redis.get("consumer:status")
        checks["consumer"] = status.decode() if status else "unknown"
    except Exception:
        checks["consumer"] = "unknown"

    all_ok = checks.get("postgres") == "ok" and checks.get("redis") == "ok"
    return JSONResponse(
        status_code=200 if all_ok else 503,
        content={"status": "ok" if all_ok else "degraded", "checks": checks},
    )


# ── Events API ─────────────────────────────────────────
@app.get("/events")
async def get_events(
    protocol: str | None = Query(None, description="Filter by protocol (SSH, HTTP, TCP)"),
    source_ip: str | None = Query(None, description="Filter by source IP"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """Query honeypot events with optional filters."""
    conditions = []
    params = []
    idx = 1

    if protocol:
        conditions.append(f"protocol = ${idx}")
        params.append(protocol.upper())
        idx += 1

    if source_ip:
        conditions.append(f"source_ip = ${idx}::inet")
        params.append(source_ip)
        idx += 1

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    async with app.state.pg_pool.acquire() as conn:
        # Count total
        total = await conn.fetchval(
            f"SELECT COUNT(*) FROM events {where}", *params
        )

        # Fetch page
        rows = await conn.fetch(
            f"""SELECT id, timestamp, source_ip, source_port, dest_port,
                       protocol, session_id, honeypot_id, command,
                       payload, sha256, risk_score, mitre_tactic,
                       mitre_technique, tags, created_at
                FROM events {where}
                ORDER BY timestamp DESC
                LIMIT ${idx} OFFSET ${idx + 1}""",
            *params, limit, offset,
        )

    events = []
    for r in rows:
        events.append({
            "id": str(r["id"]),
            "timestamp": r["timestamp"].isoformat(),
            "source_ip": str(r["source_ip"]),
            "source_port": r["source_port"],
            "dest_port": r["dest_port"],
            "protocol": r["protocol"],
            "session_id": r["session_id"],
            "honeypot_id": r["honeypot_id"],
            "command": r["command"],
            "payload": r["payload"],
            "sha256": r["sha256"],
            "risk_score": r["risk_score"],
            "mitre_tactic": r["mitre_tactic"],
            "mitre_technique": r["mitre_technique"],
            "tags": r["tags"] or [],
            "created_at": r["created_at"].isoformat(),
        })

    return {"total": total, "limit": limit, "offset": offset, "events": events}


@app.get("/events/stats")
async def events_stats():
    """Quick stats: total events, by protocol, unique IPs."""
    async with app.state.pg_pool.acquire() as conn:
        total = await conn.fetchval("SELECT COUNT(*) FROM events")
        by_protocol = await conn.fetch(
            "SELECT protocol, COUNT(*) as count FROM events GROUP BY protocol ORDER BY count DESC"
        )
        unique_ips = await conn.fetchval(
            "SELECT COUNT(DISTINCT source_ip) FROM events"
        )
        # Consumer stats from Redis
        events_ingested = await app.state.redis.get("consumer:events_total")

    return {
        "total_events": total,
        "by_protocol": {r["protocol"]: r["count"] for r in by_protocol},
        "unique_source_ips": unique_ips,
        "consumer_ingested": int(events_ingested) if events_ingested else 0,
    }


RABBITMQ_URI = os.getenv("RABBITMQ_URI", "amqp://guest:guest@broker:5672/")


# ── Scan API ───────────────────────────────────────────
class ScanRequest(BaseModel):
    target: str
    profile: str = "quick"


@app.post("/scan")
async def start_scan(req: ScanRequest):
    """Publish a scan job to RabbitMQ for the scanner container."""
    job_id = str(uuid.uuid4())[:8]
    job = json.dumps({
        "job_id": job_id,
        "target": req.target,
        "profile": req.profile,
    })

    try:
        connection = await aio_pika.connect_robust(RABBITMQ_URI)
        async with connection:
            channel = await connection.channel()
            await channel.declare_queue("scan_jobs", durable=True)
            await channel.default_exchange.publish(
                aio_pika.Message(body=job.encode()),
                routing_key="scan_jobs",
            )
        return {"status": "queued", "job_id": job_id, "target": req.target, "profile": req.profile}
    except Exception as exc:
        return JSONResponse(status_code=503, content={"error": f"Failed to queue scan: {exc}"})


@app.get("/scan/status")
async def scan_status():
    """Get current scan status from Redis."""
    status = await app.state.redis.get("scan:status")
    target = await app.state.redis.get("scan:target")
    last_result = await app.state.redis.get("scan:last_result")

    return {
        "status": status.decode() if status else "unknown",
        "target": target.decode() if target else None,
        "last_result": json.loads(last_result) if last_result else None,
    }


# ── Hosts API ──────────────────────────────────────────
@app.get("/hosts")
async def get_hosts(
    host_type: str | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List discovered network hosts."""
    conditions = []
    params = []
    idx = 1

    if host_type:
        conditions.append(f"host_type = ${idx}")
        params.append(host_type)
        idx += 1

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    async with app.state.pg_pool.acquire() as conn:
        rows = await conn.fetch(
            f"""SELECT id, ip, hostname, mac_address, os_fingerprint,
                       host_type, open_ports, is_honeypot, first_seen, last_seen,
                       mac_vendor, os_accuracy, scan_metadata
                FROM hosts {where}
                ORDER BY last_seen DESC
                LIMIT ${idx}""",
            *params, limit,
        )

    hosts = []
    for r in rows:
        host = {
            "id": str(r["id"]),
            "ip": str(r["ip"]),
            "hostname": r["hostname"],
            "mac_address": r["mac_address"],
            "mac_vendor": r.get("mac_vendor"),
            "os_fingerprint": r["os_fingerprint"],
            "os_accuracy": r.get("os_accuracy"),
            "host_type": r["host_type"],
            "open_ports": r["open_ports"],
            "scan_metadata": r.get("scan_metadata"),
            "is_honeypot": r["is_honeypot"],
            "first_seen": r["first_seen"].isoformat(),
            "last_seen": r["last_seen"].isoformat(),
        }
        hosts.append(host)

    return {"total": len(hosts), "hosts": hosts}


@app.get("/")
async def root():
    """Service identification."""
    return {"service": "tartarus-engine", "version": "0.3.0"}
