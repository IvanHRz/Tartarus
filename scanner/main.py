"""TARTARUS Scanner — Consumes scan jobs from RabbitMQ, runs nmap, persists to PostgreSQL."""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timezone

import aio_pika
import asyncpg
import redis.asyncio as aioredis

from nmap_runner import run_scan

logging.basicConfig(
    level=os.getenv("ENGINE_LOG_LEVEL", "info").upper(),
    format="%(asctime)s %(name)s %(levelname)s  %(message)s",
)
logger = logging.getLogger("tartarus.scanner")

# Config — uses host ports since network_mode: host
PG_DSN = (
    f"postgresql://{os.getenv('POSTGRES_USER', 'tartarus')}"
    f":{os.getenv('POSTGRES_PASSWORD', 'tartarus_dev_2026')}"
    f"@{os.getenv('POSTGRES_HOST', '127.0.0.1')}"
    f":{os.getenv('POSTGRES_PORT', '5432')}"
    f"/{os.getenv('POSTGRES_DB', 'tartarus')}"
)
RABBITMQ_URI = os.getenv("RABBITMQ_URI", "amqp://guest:guest@127.0.0.1:5672/")
REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
SCAN_QUEUE = "scan_jobs"
RESULT_QUEUE = "scan_results"


async def upsert_host(pool, host: dict) -> None:
    """Insert or update a host in PostgreSQL."""
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO hosts (ip, hostname, mac_address, os_fingerprint, open_ports, last_seen)
            VALUES ($1::inet, $2, $3, $4, $5::jsonb, NOW())
            ON CONFLICT (ip) DO UPDATE SET
                hostname = COALESCE(EXCLUDED.hostname, hosts.hostname),
                mac_address = COALESCE(EXCLUDED.mac_address, hosts.mac_address),
                os_fingerprint = COALESCE(EXCLUDED.os_fingerprint, hosts.os_fingerprint),
                open_ports = EXCLUDED.open_ports,
                last_seen = NOW()
            """,
            host["ip"],
            host.get("hostname"),
            host.get("mac_address"),
            host.get("os_fingerprint"),
            json.dumps(host.get("open_ports", [])),
        )


async def process_scan_job(pool, redis_conn, job: dict) -> None:
    """Execute a scan job and persist results."""
    target = job.get("target", "")
    profile = job.get("profile", "quick")
    job_id = job.get("job_id", "unknown")

    if not target:
        logger.warning("Scan job missing target, skipping")
        return

    # Update status in Redis
    await redis_conn.set("scan:status", "scanning")
    await redis_conn.set("scan:target", target)
    await redis_conn.set("scan:profile", profile)
    await redis_conn.set("scan:started_at", datetime.now(timezone.utc).isoformat())

    try:
        hosts = await run_scan(target, profile)

        # Persist each host
        for host in hosts:
            await upsert_host(pool, host)

        # Update status
        await redis_conn.set("scan:status", "idle")
        await redis_conn.set("scan:last_result", json.dumps({
            "job_id": job_id,
            "target": target,
            "profile": profile,
            "hosts_found": len(hosts),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }))

        logger.info("Scan job %s complete: %d hosts for %s", job_id, len(hosts), target)

    except Exception:
        logger.exception("Scan job %s failed", job_id)
        await redis_conn.set("scan:status", "error")


async def main() -> None:
    """Main loop: consume scan jobs from RabbitMQ."""
    pool = await asyncpg.create_pool(PG_DSN, min_size=1, max_size=3)
    redis_conn = aioredis.from_url(REDIS_URL)
    await redis_conn.set("scan:status", "idle")

    logger.info("Scanner ready — waiting for scan jobs on queue '%s'", SCAN_QUEUE)

    while True:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URI)
            async with connection:
                channel = await connection.channel()
                await channel.set_qos(prefetch_count=1)
                queue = await channel.declare_queue(SCAN_QUEUE, durable=True)

                async with queue.iterator() as qi:
                    async for message in qi:
                        async with message.process():
                            try:
                                job = json.loads(message.body)
                                await process_scan_job(pool, redis_conn, job)
                            except json.JSONDecodeError:
                                logger.warning("Malformed scan job, skipping")

        except aio_pika.exceptions.AMQPConnectionError:
            logger.warning("RabbitMQ connection lost, reconnecting in 5s...")
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            break
        except Exception:
            logger.exception("Scanner unexpected error, retrying in 5s...")
            await asyncio.sleep(5)

    await pool.close()
    await redis_conn.aclose()


if __name__ == "__main__":
    asyncio.run(main())
