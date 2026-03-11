"""TARTARUS — RabbitMQ Consumer: Beelzebub events → PostgreSQL.

Consumes JSON events from Beelzebub's `event` queue, computes SHA256
for chain of custody, and persists to the `events` table.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime, timezone

logger = logging.getLogger("tartarus.consumer")

RABBITMQ_URI = os.getenv("RABBITMQ_URI", "amqp://guest:guest@broker:5672/")
QUEUE_NAME = "event"

# Maps Beelzebub JSON keys → PostgreSQL columns
_FIELD_MAP = {
    "DateTime": "timestamp",
    "RemoteAddr": "remote_addr",
    "Protocol": "protocol",
    "Command": "command",
    "CommandOutput": "command_output",
    "Status": "status",
    "Msg": "msg",
    "ID": "session_id",
    "User": "user",
    "Password": "password",
    "Client": "client",
    "SourceIp": "source_ip",
    "SourcePort": "source_port",
}


def _compute_sha256(raw_body: bytes) -> str:
    """Chain of custody: SHA256 of the raw event payload."""
    return hashlib.sha256(raw_body).hexdigest()


def _parse_event(body: bytes) -> dict | None:
    """Parse Beelzebub JSON into a dict ready for PostgreSQL insertion."""
    try:
        raw = json.loads(body)
    except json.JSONDecodeError:
        logger.warning("Malformed JSON event, skipping")
        return None

    # Extract source IP and port
    source_ip = raw.get("SourceIp") or raw.get("RemoteAddr", "").split(":")[0]
    if not source_ip:
        logger.warning("Event without source IP, skipping")
        return None

    source_port = raw.get("SourcePort")
    if source_port:
        try:
            source_port = int(str(source_port).strip())
        except (ValueError, TypeError):
            source_port = None

    # Parse timestamp
    ts_str = raw.get("DateTime")
    if ts_str:
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            ts = datetime.now(timezone.utc)
    else:
        ts = datetime.now(timezone.utc)

    # Protocol
    protocol = (raw.get("Protocol") or "unknown").upper()

    # Dest port + protocol-aware command extraction
    dest_port = None
    command = ""

    if protocol == "HTTP":
        dest_port = 80
        method = raw.get("HTTPMethod", "")
        uri = raw.get("RequestURI", "")
        command = f"{method} {uri}".strip() if (method or uri) else raw.get("Msg", "")
    elif protocol == "SSH":
        dest_port = 22
        command = raw.get("Command") or raw.get("Msg") or ""
    elif protocol == "TCP":
        dest_port = raw.get("DestPort")
        body_data = raw.get("Body", "") or raw.get("Command", "")
        command = body_data[:200] if body_data else raw.get("Msg", "")
    else:
        command = raw.get("Command") or raw.get("Msg") or ""

    sha256 = _compute_sha256(body)

    return {
        "timestamp": ts,
        "source_ip": source_ip,
        "source_port": source_port,
        "dest_port": dest_port,
        "protocol": protocol,
        "session_id": raw.get("ID"),
        "honeypot_id": raw.get("HandlerName"),
        "command": command,
        "payload": json.dumps(raw),
        "sha256": sha256,
    }


async def _insert_event(pool, event: dict) -> None:
    """Insert a parsed event into PostgreSQL."""
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO events (timestamp, source_ip, source_port, dest_port,
                                protocol, session_id, honeypot_id, command,
                                payload, sha256)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10)
            """,
            event["timestamp"],
            event["source_ip"],
            event["source_port"],
            event["dest_port"],
            event["protocol"],
            event["session_id"],
            event["honeypot_id"],
            event["command"],
            event["payload"],
            event["sha256"],
        )


async def consume_events(pg_pool, redis=None) -> None:
    """Main consumer loop — connects to RabbitMQ and processes events.

    Runs as a background task during FastAPI lifespan.
    Reconnects automatically on connection loss.
    """
    import aio_pika

    while True:
        try:
            connection = await aio_pika.connect_robust(RABBITMQ_URI)
            async with connection:
                channel = await connection.channel()
                await channel.set_qos(prefetch_count=50)
                queue = await channel.declare_queue(QUEUE_NAME, durable=False)

                logger.info(
                    "Consumer connected — listening on queue '%s'", QUEUE_NAME
                )

                # Publish consumer status to Redis
                if redis:
                    await redis.set("consumer:status", "connected")
                    await redis.set(
                        "consumer:started_at",
                        datetime.now(timezone.utc).isoformat(),
                    )

                async with queue.iterator() as qi:
                    async for message in qi:
                        async with message.process():
                            event = _parse_event(message.body)
                            if event is None:
                                continue
                            try:
                                await _insert_event(pg_pool, event)
                                # Increment counter in Redis
                                if redis:
                                    await redis.incr("consumer:events_total")
                                logger.debug(
                                    "Ingested %s event from %s",
                                    event["protocol"],
                                    event["source_ip"],
                                )
                            except Exception:
                                logger.exception("Failed to insert event")

        except aio_pika.exceptions.AMQPConnectionError:
            logger.warning("RabbitMQ connection lost, reconnecting in 5s...")
            if redis:
                await redis.set("consumer:status", "reconnecting")
            await asyncio.sleep(5)
        except asyncio.CancelledError:
            logger.info("Consumer shutting down")
            if redis:
                await redis.set("consumer:status", "stopped")
            break
        except Exception:
            logger.exception("Consumer unexpected error, retrying in 5s...")
            await asyncio.sleep(5)
