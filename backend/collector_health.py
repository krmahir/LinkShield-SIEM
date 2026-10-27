
"""LinkShield collector heartbeat monitoring."""

import socket
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel, Field

TTL_SECONDS = 25

KNOWN = {
    "packet_capture": "Packet Capture",
    "network_events": "Connection Events",
    "windows_security": "Windows Security",
}


class CollectorHeartbeat(BaseModel):
    collector: Literal[
        "packet_capture",
        "network_events",
        "windows_security",
    ]
    hostname: str = Field(min_length=1, max_length=255)
    status: Literal[
        "running", "degraded", "stopped"
    ] = "running"
    pid: int | None = Field(default=None, ge=1)
    detail: str | None = Field(default=None, max_length=300)


def install_collector_health(database: Path) -> None:
    with closing(sqlite3.connect(database, timeout=10)) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS collector_heartbeats (
                hostname TEXT NOT NULL,
                collector TEXT NOT NULL,
                status TEXT NOT NULL,
                pid INTEGER,
                detail TEXT,
                seen_utc TEXT NOT NULL,
                PRIMARY KEY (hostname, collector)
            )
        """)
        db.commit()


def create_collector_health_router(database: Path) -> APIRouter:
    router = APIRouter(tags=["Collector Health"])

    @router.post("/collectors/heartbeat")
    def heartbeat(payload: CollectorHeartbeat):
        received = datetime.now(timezone.utc).isoformat()

        with closing(sqlite3.connect(database, timeout=10)) as db:
            db.execute("""
                INSERT INTO collector_heartbeats
                    (hostname, collector, status, pid, detail, seen_utc)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(hostname, collector) DO UPDATE SET
                    status = excluded.status,
                    pid = excluded.pid,
                    detail = excluded.detail,
                    seen_utc = excluded.seen_utc
            """, (
                payload.hostname,
                payload.collector,
                payload.status,
                payload.pid,
                payload.detail,
                received,
            ))
            db.commit()

        return {"received": True, "seen_utc": received}

    @router.get("/collectors/status")
    def status():
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)

        with closing(sqlite3.connect(database, timeout=10)) as db:
            db.row_factory = sqlite3.Row

            rows = {
                row["collector"]: dict(row)
                for row in db.execute(
                    "SELECT * FROM collector_heartbeats "
                    "WHERE hostname = ?",
                    (hostname,),
                )
            }

        collectors = []

        for name, label in KNOWN.items():
            saved = rows.get(name)

            if saved is None:
                collectors.append({
                    "collector": name,
                    "label": label,
                    "status": "not_connected",
                    "age_seconds": None,
                    "last_seen_utc": None,
                    "detail": None,
                })
                continue

            try:
                seen = datetime.fromisoformat(
                    saved["seen_utc"]
                )

                if seen.tzinfo is None:
                    seen = seen.replace(tzinfo=timezone.utc)

                age = max(
                    0,
                    int((now - seen).total_seconds()),
                )
            except ValueError:
                age = TTL_SECONDS + 1

            state = saved["status"]

            if state != "stopped" and age > TTL_SECONDS:
                state = "stale"
            elif state == "running":
                state = "active"

            collectors.append({
                "collector": name,
                "label": label,
                "status": state,
                "age_seconds": age,
                "last_seen_utc": saved["seen_utc"],
                "detail": saved["detail"],
            })

        return {
            "backend": "online",
            "database": "connected",
            "hostname": hostname,
            "checked_at_utc": now.isoformat(),
            "heartbeat_ttl_seconds": TTL_SECONDS,
            "collectors": collectors,
        }

    return router
