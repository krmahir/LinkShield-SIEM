
"""Unified timeline for LinkShield SIEM.

Reads existing events, network_flows and alerts.
Does not duplicate, delete or replace existing records.
"""

from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query


# A SQL VIEW combines the three existing tables.
# UNION ALL preserves every original record.

VIEW_SQL = """
CREATE VIEW IF NOT EXISTS v_unified_timeline AS

SELECT
    'event:' || e.id AS record_uid,
    e.id AS record_id,
    'event' AS record_type,

    CASE
        WHEN e.event_type LIKE 'windows_%logon'
            THEN 'authentication'
        WHEN e.event_type LIKE 'network_%'
            THEN 'network'
        WHEN e.event_type LIKE 'process_%'
            THEN 'process'
        ELSE 'system'
    END AS event_category,

    e.event_type AS event_type,

    CASE
        WHEN e.event_type LIKE 'windows_%'
            THEN 'windows_security'
        ELSE 'endpoint'
    END AS event_source,

    e.timestamp AS timestamp_utc,
    e.received_at AS ingested_at_utc,
    e.severity AS severity,
    e.hostname AS hostname,
    e.description AS description,

    CASE
        WHEN e.event_type LIKE 'windows_%logon'
            THEN e.remote_ip
        ELSE e.local_ip
    END AS src_ip,

    CASE
        WHEN e.event_type LIKE 'windows_%logon'
            THEN e.remote_port
        ELSE e.local_port
    END AS src_port,

    CASE
        WHEN e.event_type LIKE 'windows_%logon'
            THEN e.local_ip
        ELSE e.remote_ip
    END AS dst_ip,

    CASE
        WHEN e.event_type LIKE 'windows_%logon'
            THEN e.local_port
        ELSE e.remote_port
    END AS dst_port,

    NULL AS protocol,

    CASE
        WHEN e.event_type = 'network_connection'
            THEN 'outbound'
        ELSE NULL
    END AS direction,

    e.process_name AS process_name,
    e.process_id AS process_id,
    NULL AS packet_count,
    NULL AS byte_count,
    NULL AS rule_id,
    NULL AS related_event_uid,
    NULL AS dns_query,
    NULL AS observed_dns_name

FROM events AS e

UNION ALL

SELECT
    'flow:' || f.id,
    f.id,
    'flow',
    'network',
    'network_flow',
    'packet_capture',
    f.observed_at,
    f.received_at,
    'info',
    f.hostname,
    f.protocol || ' ' || f.direction || ' flow',
    f.src_ip,
    f.src_port,
    f.dst_ip,
    f.dst_port,
    f.protocol,
    f.direction,
    f.process_name,
    f.process_id,
    f.packet_count,
    f.byte_count,
    NULL,
    NULL,
    f.dns_query,
    f.observed_dns_name

FROM network_flows AS f

UNION ALL

SELECT
    'alert:' || a.id,
    a.id,
    'alert',
    'detection',
    'rule_match',
    'detection_engine',
    a.created_at,
    a.created_at,
    a.severity,
    e.hostname,
    a.title || ': ' || a.description,
    e.local_ip,
    e.local_port,
    e.remote_ip,
    e.remote_port,
    NULL,
    NULL,
    e.process_name,
    e.process_id,
    NULL,
    NULL,
    a.rule_id,
    'event:' || a.event_id,
    NULL,
    NULL

FROM alerts AS a
LEFT JOIN events AS e ON e.id = a.event_id
"""


def install_unified_timeline(database_path: Path) -> None:
    """Create the view without modifying existing records."""

    with closing(
        sqlite3.connect(database_path, timeout=10)
    ) as conn:
        conn.execute(VIEW_SQL)
        conn.commit()


def create_timeline_router(database_path: Path) -> APIRouter:
    router = APIRouter(tags=["Unified Event Explorer"])

    def connect() -> sqlite3.Connection:
        conn = sqlite3.connect(database_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @router.get("/timeline")
    def list_timeline(
        category: Literal[
            "network", "authentication", "process",
            "detection", "system"
        ] | None = None,

        severity: Literal[
            "info", "low", "medium", "high", "critical"
        ] | None = None,

        source: str | None = Query(
            default=None, max_length=80
        ),
        hostname: str | None = Query(
            default=None, max_length=255
        ),
        ip: str | None = Query(
            default=None, max_length=45
        ),
        process: str | None = Query(
            default=None, max_length=128
        ),
        direction: Literal[
            "inbound", "outbound", "other"
        ] | None = None,

        search: str | None = Query(
            default=None, max_length=200
        ),

        since_minutes: int | None = Query(
            default=60, ge=1, le=43200
        ),

        limit: int = Query(
            default=100, ge=1, le=500
        ),

        offset: int = Query(
            default=0, ge=0, le=100000
        ),
    ):
        conditions = []
        params = []

        if since_minutes is not None:
            cutoff = (
                datetime.now(timezone.utc)
                - timedelta(minutes=since_minutes)
            ).isoformat()

            conditions.append("timestamp_utc >= ?")
            params.append(cutoff)

        for column, value in (
            ("event_category", category),
            ("severity", severity),
            ("event_source", source),
            ("hostname", hostname),
            ("direction", direction),
        ):
            if value:
                conditions.append(f"{column} = ?")
                params.append(value)

        if process:
            conditions.append(
                "instr(lower(coalesce(process_name, '')), "
                "lower(?)) > 0"
            )
            params.append(process)

        if ip:
            conditions.append(
                "(src_ip = ? OR dst_ip = ?)"
            )
            params.extend((ip, ip))

        if search and search.strip():
            fields = (
                "record_uid",
                "event_type",
                "description",
                "hostname",
                "src_ip",
                "dst_ip",
                "process_name",
                "rule_id",
                "dns_query",
                "observed_dns_name",
            )

            conditions.append(
                "(" + " OR ".join(
                    f"instr(lower(coalesce({field}, '')), "
                    "lower(?)) > 0"
                    for field in fields
                ) + ")"
            )

            params.extend(
                [search.strip()] * len(fields)
            )

        sql = "SELECT * FROM v_unified_timeline"

        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        sql += (
            " ORDER BY timestamp_utc DESC, "
            "record_uid DESC LIMIT ? OFFSET ?"
        )

        params.extend((limit + 1, offset))

        with closing(connect()) as conn:
            rows = [
                dict(row)
                for row in conn.execute(
                    sql, params
                ).fetchall()
            ]

        return {
            "items": rows[:limit],
            "has_more": len(rows) > limit,
            "limit": limit,
            "offset": offset,
        }

    @router.get("/timeline/{record_type}/{record_id}")
    def get_timeline_record(
        record_type: Literal[
            "event", "flow", "alert"
        ],
        record_id: int,
    ):
        if record_id < 1:
            raise HTTPException(
                status_code=422,
                detail="Record ID must be positive",
            )

        tables = {
            "event": "events",
            "flow": "network_flows",
            "alert": "alerts",
        }

        with closing(connect()) as conn:
            row = conn.execute(
                "SELECT * FROM v_unified_timeline "
                "WHERE record_uid = ?",
                (f"{record_type}:{record_id}",),
            ).fetchone()

            if row is None:
                raise HTTPException(
                    status_code=404,
                    detail="Record not found",
                )

            details = conn.execute(
                f"SELECT * FROM {tables[record_type]} "
                "WHERE id = ?",
                (record_id,),
            ).fetchone()

            linked_alerts = []

            if record_type == "event":
                linked_alerts = [
                    f"alert:{result[0]}"
                    for result in conn.execute(
                        "SELECT id FROM alerts "
                        "WHERE event_id = ? ORDER BY id DESC",
                        (record_id,),
                    )
                ]

        return {
            "event": dict(row),
            "details": (
                dict(details) if details else None
            ),
            "linked_alerts": linked_alerts,
        }

    return router
