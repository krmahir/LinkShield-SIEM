"""LinkShield SIEM local API.

Features:
- Security events and basic detection rules
- Network-flow ingestion, search, statistics, timelines, IP investigations
- Country-level GeoIP enrichment
- Optional serving of the compiled React dashboard

Development: python -m uvicorn main:app --host 127.0.0.1 --port 8001
Build frontend first: cd dashboard && npm run build

Keep the API bound to loopback until authentication and agent security exist.
"""

from __future__ import annotations

import os
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import Literal

import geoip2.database
import geoip2.errors
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from detection import detect_remote_ip




# ---------------------------------------------------------------------------
# Paths and configuration
# ---------------------------------------------------------------------------

BACKEND_DIR = Path(__file__).resolve().parent

if getattr(sys, "frozen", False):
    # Resources bundled with a future PyInstaller build.
    RESOURCE_ROOT = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
else:
    RESOURCE_ROOT = BACKEND_DIR.parent

# Keep the current development database in backend/siem.db, so replacing this
# file will not move or erase existing records. Packaged builds use user data.
custom_data_dir = os.environ.get("LINKSHIELD_DATA_DIR")
if custom_data_dir:
    DATA_DIR = Path(custom_data_dir).expanduser().resolve()
elif getattr(sys, "frozen", False):
    DATA_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LinkShield"
else:
    DATA_DIR = BACKEND_DIR

DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH = DATA_DIR / "siem.db"

GEOIP_DATABASE = RESOURCE_ROOT / "backend" / "geoip" / "GeoLite2-Country.mmdb"
DASHBOARD_DIR = RESOURCE_ROOT / "dashboard" / "dist"

Severity = Literal["info", "low", "medium", "high", "critical"]
Direction = Literal["inbound", "outbound", "other"]

app = FastAPI(
    title="LinkShield SIEM",
    description="Security monitoring and event collection API",
    version="0.2.0",
)

# Vite development origin. In the final build, the dashboard uses same-origin
# API requests, so cross-origin access is unnecessary.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class SecurityEvent(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    event_type: str = Field(min_length=1, max_length=100)
    description: str = Field(min_length=1, max_length=2000)

    local_ip: str | None = None
    local_port: int | None = Field(default=None, ge=1, le=65535)
    remote_ip: str | None = None
    remote_port: int | None = Field(default=None, ge=1, le=65535)
    process_name: str | None = None
    process_id: int | None = Field(default=None, ge=0)
    severity: Severity = "info"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NetworkFlow(BaseModel):
    direction: Direction
    protocol: str
    src_ip: str
    src_port: int | None = None
    dst_ip: str
    dst_port: int | None = None
    packet_count: int = Field(ge=1)
    byte_count: int = Field(ge=0)
    dns_query: str | None = None
    observed_at: datetime
    process_name: str | None = None
    process_id: int | None = Field(default=None, ge=0)
    observed_dns_name: str | None = Field(default=None, max_length=253)


class FlowBatch(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    flows: list[NetworkFlow] = Field(min_length=1, max_length=200)


# ---------------------------------------------------------------------------
# SQLite schema and migrations — one initialisation path for fresh installs
# ---------------------------------------------------------------------------

def initialise_database() -> None:
    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                event_type TEXT NOT NULL,
                description TEXT NOT NULL,
                local_ip TEXT,
                local_port INTEGER,
                remote_ip TEXT,
                remote_port INTEGER,
                process_name TEXT,
                process_id INTEGER,
                severity TEXT NOT NULL
                    CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
                timestamp TEXT NOT NULL,
                received_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                severity TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (event_id) REFERENCES events(id)
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                direction TEXT NOT NULL,
                protocol TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER,
                dst_ip TEXT NOT NULL,
                dst_port INTEGER,
                packet_count INTEGER NOT NULL,
                byte_count INTEGER NOT NULL,
                dns_query TEXT,
                observed_at TEXT NOT NULL,
                received_at TEXT NOT NULL,
                process_name TEXT,
                process_id INTEGER,
                observed_dns_name TEXT
            )
        """)

        # Existing LinkShield databases may lack columns added later. Never
        # drop tables or delete historical flow records during an upgrade.
        columns = {
            row[1]
            for row in conn.execute("PRAGMA table_info(network_flows)")
        }
        migrations = {
            "process_name": "TEXT",
            "process_id": "INTEGER",
            "observed_dns_name": "TEXT",
        }
        for name, sql_type in migrations.items():
            if name not in columns:
                conn.execute(
                    f"ALTER TABLE network_flows ADD COLUMN {name} {sql_type}"
                )

        for index_sql in (
            "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_events_hostname ON events(hostname)",
            "CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity)",
            "CREATE INDEX IF NOT EXISTS idx_alerts_created ON alerts(created_at)",
            "CREATE INDEX IF NOT EXISTS idx_flows_received ON network_flows(received_at)",
        ):
            conn.execute(index_sql)

        conn.commit()


initialise_database()
from unified_timeline import (
    create_timeline_router,
    install_unified_timeline,
)

install_unified_timeline(DATABASE_PATH)

app.include_router(
    create_timeline_router(DATABASE_PATH)
)

from collector_health import (
    create_collector_health_router,
    install_collector_health,
)

install_collector_health(DATABASE_PATH)

app.include_router(
    create_collector_health_router(DATABASE_PATH)
)

# ---------------------------------------------------------------------------
# Security events and alert rules
# ---------------------------------------------------------------------------

def save_event(event: SecurityEvent) -> tuple[int, str]:
    received_at = datetime.now(timezone.utc).isoformat()
    event_time = event.timestamp
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    event_time_iso = event_time.astimezone(timezone.utc).isoformat()

    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        try:
            cursor = conn.execute("""
                INSERT INTO events (
                    hostname, event_type, description,
                    local_ip, local_port, remote_ip, remote_port,
                    process_name, process_id, severity, timestamp, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.hostname, event.event_type, event.description,
                event.local_ip, event.local_port,
                event.remote_ip, event.remote_port,
                event.process_name, event.process_id,
                event.severity, event_time_iso, received_at,
            ))
            event_id = cursor.lastrowid
            findings = detect_remote_ip(event.remote_ip)

            # LS-002: Repeated Windows failed-logon events (existing rule).
            if event.event_type == "windows_failed_logon":
                window_start = (
                    datetime.fromisoformat(event_time_iso) - timedelta(minutes=5)
                ).isoformat()
                count = conn.execute("""
                    SELECT COUNT(*) FROM events
                    WHERE hostname = ? AND event_type = 'windows_failed_logon'
                      AND timestamp >= ? AND timestamp <= ?
                """, (event.hostname, window_start, event_time_iso)).fetchone()[0]
                if count >= 5 and count % 5 == 0:
                    findings.append({
                        "rule_id": "LS-002",
                        "title": "Repeated failed Windows sign-ins",
                        "description": (
                            f"{count} failed sign-in events recorded on "
                            f"{event.hostname} within five minutes. "
                            "Investigate the accounts and source addresses."
                        ),
                        "severity": "medium",
                    })

            for finding in findings:
                conn.execute("""
                    INSERT INTO alerts (
                        event_id, rule_id, title, description, severity, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    event_id, finding["rule_id"], finding["title"],
                    finding["description"], finding["severity"], received_at,
                ))
            conn.commit()
            return event_id, received_at
        except Exception:
            conn.rollback()
            raise


@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "LinkShield SIEM", "database": "SQLite"}


@app.post("/events", status_code=201)
def receive_event(event: SecurityEvent):
    event_id, received_at = save_event(event)
    return {
        "message": "Security event stored",
        "event_id": event_id,
        "received_at": received_at,
    }


@app.get("/events")
def get_events(
    limit: int = Query(default=100, ge=1, le=1000),
    hostname: str | None = Query(default=None, max_length=255),
    severity: Severity | None = Query(default=None),
    event_type: str | None = Query(default=None, max_length=100),
    since_minutes: int | None = Query(default=None, ge=1, le=43200),
):
    filters: list[str] = []
    params: list[object] = []
    if hostname:
        filters.append("hostname = ?")
        params.append(hostname)
    if severity:
        filters.append("severity = ?")
        params.append(severity)
    if event_type:
        filters.append("event_type = ?")
        params.append(event_type)
    if since_minutes is not None:
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
        filters.append("timestamp >= ?")
        params.append(cutoff)

    sql = "SELECT * FROM events"
    if filters:
        sql += " WHERE " + " AND ".join(filters)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(sql, params).fetchall()]


@app.get("/stats")
def get_stats():
    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        recent_total = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?", (since,)
        ).fetchone()[0]
        severities = conn.execute("""
            SELECT severity, COUNT(*) AS count FROM events GROUP BY severity
        """).fetchall()
        hosts = conn.execute("""
            SELECT hostname, COUNT(*) AS count
            FROM events GROUP BY hostname ORDER BY count DESC LIMIT 10
        """).fetchall()
        event_types = conn.execute("""
            SELECT event_type, COUNT(*) AS count
            FROM events GROUP BY event_type ORDER BY count DESC
        """).fetchall()

    counts = {item: 0 for item in ("info", "low", "medium", "high", "critical")}
    for row in severities:
        counts[row["severity"]] = row["count"]

    return {
        "total_events": total,
        "events_last_24_hours": recent_total,
        "by_severity": counts,
        "top_hosts": [dict(row) for row in hosts],
        "by_event_type": [dict(row) for row in event_types],
        "total_alerts": total_alerts,
    }


@app.get("/alerts")
def get_alerts(limit: int = Query(default=100, ge=1, le=1000)):
    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT a.id, a.event_id, a.rule_id, a.title, a.description,
                   a.severity, a.created_at, e.hostname, e.remote_ip,
                   e.remote_port, e.process_name
            FROM alerts AS a JOIN events AS e ON a.event_id = e.id
            ORDER BY a.id DESC LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# Network flows and investigation
# ---------------------------------------------------------------------------

@app.post("/flows", status_code=201)
def receive_flows(batch: FlowBatch):
    received_at = datetime.now(timezone.utc).isoformat()
    records = [(
        batch.hostname, flow.direction, flow.protocol,
        flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
        flow.packet_count, flow.byte_count, flow.dns_query,
        flow.observed_at.isoformat(), flow.process_name, flow.process_id,
        flow.observed_dns_name, received_at,
    ) for flow in batch.flows]

    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.executemany("""
            INSERT INTO network_flows (
                hostname, direction, protocol, src_ip, src_port, dst_ip,
                dst_port, packet_count, byte_count, dns_query, observed_at,
                process_name, process_id, observed_dns_name, received_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, records)
        conn.commit()

    return {"message": "Network flows stored", "flow_count": len(records)}


@app.get("/flows")
def get_flows(
    limit: int = Query(default=100, ge=1, le=1000),
    direction: Direction | None = Query(default=None),
    protocol: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=128),
):
    filters: list[str] = []
    params: list[object] = []
    if direction:
        filters.append("direction = ?")
        params.append(direction)
    if protocol:
        protocol = protocol.upper()
        if protocol not in ("TCP", "UDP", "ICMP", "ARP", "OTHER"):
            raise HTTPException(status_code=422, detail="Invalid protocol")
        filters.append("protocol = ?")
        params.append(protocol)
    if search and search.strip():
        fields = (
            "src_ip", "dst_ip", "process_name", "dns_query",
            "observed_dns_name", "hostname",
        )
        filters.append("(" + " OR ".join(
            f"instr(lower(COALESCE({field}, '')), lower(?)) > 0"
            for field in fields
        ) + ")")
        params.extend([search.strip()] * len(fields))

    sql = "SELECT * FROM network_flows"
    if filters:
        sql += " WHERE " + " AND ".join(filters)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(sql, params).fetchall()
    return [dict(row) for row in rows]


@app.get("/flows/stats")
def get_flow_stats():
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=60)).isoformat()
    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("""
            SELECT
                COALESCE(SUM(CASE WHEN direction = 'inbound'
                    THEN byte_count ELSE 0 END), 0) AS inbound_bytes,
                COALESCE(SUM(CASE WHEN direction = 'outbound'
                    THEN byte_count ELSE 0 END), 0) AS outbound_bytes,
                COALESCE(SUM(packet_count), 0) AS total_packets
            FROM network_flows WHERE received_at >= ?
        """, (cutoff,)).fetchone()
    return {
        "period_seconds": 60,
        "inbound_bytes": row["inbound_bytes"],
        "outbound_bytes": row["outbound_bytes"],
        "total_packets": row["total_packets"],
    }


@app.get("/flows/investigate")
def investigate_ip(
    ip: str = Query(..., min_length=3, max_length=45),
    minutes: int = Query(default=60, ge=1, le=1440),
):
    try:
        ip_address(ip)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid IP address") from exc

    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat()
    condition = """
        received_at >= ? AND (
            (direction = 'inbound' AND src_ip = ?) OR
            (direction = 'outbound' AND dst_ip = ?)
        )
    """
    parameters = (cutoff, ip, ip)

    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        summary = conn.execute(f"""
            SELECT COUNT(*) AS flow_records,
                COALESCE(SUM(CASE WHEN direction = 'inbound'
                    THEN packet_count ELSE 0 END), 0) AS inbound_packets,
                COALESCE(SUM(CASE WHEN direction = 'outbound'
                    THEN packet_count ELSE 0 END), 0) AS outbound_packets,
                COALESCE(SUM(CASE WHEN direction = 'inbound'
                    THEN byte_count ELSE 0 END), 0) AS inbound_bytes,
                COALESCE(SUM(CASE WHEN direction = 'outbound'
                    THEN byte_count ELSE 0 END), 0) AS outbound_bytes,
                MAX(received_at) AS last_seen
            FROM network_flows WHERE {condition}
        """, parameters).fetchone()
        protocols = conn.execute(f"""
            SELECT protocol, SUM(packet_count) AS packets,
                   SUM(byte_count) AS bytes
            FROM network_flows WHERE {condition}
            GROUP BY protocol ORDER BY packets DESC
        """, parameters).fetchall()
        flows = conn.execute(f"""
            SELECT * FROM network_flows WHERE {condition}
            ORDER BY id DESC LIMIT 100
        """, parameters).fetchall()

    return {
        "ip": ip,
        "period_minutes": minutes,
        "summary": dict(summary),
        "protocols": [dict(row) for row in protocols],
        "flows": [dict(row) for row in flows],
    }


@app.get("/flows/timeline")
def get_flow_timeline(minutes: int = Query(default=15, ge=1, le=60)):
    bucket_seconds = 10
    bucket_count = minutes * 60 // bucket_seconds
    now = datetime.now(timezone.utc)
    last_bucket = (int(now.timestamp()) // bucket_seconds) * bucket_seconds
    first_bucket = last_bucket - (bucket_count - 1) * bucket_seconds
    cutoff = datetime.fromtimestamp(first_bucket, tz=timezone.utc).isoformat()

    buckets = {}
    for index in range(bucket_count):
        epoch = first_bucket + index * bucket_seconds
        buckets[epoch] = {
            "timestamp": datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(),
            "inbound_bytes": 0,
            "outbound_bytes": 0,
            "inbound_packets": 0,
            "outbound_packets": 0,
        }

    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT
                (CAST(CAST(strftime('%s', received_at) AS INTEGER) / ? AS INTEGER)
                 * ?) AS bucket_epoch,
                direction, SUM(byte_count) AS total_bytes,
                SUM(packet_count) AS total_packets
            FROM network_flows
            WHERE received_at >= ? AND direction IN ('inbound', 'outbound')
            GROUP BY bucket_epoch, direction
            ORDER BY bucket_epoch ASC
        """, (bucket_seconds, bucket_seconds, cutoff)).fetchall()

    for row in rows:
        epoch = row["bucket_epoch"]
        if epoch not in buckets:
            continue
        direction = row["direction"]
        buckets[epoch][f"{direction}_bytes"] += row["total_bytes"] or 0
        buckets[epoch][f"{direction}_packets"] += row["total_packets"] or 0

    return {
        "period_minutes": minutes,
        "bucket_seconds": bucket_seconds,
        "points": list(buckets.values()),
    }


# ---------------------------------------------------------------------------
# Country-level geography (optional GeoLite2 file)
# ---------------------------------------------------------------------------

@app.get("/geo/traffic")
def get_geo_traffic():
    if not GEOIP_DATABASE.is_file():
        raise HTTPException(
            status_code=503, detail="GeoLite2 Country database not found"
        )

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    with closing(sqlite3.connect(DATABASE_PATH)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT direction,
                CASE WHEN direction = 'inbound' THEN src_ip ELSE dst_ip END
                    AS remote_ip,
                COUNT(*) AS flow_count,
                SUM(packet_count) AS packet_count,
                SUM(byte_count) AS byte_count
            FROM network_flows
            WHERE received_at >= ? AND direction IN ('inbound', 'outbound')
            GROUP BY direction, remote_ip
            ORDER BY byte_count DESC LIMIT 2000
        """, (cutoff,)).fetchall()

    locations = []
    with geoip2.database.Reader(str(GEOIP_DATABASE)) as reader:
        for row in rows:
            remote_ip = row["remote_ip"]
            if not remote_ip:
                continue
            try:
                if not ip_address(remote_ip).is_global:
                    continue
                country = reader.country(remote_ip).country
                if not country.iso_code:
                    continue
                locations.append({
                    "remote_ip": remote_ip,
                    "country": country.name,
                    "country_code": country.iso_code,
                    "direction": row["direction"],
                    "flow_count": row["flow_count"],
                    "packet_count": row["packet_count"],
                    "byte_count": row["byte_count"],
                })
            except (ValueError, geoip2.errors.AddressNotFoundError):
                continue

    return {
        "period": "last_24_hours",
        "location_precision": "country",
        "locations": locations,
    }


# ---------------------------------------------------------------------------
# Dashboard: LAST, so it does not shadow the API routes above.
# ---------------------------------------------------------------------------

if DASHBOARD_DIR.is_dir():
    app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard")
else:
    @app.get("/", include_in_schema=False)
    def dashboard_not_built():
        return {
            "message": "LinkShield API is running; dashboard build was not found.",
            "next_step": "Run 'npm run build' in the dashboard folder.",
        }
