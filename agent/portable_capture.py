
"""LinkShield elevated capture helper. Requires Npcap on Windows."""
from __future__ import annotations

import argparse
import ctypes
import json
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from ipaddress import ip_address
from pathlib import Path

import psutil

API = "http://127.0.0.1:8001"
STOP = threading.Event()
LOCK = threading.Lock()
PENDING = {}


def log(message):
    print(message, flush=True)


def status_write(path, value):
    try:
        path.write_text(value, encoding="utf-8")
    except OSError as exc:
        log(f"[STATUS WARN] {exc}")


def post(route, data):
    request = urllib.request.Request(
        API + route,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=7) as reply:
        if reply.status not in (200, 201):
            raise RuntimeError(f"HTTP {reply.status}")


def active_local_ips():
    result = set()
    stats = psutil.net_if_stats()
    for name, entries in psutil.net_if_addrs().items():
        if not stats.get(name) or not stats[name].isup:
            continue
        for item in entries:
            if item.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            try:
                ip = ip_address(item.address.split("%")[0])
                if not ip.is_loopback and not ip.is_unspecified:
                    result.add(str(ip))
            except ValueError:
                pass
    return result


def process_monitor(cache):
    while not STOP.is_set():
        current = {}
        names = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid is None or not conn.laddr:
                    continue
                pid = conn.pid
                if pid not in names:
                    try:
                        names[pid] = psutil.Process(pid).name()
                    except psutil.Error:
                        names[pid] = None
                protocol = (
                    "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                )
                local = conn.laddr
                current[(protocol, local.ip, local.port)] = (
                    names[pid], pid
                )
        except (psutil.Error, OSError) as exc:
            log(f"[PROCESS WARN] {exc}")
        with LOCK:
            cache.clear()
            cache.update(current)
        STOP.wait(2)


def flush_flows():
    with LOCK:
        rows = list(PENDING.items())
        PENDING.clear()
    if not rows:
        return
    for offset in range(0, len(rows), 200):
        chunk = rows[offset:offset + 200]
        try:
            post("/flows", {
                "hostname": socket.gethostname(),
                "flows": [value for _, value in chunk],
            })
            log(f"[FLOWS] Sent {len(chunk)} flows")
        except Exception as exc:
            log(f"[FLOWS WARN] {exc}")
            with LOCK:
                for key, value in rows[offset:]:
                    if key not in PENDING:
                        PENDING[key] = value
                    else:
                        PENDING[key]["packet_count"] += value["packet_count"]
                        PENDING[key]["byte_count"] += value["byte_count"]
            return


def security_events():
    seen = set()
    ns = "{http://schemas.microsoft.com/win/2004/08/events/event}"
    query = (
        "*[System[(EventID=4624 or EventID=4625) "
        "and TimeCreated[timediff(@SystemTime) <= 180000]]]"
    )
    while not STOP.is_set():
        try:
            result = subprocess.run(
                [
                    "wevtutil.exe", "qe", "Security",
                    f"/q:{query}", "/rd:true",
                    "/c:200", "/f:xml"
                ],
                capture_output=True,
                timeout=15,
            )
            if result.returncode:
                log(
                    "[EVENT WARN] " +
                    result.stderr.decode(errors="replace")[:250]
                )
                STOP.wait(30)
                continue
            raw = result.stdout
            if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
                output = raw.decode("utf-16", errors="replace")
            else:
                output = raw.decode("utf-8-sig", errors="replace")
            chunks = re.findall(
                r"<Event\b[^>]*>.*?</Event>",
                output,
                re.DOTALL,
            )
            for chunk in reversed(chunks):
                try:
                    root = ET.fromstring(chunk)
                    sys_node = root.find(ns + "System")
                    if sys_node is None:
                        continue
                    record = sys_node.findtext(
                        ns + "EventRecordID"
                    )
                    event_id = sys_node.findtext(ns + "EventID")
                    if (
                        not record or record in seen
                        or event_id not in ("4624", "4625")
                    ):
                        continue
                    values = {
                        elem.get("Name"): elem.text or ""
                        for elem in root.findall(
                            ".//" + ns + "EventData/" + ns + "Data"
                        )
                    }
                    kind = values.get("LogonType", "")
                    if kind not in ("2", "3", "7", "10", "11"):
                        seen.add(record)
                        continue
                    if event_id == "4624" and kind == "3":
                        seen.add(record)
                        continue

                    failed = event_id == "4625"
                    event = {
                        "hostname": socket.gethostname(),
                        "event_type": (
                            "windows_failed_logon"
                            if failed
                            else "windows_successful_logon"
                        ),
                        "description": (
                            f"Windows {'failed' if failed else 'successful'} "
                            f"logon: {values.get('TargetUserName', 'unknown')} "
                            f"(type {kind})"
                        ),
                        "severity": "medium" if failed else "info",
                    }
                    created = sys_node.find(
                        ns + "TimeCreated"
                    )
                    if (
                        created is not None
                        and created.get("SystemTime")
                    ):
                        event["timestamp"] = created.get(
                            "SystemTime"
                        )
                    ip = values.get("IpAddress", "")
                    try:
                        if ip and not ip_address(ip).is_loopback:
                            event["remote_ip"] = ip
                    except ValueError:
                        pass

                    post("/events", event)
                    seen.add(record)
                    log(
                        f"[EVENT] Windows event "
                        f"{event_id} recorded"
                    )
                except Exception as exc:
                    log(f"[EVENT WARN] {exc}")
            if len(seen) > 5000:
                seen.clear()
        except Exception as exc:
            log(f"[EVENT WARN] {exc}")
        STOP.wait(20)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--session", type=Path, required=True
    )
    parser.add_argument(
        "--status", type=Path, required=True
    )
    parser.add_argument(
        "--parent-pid", type=int, required=True
    )
    parser.add_argument(
        "--windows-events", action="store_true"
    )
    args = parser.parse_args()

    try:
        if (
            sys.platform != "win32"
            or not ctypes.windll.shell32.IsUserAnAdmin()
        ):
            raise PermissionError(
                "Launch from LinkShield.exe and approve UAC"
            )

        if (
            not args.session.is_file()
            or not psutil.pid_exists(args.parent_pid)
        ):
            raise RuntimeError(
                "Parent application is no longer running"
            )

        from scapy.all import (
            AsyncSniffer, conf, IP, IPv6,
            TCP, UDP, ICMP, ARP
        )

        iface = conf.route.route("1.1.1.1")[0]
        if iface is None:
            raise RuntimeError(
                "Default network adapter not found"
            )
        local_ips = active_local_ips()
        if not local_ips:
            raise RuntimeError(
                "No active local network addresses found"
            )

        log(f"[CAPTURE] Network adapter: {iface}")
        log(
            f"[CAPTURE] Local IPs: "
            f"{', '.join(sorted(local_ips))}"
        )

        owners = {}
        threading.Thread(
            target=process_monitor,
            args=(owners,),
            daemon=True,
        ).start()

        def handle_packet(packet):
            try:
                if IP in packet:
                    src, dst = packet[IP].src, packet[IP].dst
                elif IPv6 in packet:
                    src, dst = (
                        packet[IPv6].src,
                        packet[IPv6].dst,
                    )
                elif ARP in packet:
                    src, dst = (
                        packet[ARP].psrc,
                        packet[ARP].pdst,
                    )
                else:
                    return

                if src in local_ips:
                    direction, local_ip = "outbound", src
                elif dst in local_ips:
                    direction, local_ip = "inbound", dst
                else:
                    return

                if TCP in packet:
                    protocol = "TCP"
                    src_port = int(packet[TCP].sport)
                    dst_port = int(packet[TCP].dport)
                elif UDP in packet:
                    protocol = "UDP"
                    src_port = int(packet[UDP].sport)
                    dst_port = int(packet[UDP].dport)
                elif ICMP in packet:
                    protocol = "ICMP"
                    src_port = dst_port = None
                else:
                    protocol = (
                        "ARP" if ARP in packet else "OTHER"
                    )
                    src_port = dst_port = None

                local_port = (
                    src_port
                    if direction == "outbound"
                    else dst_port
                )

                with LOCK:
                    owner = owners.get(
                        (protocol, local_ip, local_port)
                    )
                name, pid = (
                    owner if owner else (None, None)
                )

                key = (
                    direction, protocol, src,
                    src_port, dst, dst_port
                )
                now = datetime.now(
                    timezone.utc
                ).isoformat()

                with LOCK:
                    if key in PENDING:
                        PENDING[key]["packet_count"] += 1
                        PENDING[key]["byte_count"] += len(
                            packet
                        )
                        PENDING[key]["observed_at"] = now
                    else:
                        PENDING[key] = {
                            "direction": direction,
                            "protocol": protocol,
                            "src_ip": src,
                            "src_port": src_port,
                            "dst_ip": dst,
                            "dst_port": dst_port,
                            "packet_count": 1,
                            "byte_count": len(packet),
                            "observed_at": now,
                            "process_name": name,
                            "process_id": pid,
                        }

            except Exception as exc:
                log(f"[PACKET WARN] {exc}")

        sniffer = AsyncSniffer(
            iface=iface,
            prn=handle_packet,
            store=False,
            promisc=False,
        )
        sniffer.start()
        time.sleep(1)

        if not sniffer.running:
            raise RuntimeError(
                "Packet capture failed; check Npcap"
            )

        if args.windows_events:
            threading.Thread(
                target=security_events,
                daemon=True,
            ).start()
            log(
                "[EVENT] Windows Security events enabled"
            )

        status_write(args.status, "READY")
        log(
            "[CAPTURE] Running; close LinkShield.exe "
            "to stop"
        )

        try:
            while (
                args.session.is_file()
                and psutil.pid_exists(args.parent_pid)
            ):
                if not sniffer.running:
                    raise RuntimeError(
                        "Sniffer stopped unexpectedly"
                    )
                STOP.wait(5)
                flush_flows()
        finally:
            STOP.set()
            if sniffer.running:
                sniffer.stop()
            flush_flows()

        status_write(args.status, "STOPPED")
        return 0

    except Exception as exc:
        status_write(
            args.status,
            f"ERROR: {type(exc).__name__}: {exc}",
        )
        log(
            f"[CAPTURE ERROR] "
            f"{type(exc).__name__}: {exc}"
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
