
import socket
import time

import psutil
import requests

from transport import post_event


API_URL = "http://127.0.0.1:8001/events"
POLL_INTERVAL = 3


def get_process_name(pid):
    if pid is None:
        return "unknown"

    try:
        process = psutil.Process(pid)
        return process.name()

    except (
        psutil.NoSuchProcess,
        psutil.AccessDenied,
        psutil.ZombieProcess,
    ):
        return "unknown"


def collect_connections():
    active = {}

    connections = psutil.net_connections(kind="tcp")

    for conn in connections:
        if conn.status != psutil.CONN_ESTABLISHED:
            continue

        if not conn.laddr or not conn.raddr:
            continue

        key = (
            conn.pid,
            conn.laddr.ip,
            conn.laddr.port,
            conn.raddr.ip,
            conn.raddr.port,
        )

        active[key] = conn

    return active


def send_event(conn):
    process_name = get_process_name(conn.pid)

    
    event = {
        "hostname": socket.gethostname(),
        "event_type": "network_connection",
        "description": (
            f"TCP connection observed: "
            f"{process_name} (PID {conn.pid})"
        ),
        "local_ip": conn.laddr.ip,
        "local_port": conn.laddr.port,
        "remote_ip": conn.raddr.ip,
        "remote_port": conn.raddr.port,
        "process_name": process_name,
        "process_id": conn.pid,
        "severity": "info",
    }


    try:
        post_event(event)

        print(
            f"[SENT] {process_name} -> "
            f"{conn.raddr.ip}:{conn.raddr.port}"
        )

    except requests.RequestException as error:
        print(f"[ERROR] Event not delivered: {error}")


def main():
    print("LinkShield SIEM Agent started")

    previous_connections = set()

    while True:
        try:
            current = collect_connections()

            for key, conn in current.items():
                if key not in previous_connections:
                    send_event(conn)

            previous_connections = set(current.keys())

        except (psutil.Error, OSError) as error:
            print(f"[ERROR] Collection failed: {error}")

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
