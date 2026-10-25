
import socket
import threading

import psutil


class ProcessResolver:
    def __init__(self):
        self._owners = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._monitor,
            daemon=True,
        )

    def start(self):
        self._refresh()
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=3)

    def _monitor(self):
        while not self._stop.wait(2):
            self._refresh()

    def _refresh(self):
        owners = {}
        process_names = {}

        try:
            connections = psutil.net_connections(
                kind="inet"
            )
        except (psutil.AccessDenied, OSError):
            return

        for conn in connections:
            if conn.pid is None or not conn.laddr:
                continue

            if conn.type == socket.SOCK_STREAM:
                protocol = "TCP"
            elif conn.type == socket.SOCK_DGRAM:
                protocol = "UDP"
            else:
                continue

            pid = conn.pid

            if pid not in process_names:
                try:
                    process_names[pid] = (
                        psutil.Process(pid).name()
                    )
                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.ZombieProcess,
                ):
                    continue

            local_ip = conn.laddr.ip.split("%")[0]
            local_port = conn.laddr.port

            remote_ip = (
                conn.raddr.ip.split("%")[0]
                if conn.raddr else None
            )
            remote_port = (
                conn.raddr.port
                if conn.raddr else None
            )

            key = (
                protocol,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            )

            owners[key] = (
                process_names[pid],
                pid,
            )

        with self._lock:
            self._owners = owners

    def lookup(
        self,
        protocol,
        local_ip,
        local_port,
        remote_ip,
        remote_port,
    ):
        if protocol not in ("TCP", "UDP"):
            return None

        if local_port is None:
            return None

        wildcard_ip = (
            "::" if ":" in local_ip else "0.0.0.0"
        )

        candidates = [
            (
                protocol,
                local_ip,
                local_port,
                remote_ip,
                remote_port,
            ),
            (
                protocol,
                wildcard_ip,
                local_port,
                remote_ip,
                remote_port,
            ),
            (
                protocol,
                local_ip,
                local_port,
                None,
                None,
            ),
            (
                protocol,
                wildcard_ip,
                local_port,
                None,
                None,
            ),
        ]

        with self._lock:
            for key in candidates:
                owner = self._owners.get(key)

                if owner:
                    return owner

        return None
