
"""Heartbeat reporting for LinkShield collectors."""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.error
import urllib.request

URL = "http://127.0.0.1:8001/collectors/heartbeat"


class CollectorReporter:
    def __init__(
        self,
        collector: str,
        interval: float = 5.0,
    ):
        if collector not in (
            "network_events",
            "windows_security",
            "packet_capture",
        ):
            raise ValueError(
                f"Unknown collector: {collector}"
            )

        self.collector = collector
        self.interval = interval
        self._last_attempt = 0.0
        self._last_state = None
        self._last_warning = 0.0

    def send(
        self,
        status: str = "running",
        detail: str = "",
        pid: int | None = None,
    ) -> None:
        if status not in (
            "running",
            "degraded",
            "stopped",
        ):
            raise ValueError(
                f"Unknown heartbeat state: {status}"
            )

        now = time.monotonic()

        if (
            status == self._last_state
            and now - self._last_attempt < self.interval
        ):
            return

        self._last_attempt = now
        self._last_state = status

        payload = {
            "collector": self.collector,
            "hostname": socket.gethostname(),
            "status": status,
            "pid": pid if pid is not None else os.getpid(),
            "detail": detail[:300],
        }

        request = urllib.request.Request(
            URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=1.5,
            ) as response:
                if response.status not in (200, 201):
                    raise RuntimeError(
                        f"Collector API HTTP {response.status}"
                    )

        except (OSError, RuntimeError) as exc:
            if now - self._last_warning > 30:
                print(
                    f"[HEALTH WARN] {self.collector}: {exc}",
                    flush=True,
                )
                self._last_warning = now


def watch_process(
    proc,
    collector: str,
    detail: str,
) -> None:
    """Monitor a collector manager's process liveness."""

    reporter = CollectorReporter(collector)

    while proc.poll() is None:
        reporter.send(
            "running",
            detail,
            pid=proc.pid,
        )
        time.sleep(1)

    reporter.send(
        "stopped",
        f"Collector manager exited (code {proc.returncode})",
        pid=proc.pid,
    )
