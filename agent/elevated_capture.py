
"""LinkShield elevated supervisor with bounded collector recovery.

Runs under the existing UAC prompt from start_linkshield.py.
Restarts failed child collectors without re-elevating the main app.
"""

from __future__ import annotations

import argparse
import ctypes
import signal
import subprocess
import sys
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path

import psutil
from collector_heartbeat import CollectorReporter


AGENT = Path(__file__).resolve().parent

RETRY_DELAYS = (1, 3, 10)
RETRY_WINDOW_SECONDS = 300


def log(message: str) -> None:
    print(message, flush=True)


def write_status(path: Path, status: str) -> None:
    try:
        path.write_text(status, encoding="utf-8")
    except OSError as exc:
        log(f"[STATUS WARN] {exc}")


def stop_child(proc: subprocess.Popen, name: str) -> None:
    if proc.poll() is not None:
        return

    log(f"[STOP] {name}")

    try:
        proc.send_signal(signal.CTRL_BREAK_EVENT)
        proc.wait(timeout=4)
        return
    except (
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
    ):
        pass

    subprocess.run(
        ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        log(f"[WARN] {name} did not stop")


def check_security_log() -> tuple[bool, str]:
    """Read-permission check, not proof of event ingestion."""

    try:
        result = subprocess.run(
            [
                "wevtutil.exe",
                "qe",
                "Security",
                "/rd:true",
                "/c:1",
                "/f:xml",
            ],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=8,
            check=False,
        )

        if result.returncode == 0:
            return (
                True,
                "Security log readable; ingestion not verified",
            )

        return (
            False,
            (result.stderr.strip() or "Security query failed")[:200],
        )

    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)[:200]


@dataclass
class Worker:
    name: str
    args: list[str]

    proc: subprocess.Popen | None = None
    started_at: float = 0.0
    restart_at: float = 0.0
    failures: deque[float] = field(default_factory=deque)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="LinkShield elevated collector supervisor"
    )

    parser.add_argument(
        "--session", type=Path, required=True
    )
    parser.add_argument(
        "--parent-pid", type=int, required=True
    )
    parser.add_argument(
        "--windows-events", action="store_true"
    )

    args = parser.parse_args()

    status_file = args.session.with_name("capture.status")

    capture_health = CollectorReporter("packet_capture")
    security_health = CollectorReporter("windows_security")
    network_health = CollectorReporter("network_events")

    workers = [
        Worker(
            "Packet Capture",
            [
                sys.executable,
                "-u",
                str(AGENT / "flow_capture.py"),
            ],
        )
    ]

    if args.windows_events:
        workers.append(
            Worker(
                "Windows Events",
                [
                    sys.executable,
                    "-u",
                    str(AGENT / "run_agent.py"),
                    "--collectors",
                    "all",
                ],
            )
        )

    failed = False
    last_status = ""

    last_security_probe = -1e9
    security_ok = False
    security_detail = "Not checked"

    def publish_status(value: str) -> None:
        nonlocal last_status

        if value != last_status:
            write_status(status_file, value)
            last_status = value
            log(f"[SUPERVISOR] {value}")

    def report_problem(
        worker: Worker,
        detail: str,
        stopped: bool = False,
    ) -> None:
        state = "stopped" if stopped else "degraded"

        if worker.name == "Packet Capture":
            capture_health.send(state, detail)
        else:
            security_health.send(state, detail)
            network_health.send(state, detail)

    def schedule_retry(
        worker: Worker,
        detail: str,
    ) -> None:
        worker.proc = None
        now = time.monotonic()

        while (
            worker.failures
            and now - worker.failures[0] > RETRY_WINDOW_SECONDS
        ):
            worker.failures.popleft()

        worker.failures.append(now)
        attempt = len(worker.failures)

        if attempt > len(RETRY_DELAYS):
            report_problem(
                worker,
                f"Recovery limit reached: {detail}",
                stopped=True,
            )
            raise RuntimeError(
                f"{worker.name} exceeded "
                f"{len(RETRY_DELAYS)} restarts "
                f"within {RETRY_WINDOW_SECONDS} seconds"
            )

        delay = RETRY_DELAYS[attempt - 1]
        worker.restart_at = now + delay

        report_problem(
            worker,
            f"Restart {attempt}/{len(RETRY_DELAYS)} "
            f"in {delay}s: {detail}",
        )

        log(
            f"[RECOVERY] {worker.name}: {detail}; "
            f"retry {attempt}/{len(RETRY_DELAYS)} "
            f"in {delay}s"
        )

    def launch(worker: Worker) -> None:
        try:
            worker.proc = subprocess.Popen(
                worker.args,
                cwd=str(AGENT),
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )

            worker.started_at = time.monotonic()

            log(
                f"[START] {worker.name} "
                f"(PID {worker.proc.pid})"
            )

        except OSError as exc:
            schedule_retry(
                worker,
                f"Cannot start: {exc}",
            )

    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError(
                "Capture supervisor was not elevated"
            )

        if (
            not args.session.is_file()
            or not psutil.pid_exists(args.parent_pid)
        ):
            raise RuntimeError(
                "Parent LinkShield session is not active"
            )

        if not (AGENT / "flow_capture.py").is_file():
            raise FileNotFoundError(
                "flow_capture.py is missing"
            )

        if (
            args.windows_events
            and not (AGENT / "run_agent.py").is_file()
        ):
            raise FileNotFoundError(
                "run_agent.py is missing"
            )

        log(
            "[CAPTURE] Elevated supervisor running; "
            "automatic recovery enabled"
        )

        for worker in workers:
            launch(worker)

        while (
            args.session.is_file()
            and psutil.pid_exists(args.parent_pid)
        ):
            now = time.monotonic()

            for worker in workers:
                if worker.proc is not None:
                    exit_code = worker.proc.poll()

                    if exit_code is not None:
                        schedule_retry(
                            worker,
                            f"exited with code {exit_code}",
                        )

                elif now >= worker.restart_at:
                    launch(worker)

            all_running = all(
                worker.proc is not None
                and worker.proc.poll() is None
                and time.monotonic() - worker.started_at >= 1
                for worker in workers
            )

            publish_status(
                "READY"
                if all_running
                else "DEGRADED: restarting collector"
            )

            # The packet collector reports its own heartbeat.
            # Manager liveness is not proof of event delivery.

            if args.windows_events:
                event_worker = workers[1]

                if (
                    event_worker.proc is not None
                    and event_worker.proc.poll() is None
                ):
                    if now - last_security_probe >= 60:
                        (
                            security_ok,
                            security_detail,
                        ) = check_security_log()

                        last_security_probe = time.monotonic()

                    network_health.send(
                        "running",
                        "Elevated event manager running; "
                        "ingestion not verified",
                        pid=event_worker.proc.pid,
                    )

                    security_health.send(
                        "running" if security_ok else "degraded",
                        security_detail,
                        pid=event_worker.proc.pid,
                    )

            time.sleep(0.5)

        return 0

    except Exception as exc:
        failed = True

        log(f"[CAPTURE ERROR] {exc}")
        publish_status(f"ERROR: {exc}")
        return 1

    finally:
        for worker in reversed(workers):
            if worker.proc is not None:
                stop_child(worker.proc, worker.name)

        capture_health.send(
            "stopped",
            "Elevated supervisor stopped",
        )

        if args.windows_events:
            network_health.send(
                "stopped",
                "Elevated event manager stopped",
            )

            security_health.send(
                "stopped",
                "Elevated supervisor stopped",
            )

        if not failed:
            publish_status("STOPPED")

        log("[CAPTURE] Supervisor exited")


if __name__ == "__main__":
    raise SystemExit(main())
