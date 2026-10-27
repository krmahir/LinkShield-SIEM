
"""LinkShield SIEM development launcher for Windows.

Commands:
    python start_linkshield.py
    python start_linkshield.py --windows-events
    python start_linkshield.py --no-capture

React is served by FastAPI on 127.0.0.1:8001.
Only the separate capture supervisor requests UAC.
A capture failure does not stop the dashboard.
"""

from __future__ import annotations
from agent.collector_heartbeat import watch_process
from collections import deque

import argparse
import ctypes
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BACKEND = ROOT / "backend"
AGENT = ROOT / "agent"
DASHBOARD = ROOT / "dashboard"

HOST = "127.0.0.1"
PORT = 8001
URL = f"http://{HOST}:{PORT}"

PRINT_LOCK = threading.Lock()


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def running_as_admin() -> bool:
    try:
        return bool(
            ctypes.windll.shell32.IsUserAnAdmin()
        )
    except (AttributeError, OSError):
        return False


def port_busy() -> bool:
    try:
        with socket.create_connection(
            (HOST, PORT), timeout=0.5
        ):
            return True
    except OSError:
        return False


def check_files(capture: bool) -> tuple[Path, Path]:
    backend_python = (
        BACKEND / ".venv" / "Scripts" / "python.exe"
    )
    agent_python = (
        AGENT / ".venv" / "Scripts" / "python.exe"
    )

    required = {
        backend_python: "Backend Python virtual environment",
        agent_python: "Agent Python virtual environment",
        BACKEND / "main.py": "FastAPI backend",
        AGENT / "run_agent.py": "Connection event collector",
        DASHBOARD / "dist" / "index.html": "Compiled React dashboard",
    }

    if capture:
        required[
            AGENT / "flow_capture.py"
        ] = "Packet collector"

        required[
            AGENT / "elevated_capture.py"
        ] = "Elevated supervisor"

    for path, description in required.items():
        if not path.is_file():
            raise FileNotFoundError(
                f"{description} missing: {path}"
            )

    return backend_python, agent_python


def forward_output(
    name: str,
    proc: subprocess.Popen[str],
) -> None:
    if proc.stdout is None:
        return

    try:
        for line in proc.stdout:
            if line.strip():
                log(f"[{name}] {line.rstrip()}")

    except (OSError, UnicodeError) as exc:
        log(
            f"[{name}] Log stream stopped: {exc}"
        )

    finally:
        proc.stdout.close()


def start_service(
    name: str,
    command: list[str],
    cwd: Path,
) -> subprocess.Popen[str]:
    log(f"[START] {name}")

    proc = subprocess.Popen(
        command,
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    threading.Thread(
        target=forward_output,
        args=(name, proc),
        daemon=True,
    ).start()

    return proc


def wait_for_api(
    proc: subprocess.Popen[str],
    seconds: float = 25,
) -> bool:
    deadline = time.monotonic() + seconds

    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False

        try:
            with urllib.request.urlopen(
                f"{URL}/health",
                timeout=1,
            ) as response:
                if response.status == 200:
                    return True

        except (OSError, urllib.error.URLError):
            pass

        time.sleep(0.4)

    return False


def read_capture_status(
    status: Path,
) -> tuple[str | None, str | None]:
    try:
        value = status.read_text(
            encoding="utf-8",
            errors="replace",
        ).strip()

        return value, None

    except FileNotFoundError:
        return None, None

    except OSError as exc:
        return None, str(exc)


def launch_elevated_capture(
    agent_python: Path,
    marker: Path,
    windows_events: bool,
) -> None:
    arguments = [
        "-u",
        str(AGENT / "elevated_capture.py"),
        "--session",
        str(marker),
        "--parent-pid",
        str(os.getpid()),
    ]

    if windows_events:
        arguments.append("--windows-events")

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        str(agent_python),
        subprocess.list2cmdline(arguments),
        str(AGENT),
        1,
    )

    if result <= 32:
        raise OSError(
            "UAC declined or launch failed "
            f"(Windows code {result})"
        )


def stop_service(
    name: str,
    proc: subprocess.Popen[str],
) -> None:
    if proc.poll() is not None:
        return

    log(f"[STOP] {name}")

    try:
        proc.send_signal(signal.CTRL_BREAK_EVENT)
        proc.wait(timeout=3)
        return

    except (
        OSError,
        ValueError,
        subprocess.TimeoutExpired,
    ):
        pass

    subprocess.run(
        [
            "taskkill",
            "/PID",
            str(proc.pid),
            "/T",
            "/F",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    try:
        proc.wait(timeout=3)

    except subprocess.TimeoutExpired:
        log(
            f"[WARN] {name} did not exit after taskkill"
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run LinkShield locally"
    )

    parser.add_argument(
        "--windows-events",
        action="store_true",
        help=(
            "Also collect Windows Security logs "
            "in the elevated supervisor"
        ),
    )

    parser.add_argument(
        "--no-capture",
        action="store_true",
        help=(
            "Do not request UAC or capture raw packets"
        ),
    )

    parser.add_argument(
        "--no-browser",
        action="store_true",
        help=(
            "Do not automatically open the dashboard"
        ),
    )

    args = parser.parse_args()

    if sys.platform != "win32":
        log(
            "[ERROR] The development launcher "
            "requires Windows"
        )
        return 2

    if running_as_admin():
        log(
            "[ERROR] Run this launcher from normal "
            "PowerShell, not Administrator"
        )
        return 2

    if args.windows_events and args.no_capture:
        parser.error(
            "--windows-events cannot be combined "
            "with --no-capture"
        )

    try:
        backend_python, agent_python = check_files(
            not args.no_capture
        )

        if port_busy():
            raise RuntimeError(
                "Port 8001 is already in use; "
                "close the other LinkShield instance"
            )

    except (FileNotFoundError, RuntimeError) as exc:
        log(f"[ERROR] {exc}")
        return 2

    log(
        "=== LinkShield SIEM v0.4 (development) ==="
    )
    log(
        f"[UI] {URL} "
        "(React is served by FastAPI)"
    )
    log(
        "[INFO] The API and normal collectors "
        "run without Administrator privileges"
    )
    log(
        "[INFO] Ctrl+C stops the processes "
        "started by this launcher"
    )

    processes: list[
        tuple[str, subprocess.Popen[str]]
    ] = []

    event_process: subprocess.Popen[str] | None = None

    capture_started = False
    capture_problem_reported = False
    event_restart_attempts: deque[float] = deque()
    event_restart_due: float | None = None
    event_recovery_disabled = False

    with tempfile.TemporaryDirectory(
        prefix="linkshield_session_",
        ignore_cleanup_errors=True,
    ) as tmp_dir:

        session = Path(tmp_dir) / "active.marker"
        status_file = Path(tmp_dir) / "capture.status"

        session.write_text(
            "active\n",
            encoding="utf-8",
        )

        if not args.no_capture:
            status_file.write_text(
                "STARTING",
                encoding="utf-8",
            )

        def start_network_events() -> None:
            nonlocal event_process

            if (
                event_process is not None
                and event_process.poll() is None
            ):
                return

            try:
                proc = start_service(
                    "Events",
                    [
                        str(agent_python),
                        "-u",
                        "run_agent.py",
                        "--collectors",
                        "network",
                    ],
                    AGENT,
                )

                event_process = proc
                processes.append(("Events", proc))


                threading.Thread(
                    target=watch_process,
                    args=(
                        proc,
                        "network_events",
                        "run_agent.py manager running; "
                        "event delivery not independently verified",
                    ),
                    daemon=True,
                ).start()


                time.sleep(0.5)

                if proc.poll() is not None:
                    log(
                        "[WARN] Connection collector "
                        f"exited with {proc.returncode}"
                    )

            except OSError as exc:
                log(
                    "[WARN] Connection collector "
                    f"could not start: {exc}"
                )

        try:
            api = start_service(
                "API",
                [
                    str(backend_python),
                    "-u",
                    "-m",
                    "uvicorn",
                    "main:app",
                    "--host",
                    HOST,
                    "--port",
                    str(PORT),
                ],
                BACKEND,
            )

            processes.append(("API", api))

            if not wait_for_api(api):
                log(
                    "[ERROR] API failed to start; "
                    "review [API] output above"
                )
                return 1

            try:
                with urllib.request.urlopen(
                    URL,
                    timeout=3,
                ) as response:

                    content_type = response.headers.get(
                        "Content-Type",
                        "",
                    )

                    if "text/html" not in content_type:
                        log(
                            "[WARN] API is up but the "
                            "React dashboard was not served"
                        )

            except (
                OSError,
                urllib.error.URLError,
            ) as exc:
                log(
                    "[WARN] Dashboard root check "
                    f"failed: {exc}"
                )

            # If --windows-events is enabled, the
            # elevated supervisor runs run_agent with
            # all collectors. Starting another normal
            # collector would duplicate network events.
            if (
                args.no_capture
                or not args.windows_events
            ):
                start_network_events()

            if not args.no_capture:
                log(
                    "[UAC] Approve Administrator access "
                    "for packet capture only"
                )

                try:
                    launch_elevated_capture(
                        agent_python,
                        session,
                        args.windows_events,
                    )

                except OSError as exc:
                    capture_problem_reported = True

                    log(
                        "[WARN] Packet capture "
                        f"unavailable: {exc}"
                    )

                else:
                    deadline = time.monotonic() + 20
                    last_state = "STARTING"
                    last_error = None

                    while time.monotonic() < deadline:
                        state, error = read_capture_status(
                            status_file
                        )

                        if error:
                            last_error = error

                        if state:
                            last_state = state

                        if state == "READY":
                            capture_started = True

                            log(
                                "[CAPTURE] Elevated "
                                "capture supervisor is ready"
                            )
                            break

                        if state and (
                            state.startswith("ERROR")
                            or state == "STOPPED"
                        ):
                            log(
                                "[WARN] Packet capture "
                                f"failed: {state}"
                            )

                            capture_problem_reported = True
                            break

                        time.sleep(0.3)

                    if (
                        not capture_started
                        and not capture_problem_reported
                    ):
                        log(
                            "[WARN] Capture did not "
                            "become ready: "
                            f"{last_error or last_state}"
                        )

                        capture_problem_reported = True

                if (
                    args.windows_events
                    and not capture_started
                ):
                    log(
                        "[WARN] Falling back to normal "
                        "network-event collection"
                    )

                    start_network_events()

            log(
                "[READY] API and dashboard are available"
            )
            log(f"[OPEN] {URL}")

            if not args.no_browser:
                try:
                    webbrowser.open(URL)

                except OSError as exc:
                    log(
                        "[WARN] Browser could not "
                        f"open automatically: {exc}"
                    )

            capture_read_warned = False
            events_exit_warned = False

            while True:
                code = api.poll()

                if code is not None:
                    log(
                        "[ERROR] API exited "
                        f"with code {code}"
                    )
                    return 1

                
                normal_events_expected = (
                    args.no_capture
                    or not args.windows_events
                    or (
                        args.windows_events
                        and capture_problem_reported
                    )
                )

                if (
                    normal_events_expected
                    and not event_recovery_disabled
                    and (
                        event_process is None
                        or event_process.poll() is not None
                    )
                ):
                    now = time.monotonic()

                    if event_restart_due is None:
                        # Discard old failures outside the
                        # five-minute recovery window.
                        while (
                            event_restart_attempts
                            and now - event_restart_attempts[0] > 300
                        ):
                            event_restart_attempts.popleft()

                        if len(event_restart_attempts) >= 3:
                            event_recovery_disabled = True
                            log(
                                "[RECOVERY ERROR] Connection events "
                                "exceeded 3 restart attempts "
                                "within 5 minutes."
                            )
                        else:
                            event_restart_attempts.append(now)

                            delay = (1, 3, 10)[
                                len(event_restart_attempts) - 1
                            ]

                            event_restart_due = now + delay

                            log(
                                "[RECOVERY] Connection-event "
                                f"manager stopped. Restarting in "
                                f"{delay}s "
                                f"(attempt "
                                f"{len(event_restart_attempts)}/3)"
                            )

                    elif now >= event_restart_due:
                        event_restart_due = None
                        start_network_events()

                if (
                    capture_started
                    and not capture_problem_reported
                ):
                    state, error = read_capture_status(
                        status_file
                    )

                    if error:
                        if not capture_read_warned:
                            log(
                                "[WARN] Capture status "
                                "temporarily unreadable: "
                                f"{error}"
                            )

                            capture_read_warned = True

                    else:
                        capture_read_warned = False

                    if state and (
                        state.startswith("ERROR")
                        or state == "STOPPED"
                    ):
                        capture_problem_reported = True

                        log(
                            "[WARN] Packet capture "
                            f"has stopped: {state}"
                        )

                        log(
                            "[WARN] Dashboard and API "
                            "will remain online"
                        )

                        if args.windows_events:
                            log(
                                "[WARN] Restoring normal "
                                "network-event collection"
                            )

                            start_network_events()

                time.sleep(0.7)

        except KeyboardInterrupt:
            log(
                "\n[SHUTDOWN] Ctrl+C received"
            )
            return 0

        except OSError as exc:
            log(
                f"[ERROR] Could not start LinkShield: {exc}"
            )
            return 1

        finally:
            # Removing this marker asks the elevated
            # supervisor to stop its own collectors.
            try:
                session.unlink(missing_ok=True)

            except OSError as exc:
                log(
                    "[WARN] Could not remove "
                    f"session marker: {exc}"
                )

            for name, proc in reversed(processes):
                stop_service(name, proc)

            if capture_started:
                deadline = time.monotonic() + 4

                while time.monotonic() < deadline:
                    state, _ = read_capture_status(
                        status_file
                    )

                    if state == "STOPPED":
                        break

                    time.sleep(0.25)

            log(
                "[SHUTDOWN] LinkShield "
                "normal-user services stopped"
            )


if __name__ == "__main__":
    raise SystemExit(main())
