"""LinkShield Windows development launcher.

Run from a NORMAL (non-administrator) PowerShell window:
    python start_linkshield.py

API, web UI, and ordinary network-event monitoring run unprivileged.
Windows UAC elevates ONLY the separate packet-capture supervisor.
Use --windows-events to include the privileged Windows Security log collector.
Use --no-capture to launch the UI and backend without requiring UAC.

Development helper only: not an installed Windows service, not production-ready.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import shutil
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
PRINT_LOCK = threading.Lock()


def log(message: str) -> None:
    with PRINT_LOCK:
        print(message, flush=True)


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def verify_file(path: Path, description: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"{description} is missing: {path}")


def port_is_busy(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.4):
            return True
    except OSError:
        return False


def read_logs(label: str, process: subprocess.Popen[str]) -> None:
    if process.stdout is None:
        return
    try:
        for line in process.stdout:
            if line.strip():
                log(f"[{label}] {line.rstrip()}")
    except (OSError, UnicodeError) as exc:
        log(f"[{label}] Output stream stopped: {exc}")


def start_service(label: str, command: list[str], cwd: Path) -> subprocess.Popen[str]:
    log(f"[START] {label}")
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
    threading.Thread(target=read_logs, args=(label, proc), daemon=True).start()
    return proc


def wait_for_http(url: str, process: subprocess.Popen[str], timeout: float = 25.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(url, timeout=0.8) as response:
                if response.status < 500:
                    return True
        except (OSError, urllib.error.URLError):
            pass
        time.sleep(0.4)
    return False


def read_capture_status(path: Path) -> tuple[str | None, str | None]:
    """Read elevated-agent status without crashing on Windows file/ACL races.

    The elevated process may be updating the file, or Windows may briefly
    deny access. Return a diagnostic instead of raising from a status check.
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip(), None
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, f"{type(exc).__name__}: {exc}"


def request_elevation(python_exe: Path, helper: Path, session_file: Path,
                      parent_pid: int, windows_events: bool) -> None:
    """UAC elevation is limited to the agent venv + capture supervisor."""
    cmd = ["-u", str(helper), "--session", str(session_file), "--parent-pid", str(parent_pid)]
    if windows_events:
        cmd.append("--windows-events")
    params = subprocess.list2cmdline(cmd)

    # ShellExecuteW with the 'runas' verb displays the standard Windows UAC prompt.
    # lpFile is the agent venv Python; no elevation is applied to this launcher.
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", str(python_exe), params, str(AGENT), 1,
    )
    if result <= 32:
        raise OSError(f"Windows denied or could not launch elevated capture (code {result}).")


def stop_process(label: str, process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    log(f"[STOP] {label}")
    subprocess.run(
        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        log(f"[WARN] {label} did not stop cleanly.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Start all LinkShield development components.")
    parser.add_argument("--windows-events", action="store_true",
                        help="Include Windows Security log monitoring in the elevated agent.")
    parser.add_argument("--no-capture", action="store_true",
                        help="Start API, UI and network events without a UAC prompt.")
    parser.add_argument("--no-browser", action="store_true",
                        help="Do not automatically open the dashboard in your browser.")
    args = parser.parse_args()

    if sys.platform != "win32":
        log("[ERROR] This launcher is for Windows.")
        return 2
    if is_admin():
        log("[ERROR] The launcher is elevated. Open a NORMAL PowerShell window instead.")
        log("        Only the network capture agent should receive Administrator access.")
        return 2
    if args.windows_events and args.no_capture:
        parser.error("--windows-events and --no-capture cannot be combined")

    backend_python = BACKEND / ".venv" / "Scripts" / "python.exe"
    agent_python = AGENT / ".venv" / "Scripts" / "python.exe"
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    try:
        verify_file(backend_python, "Backend Python")
        verify_file(agent_python, "Agent Python")
        verify_file(BACKEND / "main.py", "Backend application")
        verify_file(AGENT / "flow_capture.py", "Packet capture collector")
        verify_file(AGENT / "elevated_capture.py", "Elevated capture supervisor")
        verify_file(AGENT / "run_agent.py", "Connection event collector")
        verify_file(DASHBOARD / "package.json", "Frontend package manifest")
        if npm is None:
            raise FileNotFoundError("npm.cmd not found. Install Node.js and reopen PowerShell.")
        if not (DASHBOARD / "node_modules").is_dir():
            raise FileNotFoundError("Dashboard dependencies absent. Run: cd dashboard; npm install")
        for port in (8001, 5173):
            if port_is_busy(port):
                raise RuntimeError(f"Port {port} is already in use. Stop your old LinkShield windows first.")
    except (FileNotFoundError, RuntimeError) as exc:
        log(f"[ERROR] {exc}")
        return 2

    running: list[tuple[str, subprocess.Popen[str]]] = []
    log("=== LinkShield SIEM (development) ===")
    log("Running API and dashboard as a standard user.")
    log("Network packet capture requests a SEPARATE UAC prompt.")
    log("Dashboard: http://127.0.0.1:5173")
    log("Press Ctrl+C here to stop the managed stack.\n")

    # Marker lives in the system temp directory, not the OneDrive project folder.
    # The privileged supervisor watches it and the parent PID to know when to stop.
    with tempfile.TemporaryDirectory(prefix="linkshield_session_", ignore_cleanup_errors=True) as temp_dir:
        session = Path(temp_dir) / "active.marker"
        status = Path(temp_dir) / "capture.status"
        session.write_text("LinkShield local development session\n", encoding="utf-8")
        # Create the status file BEFORE UAC elevation. This preserves the
        # original user's file ownership/ACL when the elevated helper writes.
        if not args.no_capture:
            status.write_text("STARTING", encoding="utf-8")
        try:
            api = start_service(
                "API",
                [str(backend_python), "-u", "-m", "uvicorn", "main:app",
                 "--host", "127.0.0.1", "--port", "8001"],
                BACKEND,
            )
            running.append(("API", api))
            if not wait_for_http("http://127.0.0.1:8001/health", api):
                log("[ERROR] API failed to become available on port 8001.")
                return 1

            ui = start_service(
                "Dashboard",
                [str(npm), "run", "dev", "--", "--host", "127.0.0.1",
                 "--port", "5173", "--strictPort"],
                DASHBOARD,
            )
            running.append(("Dashboard", ui))
            if not wait_for_http("http://127.0.0.1:5173", ui):
                log("[ERROR] Dashboard failed to become available on port 5173.")
                return 1

            if not args.windows_events:
                events = start_service(
                    "Events",
                    [str(agent_python), "-u", "run_agent.py", "--collectors", "network"],
                    AGENT,
                )
                running.append(("Events", events))
                time.sleep(0.5)
                if events.poll() is not None:
                    log("[ERROR] Network event collector exited on startup.")
                    return 1

            if not args.no_capture:
                log("[UAC] Accept Administrator permission for the packet collector ONLY.")
                try:
                    request_elevation(
                        agent_python, AGENT / "elevated_capture.py", session,
                        os.getpid(), args.windows_events,
                    )
                except OSError as exc:
                    log(f"[ERROR] {exc}")
                    return 1

                deadline = time.monotonic() + 20.0
                last_state = "STARTING"
                last_read_error = None
                while time.monotonic() < deadline:
                    state, error = read_capture_status(status)
                    if error:
                        last_read_error = error
                    if state:
                        last_state = state
                    if state == "READY":
                        break
                    if state and state.startswith("ERROR"):
                        log(f"[ERROR] Elevated capture failed: {state}")
                        return 1
                    time.sleep(0.3)
                else:
                    detail = last_read_error or last_state or "No startup acknowledgement"
                    log(f"[ERROR] Elevated capture was not ready: {detail}")
                    log("[HINT] Review the elevated capture window for its first error.")
                    return 1

            log("\n[READY] API and dashboard are available; collectors started.")
            log("[OPEN] http://127.0.0.1:5173")
            if not args.no_browser:
                try:
                    webbrowser.open("http://127.0.0.1:5173")
                except OSError:
                    log("[WARN] Could not open browser automatically; use the URL above.")
            status_read_warning_shown = False
            while True:
                for name, proc in running:
                    code = proc.poll()
                    if code is not None:
                        log(f"[ERROR] {name} exited with code {code}.")
                        return 1
                if not args.no_capture:
                    current, read_error = read_capture_status(status)
                    if read_error:
                        if not status_read_warning_shown:
                            log(f"[WARN] Capture status temporarily unreadable: {read_error}")
                            status_read_warning_shown = True
                    else:
                        status_read_warning_shown = False
                    if current and (current.startswith("ERROR") or current == "STOPPED"):
                        log(f"[ERROR] Capture supervisor status: {current}")
                        return 1
                time.sleep(0.6)
        except KeyboardInterrupt:
            log("\n[SHUTDOWN] Ctrl+C received.")
            return 0
        except OSError as exc:
            log(f"[ERROR] Could not start LinkShield: {exc}")
            return 1
        finally:
            # Elevated supervisor notices this marker has vanished and stops capture.
            try:
                session.unlink(missing_ok=True)
            except OSError:
                pass
            for name, proc in reversed(running):
                stop_process(name, proc)
            # Give the elevated supervisor a chance to acknowledge and shut down.
            deadline = time.monotonic() + 5
            while not args.no_capture and time.monotonic() < deadline:
                current, read_error = read_capture_status(status)
                # This acknowledgement is best-effort; do not crash on a
                # Windows ACL/sharing violation during elevated shutdown.
                if current == "STOPPED" or read_error:
                    break
                time.sleep(0.25)
            log("[SHUTDOWN] Normal-user components stopped; capture stop requested.")


if __name__ == "__main__":
    raise SystemExit(main())
