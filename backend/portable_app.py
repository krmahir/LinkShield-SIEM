
"""LinkShield Portable launcher: API, dashboard, events, capture helper."""
from __future__ import annotations

import argparse
import ctypes
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import urllib.request
import webbrowser
from ipaddress import ip_address
from pathlib import Path

HOST = "127.0.0.1"
PORT = 8001
URL = f"http://{HOST}:{PORT}"
STOP = threading.Event()


def program_folder():
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def configure_storage():
    folder = program_folder()
    if (folder / "portable-data.flag").exists():
        data = folder / "data"
        print("[DATA] USB storage mode enabled", flush=True)
    else:
        data = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "LinkShield"
    data.mkdir(parents=True, exist_ok=True)
    os.environ["LINKSHIELD_DATA_DIR"] = str(data)
    print(f"[DATA] {data}", flush=True)


def open_dashboard():
    for _ in range(100):
        if STOP.is_set():
            return
        try:
            with urllib.request.urlopen(URL + "/health", timeout=1) as response:
                if response.status == 200:
                    webbrowser.open(URL)
                    return
        except OSError:
            pass
        STOP.wait(0.2)


def socket_monitor(backend):
    import psutil

    previous = set()
    hostname = socket.gethostname()

    while not STOP.is_set():
        current = set()
        try:
            connections = psutil.net_connections(kind="tcp")
        except (psutil.AccessDenied, OSError) as exc:
            print(f"[SOCKET WARN] {exc}", flush=True)
            STOP.wait(5)
            continue

        for conn in connections:
            if conn.status != psutil.CONN_ESTABLISHED:
                continue
            if not conn.laddr or not conn.raddr:
                continue

            local_ip = conn.laddr.ip
            local_port = conn.laddr.port
            remote_ip = conn.raddr.ip
            remote_port = conn.raddr.port

            try:
                if ip_address(remote_ip.split("%")[0]).is_loopback:
                    continue
            except ValueError:
                continue

            identity = (
                conn.pid, local_ip, local_port,
                remote_ip, remote_port
            )
            current.add(identity)

            if identity in previous:
                continue

            process_name = None
            if conn.pid is not None:
                try:
                    process_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess,
                        psutil.AccessDenied,
                        psutil.ZombieProcess):
                    pass

            try:
                backend.save_event(backend.SecurityEvent(
                    hostname=hostname,
                    event_type="network_connection",
                    description=(
                        f"Observed TCP connection to "
                        f"{remote_ip}:{remote_port}"
                    ),
                    local_ip=local_ip,
                    local_port=local_port,
                    remote_ip=remote_ip,
                    remote_port=remote_port,
                    process_name=process_name,
                    process_id=conn.pid,
                ))
            except Exception as exc:
                print(f"[SOCKET WARN] {exc}", flush=True)

        previous = current
        STOP.wait(2)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def launch_capture(helper, session, status, windows_events):
    import subprocess

    arguments = [
        "--session", str(session),
        "--status", str(status),
        "--parent-pid", str(os.getpid()),
    ]
    if windows_events:
        arguments.append("--windows-events")

    parameters = subprocess.list2cmdline(arguments)

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        str(helper),
        parameters,
        str(helper.parent),
        1,
    )

    if result <= 32:
        print(
            f"[CAPTURE WARN] Elevation declined or failed: {result}",
            flush=True,
        )
        return False

    print("[CAPTURE] Elevated collector launched", flush=True)
    return True


def capture_status_monitor(status):
    for _ in range(50):
        if STOP.is_set():
            return
        try:
            message = status.read_text(
                encoding="utf-8"
            ).strip()
        except OSError:
            message = "STARTING"

        if message == "READY":
            print("[CAPTURE] Packet capture ACTIVE", flush=True)
            return
        if message.startswith("ERROR:") or message == "STOPPED":
            print(f"[CAPTURE WARN] {message}", flush=True)
            return

        STOP.wait(0.4)

    if not STOP.is_set():
        print("[CAPTURE WARN] No ready signal received", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--windows-events", action="store_true")
    parser.add_argument("--no-capture", action="store_true")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("[ERROR] Windows is required", flush=True)
        return 2

    if is_admin():
        print(
            "[ERROR] Start LinkShield.exe as a normal user. "
            "Only the capture helper needs elevation.",
            flush=True,
        )
        return 2

    with socket.socket() as sock:
        if sock.connect_ex((HOST, PORT)) == 0:
            print("[ERROR] Port 8001 is already in use", flush=True)
            return 2

    configure_storage()

    import main as backend
    import uvicorn

    if not (backend.DASHBOARD_DIR / "index.html").exists():
        print("[ERROR] React dashboard build is missing", flush=True)
        return 2

    print(f"[UI] {URL}", flush=True)

    session_dir = Path(
        tempfile.mkdtemp(prefix="linkshield_capture_")
    )
    session = session_dir / "session.active"
    status = session_dir / "capture.status"

    session.write_text("active", encoding="utf-8")
    status.write_text("STARTING", encoding="utf-8")

    try:
        if not args.no_capture:
            helper = program_folder() / "LinkShieldCapture.exe"

            if helper.exists():
                if launch_capture(
                    helper, session, status, args.windows_events
                ):
                    threading.Thread(
                        target=capture_status_monitor,
                        args=(status,),
                        daemon=True,
                    ).start()
            else:
                print(
                    "[CAPTURE WARN] LinkShieldCapture.exe missing",
                    flush=True,
                )

        if not args.no_browser:
            threading.Thread(
                target=open_dashboard,
                daemon=True,
            ).start()

        threading.Thread(
            target=socket_monitor,
            args=(backend,),
            daemon=True,
        ).start()

        print("[SOCKET] TCP connection monitoring active", flush=True)
        print("[INFO] Press Ctrl+C to stop LinkShield", flush=True)

        uvicorn.run(
            backend.app,
            host=HOST,
            port=PORT,
            loop="asyncio",
            http="h11",
            ws="none",
            log_level="warning",
        )
    finally:
        STOP.set()
        try:
            session.unlink(missing_ok=True)
        except OSError:
            pass
        time.sleep(0.6)
        shutil.rmtree(session_dir, ignore_errors=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
