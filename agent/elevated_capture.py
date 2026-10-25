
"""Elevated supervisor for LinkShield packet capture."""

from __future__ import annotations

import argparse
import ctypes
import signal
import subprocess
import sys
import time
from pathlib import Path

import psutil


AGENT = Path(__file__).resolve().parent


def stop_child(proc, name):
    if proc.poll() is not None:
        return

    print(f"[CAPTURE] Stopping {name}...", flush=True)

    try:
        proc.send_signal(signal.CTRL_BREAK_EVENT)
        proc.wait(timeout=4)

    except (OSError, subprocess.TimeoutExpired, ValueError):
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


def main():
    parser = argparse.ArgumentParser(
        description="LinkShield elevated packet collector"
    )

    parser.add_argument(
        "--session",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--parent-pid",
        type=int,
        required=True,
    )

    parser.add_argument(
        "--windows-events",
        action="store_true",
    )

    args = parser.parse_args()

    status = args.session.with_name("capture.status")
    children = []
    had_error = False

    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise PermissionError(
                "Administrator privileges are required"
            )

        if not args.session.is_file():
            raise RuntimeError(
                "LinkShield launcher session is not active"
            )

        if not psutil.pid_exists(args.parent_pid):
            raise RuntimeError(
                "Parent launcher is not running"
            )

        flow_script = AGENT / "flow_capture.py"

        if not flow_script.is_file():
            raise FileNotFoundError(
                f"Missing collector: {flow_script}"
            )

        print(
            "[CAPTURE] Administrator privileges confirmed",
            flush=True,
        )

        flow_process = subprocess.Popen(
            [
                sys.executable,
                "-u",
                str(flow_script),
            ],
            cwd=str(AGENT),
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
        )

        children.append(("Network Flows", flow_process))

        if args.windows_events:
            security_process = subprocess.Popen(
                [
                    sys.executable,
                    "-u",
                    str(AGENT / "run_agent.py"),
                    "--collectors",
                    "all",
                ],
                cwd=str(AGENT),
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
            )

            children.append(
                ("Windows Security Events", security_process)
            )

        time.sleep(1)

        for name, process in children:
            if process.poll() is not None:
                raise RuntimeError(
                    f"{name} exited during startup"
                )

        status.write_text("READY", encoding="utf-8")

        print(
            "[CAPTURE] Packet capture started successfully",
            flush=True,
        )

        while (
            args.session.is_file()
            and psutil.pid_exists(args.parent_pid)
        ):
            for name, process in children:
                if process.poll() is not None:
                    raise RuntimeError(
                        f"{name} stopped unexpectedly"
                    )

            time.sleep(0.5)

        return 0

    except Exception as exc:
        had_error = True

        print(
            f"[CAPTURE ERROR] {exc}",
            flush=True,
        )

        try:
            status.write_text(
                f"ERROR: {exc}",
                encoding="utf-8",
            )
        except OSError:
            pass

        return 1

    finally:
        for name, process in reversed(children):
            stop_child(process, name)

        if not had_error:
            try:
                status.write_text(
                    "STOPPED",
                    encoding="utf-8",
                )
            except OSError:
                pass

        print("[CAPTURE] Stopped", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
