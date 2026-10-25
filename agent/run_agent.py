
import argparse
import subprocess
import sys
import time

from pathlib import Path


AGENT_DIR = Path(__file__).resolve().parent

COLLECTORS = {
    "network": "agent.py",
    "windows": "windows_events.py",
}


def start_collector(name):
    script = AGENT_DIR / COLLECTORS[name]

    process = subprocess.Popen(
        [
            sys.executable,
            "-u",
            str(script),
        ],
        cwd=AGENT_DIR,
    )

    print(
        f"[STARTED] {name} collector "
        f"(PID {process.pid})",
        flush=True,
    )

    return process


def main():
    parser = argparse.ArgumentParser(
        description="LinkShield SIEM Agent"
    )

    parser.add_argument(
        "--collectors",
        choices=["network", "windows", "all"],
        default="network",
        help="Collectors to run",
    )

    args = parser.parse_args()

    if args.collectors == "all":
        selected = ["network", "windows"]
    else:
        selected = [args.collectors]

    processes = {}

    print("LinkShield SIEM Agent Manager")

    try:
        for name in selected:
            processes[name] = start_collector(name)

        while True:
            for name, process in processes.items():
                return_code = process.poll()

                if return_code is not None:
                    print(
                        f"[STOPPED] {name} collector "
                        f"exited with code {return_code}"
                    )
                    return

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[STOPPING] Agent manager")

    finally:
        for process in processes.values():
            if process.poll() is None:
                process.terminate()

        for process in processes.values():
            try:
                process.wait(timeout=5)

            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

        print("[STOPPED] All managed collectors")


if __name__ == "__main__":
    main()
