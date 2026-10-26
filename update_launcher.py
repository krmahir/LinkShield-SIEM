
from pathlib import Path
import re
import shutil

path = Path("start_linkshield.py")
source = path.read_text(encoding="utf-8")

if 'npm = shutil.which("npm.cmd")' not in source:
    raise SystemExit(
        "Launcher version differs. No changes made."
    )

replacements = [
    (
        r'(?m)^    npm = shutil\.which\("npm\.cmd"\) or shutil\.which\("npm"\)\n',
        "",
    ),
    (
        r'(?s)        verify_file\(DASHBOARD / "package\.json", "Frontend package manifest"\)\n.*?                raise RuntimeError\(f"Port \{port\} is already in use\. Stop your old LinkShield windows first\."\)\n',
        '''        if not (DASHBOARD / "dist" / "index.html").is_file():
            raise FileNotFoundError("Run: cd dashboard; npm run build")
        if port_is_busy(8001):
            raise RuntimeError("Port 8001 is already in use.")
''',
    ),
    (
        r'(?s)            ui = start_service\(\n.*?                log\("\[ERROR\] Dashboard failed to become available on port 5173\."\)\n                return 1\n',
        '''            # FastAPI serves the compiled React dashboard.
            try:
                with urllib.request.urlopen(
                    "http://127.0.0.1:8001/", timeout=3
                ) as response:
                    if "text/html" not in response.headers.get(
                        "Content-Type", ""
                    ):
                        log("[ERROR] React dashboard not served.")
                        return 1
            except (OSError, urllib.error.URLError) as exc:
                log(f"[ERROR] Dashboard unavailable: {exc}")
                return 1
''',
    ),
]

for pattern, replacement in replacements:
    source, count = re.subn(
        pattern,
        lambda match: replacement,
        source,
        count=1,
    )
    if count != 1:
        raise SystemExit(
            "Unexpected launcher layout. No changes made."
        )

source = source.replace(
    "http://127.0.0.1:5173",
    "http://127.0.0.1:8001",
)

shutil.copy2(
    path,
    "start_linkshield_before_nodefree.py",
)

path.write_text(source, encoding="utf-8")

print("Success: LinkShield launcher updated.")
