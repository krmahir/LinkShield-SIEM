
$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

$Python = Join-Path $Root "backend\.venv\Scripts\python.exe"
$App = Join-Path $Root "backend\portable_app.py"
$Capture = Join-Path $Root "agent\portable_capture.py"
$Dashboard = Join-Path $Root "dashboard\dist"
$GeoIP = Join-Path $Root "backend\geoip\GeoLite2-Country.mmdb"

foreach ($File in @(
    $Python,
    $App,
    $Capture,
    (Join-Path $Dashboard "index.html")
)) {
    if (-not (Test-Path $File)) {
        throw "Missing required file: $File"
    }
}

Write-Host "[1/4] Installing packaging dependencies..."

& $Python -m pip install --upgrade pyinstaller scapy psutil h11

if ($LASTEXITCODE -ne 0) {
    throw "Dependency installation failed"
}

Write-Host "[2/4] Building LinkShield.exe..."

$BackendArgs = @(
    "--noconfirm",
    "--clean",
    "--onedir",
    "--console",
    "--name", "LinkShield",
    "--paths", (Join-Path $Root "backend"),
    "--add-data", "$Dashboard;dashboard\dist",
    "--collect-submodules", "uvicorn",
    "--collect-submodules", "pydantic",
    "--collect-submodules", "starlette",
    "--collect-submodules", "geoip2",
    "--copy-metadata", "geoip2",
    "--copy-metadata", "maxminddb"
)

if (Test-Path $GeoIP) {
    $BackendArgs += @(
        "--add-data", "$GeoIP;backend\geoip"
    )
}

$BackendArgs += $App

& $Python -m PyInstaller @BackendArgs

if ($LASTEXITCODE -ne 0) {
    throw "Main executable build failed"
}

Write-Host "[3/4] Building LinkShieldCapture.exe..."

$CaptureArgs = @(
    "--noconfirm",
    "--clean",
    "--onefile",
    "--console",
    "--name", "LinkShieldCapture",
    "--distpath", (Join-Path $Root "capture_dist"),
    "--workpath", (Join-Path $Root "build_capture"),
    "--paths", (Join-Path $Root "agent"),
    "--collect-submodules", "scapy",
    "--collect-submodules", "psutil",
    $Capture
)

& $Python -m PyInstaller @CaptureArgs

if ($LASTEXITCODE -ne 0) {
    throw "Capture executable build failed"
}

$Helper = Join-Path $Root "capture_dist\LinkShieldCapture.exe"
$Destination = Join-Path $Root "dist\LinkShield\LinkShieldCapture.exe"

if (-not (Test-Path $Helper)) {
    throw "Capture executable was not generated"
}

Copy-Item $Helper $Destination -Force

Write-Host "[4/4] Build complete!"
Write-Host "Created LinkShield.exe"
Write-Host "Created LinkShieldCapture.exe"


