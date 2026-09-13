# =============================================================================
# 100-Port Test Suite (2 batches of 50 ports to comply with MAX_PROBES = 50)
# =============================================================================
# FORCE CONSOLE & PIPES TO CLEAN UTF-8 (Prevents ΓòÉ / ΓöÇ mojibake)
# =============================================================================
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

# Target & Adapter Settings
$TARGET_IP = "192.168.1.104"  # <-- Change this to your target IP if needed
$ADAPTER   = "\Device\NPF_{79613882-4F62-495C-9891-92E06A2C6E9B}"  # Realtek Wi-Fi Adapter

$LOG_DIR   = Join-Path $PSScriptRoot "final-log"
$LOG_FILE  = Join-Path $LOG_DIR "scan_100_ports.log"

if (-not $TARGET_IP) {
    Write-Host "[!] Please set your `$TARGET_IP at the top of the script before running." -ForegroundColor Yellow
    exit 1
}

# Ensure destination directory exists
if (-not (Test-Path $LOG_DIR)) {
    New-Item -ItemType Directory -Force -Path $LOG_DIR | Out-Null
}

$TIMESTAMP = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HEADER = @"
=============================================================================
100-PORT VERIFICATION TEST RUN
Date      : $TIMESTAMP
Target IP : $TARGET_IP
Adapter   : $ADAPTER
Exploits  : Skipped (--skip-exploits)
=============================================================================
"@

Write-Host $HEADER -ForegroundColor Green
$HEADER | Out-File -FilePath $LOG_FILE -Encoding utf8

# Helper to run a batch cleanly with real-time output and UTF-8 file logging
function Run-ScanBatch {
    param(
        [string]$Title,
        [int[]]$Ports
    )
    Write-Host "`n>>> $Title <<<" -ForegroundColor Cyan
    "`n=== $Title ===" | Out-File -FilePath $LOG_FILE -Append -Encoding utf8

    & python -u Imp\attacker\main.py `
        --adapter $ADAPTER `
        --target $TARGET_IP `
        --ports $Ports `
        --skip-exploits | ForEach-Object {
            Write-Host $_
            $_ | Out-File -FilePath $LOG_FILE -Append -Encoding utf8
        }
}

# --- BATCH 1: 50 Core System & Well-Known Ports ---
$batch1_ports = @(
    20, 21, 22, 23, 25, 53, 79, 80, 81, 82, 88, 110, 111, 113, 119,
    135, 137, 138, 139, 143, 161, 179, 199, 389, 443, 445, 464, 465,
    500, 514, 515, 554, 587, 631, 636, 873, 990, 993, 995, 1024,
    1025, 1026, 1027, 1028, 1029, 1080, 1194, 1433, 1521, 1723
)
Run-ScanBatch -Title "BATCH 1: Top 50 Well-Known & System Services (Low Range)" -Ports $batch1_ports

# --- BATCH 2: 50 High Ports, Web Apps, RPC & Cloud/Dev Services ---
$batch2_ports = @(
    1883, 1900, 2049, 2082, 2083, 2086, 2087, 2121, 2221, 2375, 3000, 3128,
    3306, 3389, 4443, 4899, 5000, 5060, 5357, 5432, 5672, 5900, 6379, 7001,
    8000, 8008, 8080, 8081, 8082, 8443, 8880, 8888, 9000, 9090, 9200, 10000,
    27017, 49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160,
    49161, 49162, 49163, 49164
)
Run-ScanBatch -Title "BATCH 2: Top 50 High Ports, Web Apps, RPC & Cloud/Dev Services" -Ports $batch2_ports

Write-Host "`n[+] Complete 100-port scan finished!" -ForegroundColor Green
Write-Host "[+] Full clean UTF-8 log saved to: $LOG_FILE" -ForegroundColor Green
