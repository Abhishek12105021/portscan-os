[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [ValidateSet("quiet", "stealth", "loud", "full")]
    [string]$Mode = "loud"
)

# =============================================================================
# SSH Exploit & Target Verification Test Run
# Target: 192.168.1.104 (Port 22 SSH)
# Modes:
#   - quiet / stealth : Silent reconnaissance only (whoami, hostname, ipconfig, os_info)
#   - loud / full     : Spooky trophy file + 1000-loop payloads + voice alert
# =============================================================================

# Force console and streams to clean UTF-8
chcp 65001 | Out-Null
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
$env:PYTHONIOENCODING = "utf-8"

# Target & Adapter Settings (from your active Wi-Fi configuration)
$TARGET_IP = "192.168.1.104"
$ADAPTER   = "\Device\NPF_{79613882-4F62-495C-9891-92E06A2C6E9B}"

$PROJECT_ROOT = Split-Path $PSScriptRoot -Parent
$LOG_DIR      = Join-Path $PROJECT_ROOT "final-log"
if (-not (Test-Path $LOG_DIR)) {
    New-Item -ItemType Directory -Force -Path $LOG_DIR | Out-Null
}

if ($Mode -in @("quiet", "stealth")) {
    $LOG_FILE = Join-Path $LOG_DIR "ssh_quiet.log"
    $MODE_LABEL = "QUIET / STEALTH (Silent Recon Only - No Payloads/Voice)"
} else {
    $LOG_FILE = Join-Path $LOG_DIR "ssh_attack.log"
    $MODE_LABEL = "LOUD / FULL (Trophy File + 1000-Loop Payloads + Voice Alert)"
}

$TIMESTAMP = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$HEADER = @"
=============================================================================
SSH EXPLOIT & TARGET VERIFICATION RUN
Date       : $TIMESTAMP
Target IP  : $TARGET_IP
Adapter    : $ADAPTER
Ports      : [22] (SSH)
Attack Mode: $MODE_LABEL
Log File   : $LOG_FILE
Exploits   : Enabled (Phase 5 will attempt weak-credential SSH login)
=============================================================================
"@

Write-Host $HEADER -ForegroundColor Green
$HEADER | Out-File -FilePath $LOG_FILE -Encoding utf8

Write-Host "`n>>> Starting Port 22 Scan, Banner Grabbing, OS Fingerprint & SSH Exploit ($Mode Mode) <<<`n" -ForegroundColor Cyan

# Execute attacker/main.py with exploits enabled and specified ssh-mode
& python -u Imp\attacker\main.py `
    --adapter $ADAPTER `
    --target $TARGET_IP `
    --ports 22 `
    --timeout 2.0 `
    --delay 0.5 `
    --ssh-mode $Mode | ForEach-Object {
        Write-Host $_
        $_ | Out-File -FilePath $LOG_FILE -Append -Encoding utf8
    }

Write-Host "`n[+] SSH test run ($Mode mode) completed!" -ForegroundColor Green
Write-Host "[+] Full log saved to: $LOG_FILE" -ForegroundColor Green
