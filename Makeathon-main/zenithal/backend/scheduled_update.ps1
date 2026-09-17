# Zenithal — scheduled threat-feed refresh (run daily by Task Scheduler).
# Refreshes URLhaus + OpenPhish + PhishTank blocklist and the reputation lists.
# Add -retrain (pass as arg) to also rebuild/validate the ML models (heavier;
# do this weekly, not daily).

$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent          # ...\zenithal
$py   = Join-Path $root ".venv\Scripts\python.exe"

# C: is full on this machine — keep pip/temp on D:
$env:TMP  = "D:\zenithal-tmp"
$env:TEMP = "D:\zenithal-tmp"
if (-not (Test-Path $env:TMP)) { New-Item -ItemType Directory -Force $env:TMP | Out-Null }

$updater = Join-Path $root "backend\training\update_feeds.py"
$log     = Join-Path $root "backend\feed_update.log"

"$(Get-Date -Format s)  starting feed update" | Out-File -Append -Encoding utf8 $log
& $py $updater @args 2>&1 | Out-File -Append -Encoding utf8 $log
"$(Get-Date -Format s)  done (exit $LASTEXITCODE)" | Out-File -Append -Encoding utf8 $log
