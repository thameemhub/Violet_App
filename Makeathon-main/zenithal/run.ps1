# Zenithal — one-command dev launcher (Windows PowerShell).
# Starts the FastAPI backend and the Vite dashboard in separate windows.
#
#   powershell -ExecutionPolicy Bypass -File run.ps1

$root = $PSScriptRoot

Write-Host "== Zenithal :: URL Threat Intelligence from IP Data ==" -ForegroundColor Cyan

# Prefer the project venv (installed on D: to avoid the full C: drive); fall
# back to whatever 'python' is on PATH if the venv is missing.
$venvPy = Join-Path $root ".venv\Scripts\python.exe"
if (Test-Path $venvPy) {
  $py = "& '$venvPy'"
  Write-Host "[*] Using project venv: .venv" -ForegroundColor DarkGray
} else {
  $py = "python"
  Write-Host "[!] .venv not found - using system python. Run setup first (see README)." -ForegroundColor DarkYellow
}

# --- Backend ---
Write-Host "[*] Starting backend on http://127.0.0.1:8000 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @(
  "-NoExit", "-Command",
  "cd '$root\backend'; $py -m uvicorn app.main:app --port 8000"
)

Start-Sleep -Seconds 3

# --- Dashboard ---
Write-Host "[*] Starting dashboard on http://127.0.0.1:5173 ..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList @(
  "-NoExit", "-Command",
  "cd '$root\dashboard'; npm run dev"
)

Start-Sleep -Seconds 4
Write-Host "[OK] Dashboard: http://127.0.0.1:5173   API docs: http://127.0.0.1:8000/docs" -ForegroundColor Green
Start-Process "http://127.0.0.1:5173"
