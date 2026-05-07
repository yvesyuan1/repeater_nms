$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$env:DATABASE_URL = "sqlite:///./local_trial.sqlite"
$env:ADMIN_USERNAME = "admin"
if (-not $env:ADMIN_PASSWORD) {
  $env:ADMIN_PASSWORD = "admin123"
}
$env:SECRET_KEY = "local-trial-secret"
$env:REDIS_URL = "redis://127.0.0.1:6379/0"
$env:REDIS_CHANNEL_PREFIX = "repeater_nms"
$env:APP_HOST = "127.0.0.1"
$env:APP_PORT = "5000"
$env:TIMEZONE = "Asia/Shanghai"

& .\.venv\Scripts\python.exe -m flask --app wsgi init-db
& .\.venv\Scripts\python.exe -m flask --app wsgi seed-local-demo
try {
  & .\.venv\Scripts\python.exe -m repeater_nms.collector poll-once
} catch {
  Write-Host "Initial poll skipped: $($_.Exception.Message)"
}

Write-Host "Local trial initialized."
Write-Host "Open: http://127.0.0.1:5000/login"
Write-Host "Username: admin"
Write-Host "Password: $env:ADMIN_PASSWORD"

& .\.venv\Scripts\python.exe -m flask --app wsgi run --host 127.0.0.1 --port 5000
