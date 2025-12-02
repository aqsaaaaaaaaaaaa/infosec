#!/usr/bin/env pwsh
# Run client in current terminal
Write-Host "Starting Infosec Demo Client..." -ForegroundColor Green
Start-Sleep -Seconds 2
cd "C:\Users\USER\Desktop\IS\demo"
& "C:/Users/USER/Desktop/IS/.venv/Scripts/python.exe" client.py
