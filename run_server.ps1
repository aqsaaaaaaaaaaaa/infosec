#!/usr/bin/env pwsh
# Run server in current terminal
Write-Host "Starting Infosec Demo Server..." -ForegroundColor Cyan
cd "C:\Users\USER\Desktop\IS\demo"
& "C:/Users/USER/Desktop/IS/.venv/Scripts/python.exe" server.py
