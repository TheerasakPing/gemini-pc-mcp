@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title Gemini PC Workspace Launcher

echo ========================================================
echo        Gemini PC Workspace - MCP Server Launcher
echo ========================================================
echo.

:: 1. Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

:: 2. Libraries (first run only)
python -c "import mcp, uvicorn" >nul 2>&1
if errorlevel 1 (
    echo [*] Installing libraries...
    python -m pip install -q -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] pip install failed
        pause
        exit /b 1
    )
)

:: 3. cloudflared
set "CF_EXE="
where cloudflared >nul 2>&1
if not errorlevel 1 set "CF_EXE=cloudflared"
if not defined CF_EXE if exist "C:\Program Files (x86)\cloudflared\cloudflared.exe" set "CF_EXE=C:\Program Files (x86)\cloudflared\cloudflared.exe"
if not defined CF_EXE if exist "C:\Program Files\cloudflared\cloudflared.exe" set "CF_EXE=C:\Program Files\cloudflared\cloudflared.exe"
if not defined CF_EXE if exist "%LOCALAPPDATA%\Microsoft\WinGet\Links\cloudflared.exe" set "CF_EXE=%LOCALAPPDATA%\Microsoft\WinGet\Links\cloudflared.exe"
if not defined CF_EXE (
    echo [ERROR] cloudflared not found. Install it with:
    echo         winget install --id Cloudflare.cloudflared
    echo         then close this window and run start.bat again.
    pause
    exit /b 1
)

:: 4. Secret key (created once, never committed)
if not exist ".mcp_secret" (
    python -c "import secrets;open('.mcp_secret','w').write(secrets.token_urlsafe(24))"
    echo [*] Created new secret key in .mcp_secret
)
set /p MCP_SECRET=<.mcp_secret

:: 5. MCP server
echo [*] Starting MCP server on 127.0.0.1:8000 ...
start "Gemini MCP Server" cmd /k "cd /d ""%~dp0"" && python server.py"

echo.
echo ========================================================
if exist ".tunnel_token" (
    echo  Mode: Named Tunnel ^(fixed URL from your Cloudflare^)
    echo  Gemini URL:  https://^<your-hostname^>/!MCP_SECRET!/mcp
    echo ========================================================
    echo.
    "%CF_EXE%" tunnel run --token-file "%~dp0.tunnel_token"
) else (
    echo  Mode: Quick Tunnel ^(free, random URL each start^)
    echo  1. Wait for the box below that shows https://xxxx.trycloudflare.com
    echo  2. Paste this into Gemini ^(Connectors ^> Custom^):
    echo.
    echo     https://xxxx.trycloudflare.com/!MCP_SECRET!/mcp
    echo.
    echo  Keep the secret private. Anyone with it can use your tools.
    echo ========================================================
    echo.
    echo  NOTE: the server checks the Host header. Once the tunnel shows its
    echo        hostname, close the server window, then in a new window run:
    echo          set MCP_ALLOWED_HOSTS=127.0.0.1:8000,localhost:8000,HOSTNAME
    echo          python server.py
    echo        The tunnel keeps running; only the server needs the allowlist.
    echo.
    "%CF_EXE%" tunnel --url http://127.0.0.1:8000
)

pause
