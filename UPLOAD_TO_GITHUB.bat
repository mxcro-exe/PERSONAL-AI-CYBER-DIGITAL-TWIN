@echo off
title Personal AI Cyber Digital Twin - GitHub Uploader
color 0A
cls

echo.
echo  ============================================================
echo     PERSONAL AI CYBER DIGITAL TWIN - GitHub Upload Tool
echo  ============================================================
echo.

REM Check if Git is installed
git --version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [!] Git is NOT installed on your laptop!
    echo.
    echo  Downloading and installing Git automatically...
    echo.
    powershell -Command "& {Invoke-WebRequest -Uri 'https://github.com/git-for-windows/git/releases/download/v2.45.2.windows.1/Git-2.45.2-64-bit.exe' -OutFile '%TEMP%\git-installer.exe'}"
    echo  Running Git installer...
    start /wait "%TEMP%\git-installer.exe" /SILENT /NORESTART
    echo.
    echo  [OK] Git installed! Please CLOSE and RE-OPEN this file.
    pause
    exit
)

echo  [OK] Git detected on your system.
echo.

REM Check if repo is already initialized
if not exist ".git" (
    echo  [1/5] Initializing Git repository...
    git init
    git branch -M main
) else (
    echo  [1/5] Git repository already initialized.
)

echo.
echo  [2/5] Staging all project files...
git add .
git status --short
echo.

REM Ask for commit message
set /p COMMIT_MSG=  Enter a commit message (or press Enter for default): 
if "%COMMIT_MSG%"=="" set COMMIT_MSG=Update: Personal AI Cyber Digital Twin

echo.
echo  [3/5] Creating commit: "%COMMIT_MSG%"
git commit -m "%COMMIT_MSG%"

echo.
echo  ============================================================
echo   GITHUB REMOTE SETUP
echo  ============================================================
echo.
echo  Go to https://github.com/new and create a NEW repository.
echo  Name it: personal-ai-cyber-digital-twin
echo  Keep it PUBLIC or PRIVATE (your choice)
echo  Do NOT add README or .gitignore (we already have them!)
echo.
echo  After creating the repo, copy the repository URL.
echo  Example: https://github.com/YOUR_USERNAME/personal-ai-cyber-digital-twin.git
echo.
set /p REPO_URL=  Paste your GitHub repository URL here: 

echo.
echo  [4/5] Connecting to GitHub...

REM Check if remote already exists
git remote get-url origin >nul 2>&1
if %errorlevel% equ 0 (
    git remote set-url origin %REPO_URL%
) else (
    git remote add origin %REPO_URL%
)

echo.
echo  [5/5] Pushing to GitHub...
echo  (A browser window may open asking you to login to GitHub)
echo.
git push -u origin main

echo.
if %errorlevel% equ 0 (
    echo  ============================================================
    echo   SUCCESS! Your project is now live on GitHub!
    echo   Visit: %REPO_URL%
    echo  ============================================================
) else (
    echo  ============================================================
    echo   [!] Push failed. Common fixes:
    echo   1. Make sure you created the repo on GitHub first
    echo   2. Make sure the URL is correct
    echo   3. Login with your GitHub credentials when prompted
    echo  ============================================================
)

echo.
pause
