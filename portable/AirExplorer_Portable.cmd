@echo off
rem ============================================================
rem  AirExplorer Portable Launcher (official exe, zero patch)
rem
rem  Redirects user data (USERPROFILE / APPDATA / LOCALAPPDATA /
rem  TEMP) into .\data\ next to this file, then starts the
rem  OFFICIAL unmodified AirExplorer.exe.
rem
rem  Usage: put this file in the same folder as the official
rem  AirExplorer.exe (v5.11.0.0, md5 A12B5C57...) and double-click.
rem  All user data (login, settings, cache) lands in .\data\ -
rem  delete the folder = clean reset; copy the folder = backup.
rem ============================================================
setlocal EnableExtensions
set "HERE=%~dp0"
set "DATA=%HERE%data"

if not exist "%HERE%AirExplorer.exe" (
  echo [ERROR] AirExplorer.exe not found in this folder.
  echo         Put the official AirExplorer.exe next to this launcher.
  pause
  exit /b 1
)

rem ---- data skeleton ----
if not exist "%DATA%"                    mkdir "%DATA%"                    2>nul
if not exist "%DATA%\profile"            mkdir "%DATA%\profile"            2>nul
if not exist "%DATA%\profile\Desktop"    mkdir "%DATA%\profile\Desktop"    2>nul
if not exist "%DATA%\profile\Documents"  mkdir "%DATA%\profile\Documents"  2>nul
if not exist "%DATA%\profile\Downloads"  mkdir "%DATA%\profile\Downloads"  2>nul
if not exist "%DATA%\AppData\Roaming"    mkdir "%DATA%\AppData\Roaming"    2>nul
if not exist "%DATA%\AppData\Local"      mkdir "%DATA%\AppData\Local"      2>nul
if not exist "%DATA%\AppData\Local\Temp" mkdir "%DATA%\AppData\Local\Temp" 2>nul

rem ---- environment redirection (process-local, nothing global is touched) ----
set "USERPROFILE=%DATA%\profile"
set "HOMEDRIVE=%DATA:~0,2%"
set "HOMEPATH=%DATA:~2%"
set "APPDATA=%DATA%\AppData\Roaming"
set "LOCALAPPDATA=%DATA%\AppData\Local"
set "TEMP=%DATA%\AppData\Local\Temp"
set "TMP=%DATA%\AppData\Local\Temp"

rem start /wait keeps cmd.exe as the parent, so the process tree
rem stays visible to tools/ci/probe.ps1 and Task Manager.
title AirExplorer Portable - user data lives in .\data\
start "" /wait "%HERE%AirExplorer.exe"
endlocal
