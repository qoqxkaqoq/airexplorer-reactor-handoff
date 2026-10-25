# soak_iso.ps1 -- run soak.ps1 with an isolated APPDATA/LOCALAPPDATA/TMP.
# Exit code propagates from soak.ps1: 0 = PASS, 2 = process died, 3 = no window, 4 = error dialog.
# usage: powershell -File soak_iso.ps1 -ExePath X.exe -Minutes 7
param(
    [Parameter(Mandatory = $true)][string]$ExePath,
    [int]$Minutes = 7
)
$iso = Join-Path $PSScriptRoot "soak_env"
New-Item -ItemType Directory -Force -Path "$iso\a", "$iso\b", "$iso\a\tmp" | Out-Null
$env:APPDATA = "$iso\a"
$env:LOCALAPPDATA = "$iso\b"
$env:TMP = "$iso\a\tmp"
$env:TEMP = "$iso\a\tmp"
Write-Host ("[soak_iso] isolated env at " + $iso)
& (Join-Path $PSScriptRoot "soak.ps1") -ExePath $ExePath -Minutes $Minutes
exit $LASTEXITCODE
