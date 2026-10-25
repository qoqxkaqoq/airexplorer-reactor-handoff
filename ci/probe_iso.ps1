# probe_iso.ps1 -- run probe.ps1 with an isolated APPDATA/LOCALAPPDATA/TMP so the
# exe under test never touches this machine's real user profile.
# usage: powershell -File probe_iso.ps1 -ExePath X.exe [-WaitSec 100] [-OutDir probe_iso]
param(
    [Parameter(Mandatory = $true)][string]$ExePath,
    [int]$WaitSec = 100,
    [string]$OutDir = "probe_iso"
)
$iso = Join-Path $PSScriptRoot "probe_env"
New-Item -ItemType Directory -Force -Path "$iso\a", "$iso\b", "$iso\a\tmp" | Out-Null
$env:APPDATA = "$iso\a"
$env:LOCALAPPDATA = "$iso\b"
$env:TMP = "$iso\a\tmp"
$env:TEMP = "$iso\a\tmp"
Write-Host ("[probe_iso] isolated env at " + $iso)
& (Join-Path $PSScriptRoot "probe.ps1") -ExePath $ExePath -WaitSec $WaitSec -OutDir $OutDir
