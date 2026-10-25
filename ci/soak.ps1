# soak.ps1 -- long-run stability probe: LAUNCH the exe, then verify process alive
# + window present for N minutes. FIX 2026-10-26: the previous version of this
# script was monitor-only (never started the target), so calling it standalone
# (as soak_iso.ps1 / the gate does) always reported "PROCESS GONE" -- no process
# had ever been started. Launch behavior now mirrors ci/probe.ps1 (ProcessStartInfo,
# WorkingDirectory = the exe's own directory so the payload next to it is found).
# Exit codes unchanged: 0 = PASS, 2 = process died, 3 = no window, 4 = error dialog.
# usage: soak.ps1 -ExePath <exe> -Minutes 7 [-DataDir <dir>]
param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [int]$Minutes = 7,
    [string]$DataDir = ""
)
$ErrorActionPreference = 'Continue'

function Get-TreePids([int]$Root) {
    $all = Get-CimInstance Win32_Process
    $map = @{}
    foreach ($p in $all) { $map[[int]$p.ProcessId] = [int]$p.ParentProcessId }
    $out = New-Object System.Collections.Generic.HashSet[int]
    $q = New-Object System.Collections.Queue
    $q.Enqueue($Root)
    while ($q.Count -gt 0) {
        $cur = $q.Dequeue()
        if (-not $out.Add($cur)) { continue }
        foreach ($kv in $map.GetEnumerator()) { if ($kv.Value -eq $cur) { $q.Enqueue($kv.Key) } }
    }
    return $out
}

$exeName = [System.IO.Path]::GetFileNameWithoutExtension($ExePath)
$deadline = (Get-Date).AddMinutes($Minutes)
$checkEverySec = 20
$samples = 0
$winSeen = 0
$aliveGaps = 0
$errors = @()
$started = Get-Date

# ---- launch (FIX: previously monitor-only) ----
$exeFull = (Resolve-Path $ExePath).Path
$wd = Split-Path -Parent $exeFull
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exeFull
$psi.UseShellExecute = $false
$psi.WorkingDirectory = $wd
$launchedPid = -1
$proc = [System.Diagnostics.Process]::Start($psi)
$launchedPid = $proc.Id
Write-Host ("started pid = " + $launchedPid + "  wd = " + $wd)
Write-Host "soak: $exeName for $Minutes min (started $started)"

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $checkEverySec
    $samples++
    $tgt = $null
    if ($launchedPid -gt 0) {
        $tgt = Get-Process -Id $launchedPid -ErrorAction SilentlyContinue
    }
    if (-not $tgt) {
        # fall back to name match only if we did not launch a tracked pid
        if ($launchedPid -le 0) { $tgt = Get-Process -Name $exeName -ErrorAction SilentlyContinue | Select-Object -First 1 }
    }
    if (-not $tgt) {
        $aliveGaps++
        Write-Host ("[{0}] PROCESS GONE" -f (Get-Date -Format 'HH:mm:ss'))
        if ($aliveGaps -gt 3) { Write-Host "FAIL: process repeatedly gone"; exit 2 }
        continue
    }
    $title = ""
    try { $tgt.Refresh(); $title = $tgt.MainWindowTitle } catch {}
    if ($title -and $title.Length -gt 0) {
        $winSeen++
        Write-Host ("[{0}] alive pid={1} window='{2}'" -f (Get-Date -Format 'HH:mm:ss'), $tgt.Id, $title)
        if ($title -like '*Error detected*') { $errors += $title }
    } else {
        Write-Host ("[{0}] alive pid={1} window=(none)" -f (Get-Date -Format 'HH:mm:ss'), $tgt.Id)
    }
}

$elapsed = ((Get-Date) - $started).TotalMinutes
Write-Host ("soak done: {0:N1} min, samples={1}, winSeen={2}, aliveGaps={3}, errorDialogs={4}" -f $elapsed, $samples, $winSeen, $aliveGaps, $errors.Count)

# kill tree of the launched process, then belt-and-suspenders same-name sweep
if ($launchedPid -gt 0) {
    $pids = Get-TreePids $launchedPid
    foreach ($p in $pids) { taskkill /PID $p /F /T 2>$null | Out-Null }
}
Get-Process -Name $exeName -ErrorAction SilentlyContinue | ForEach-Object {
    taskkill /PID $_.Id /F /T 2>$null | Out-Null
}

if ($aliveGaps -gt 0) { Write-Host "FAIL: process died during soak"; exit 2 }
if ($winSeen -eq 0) { Write-Host "FAIL: window never seen"; exit 3 }
if ($errors.Count -gt 0) { Write-Host "FAIL: error dialog appeared"; exit 4 }
Write-Host "SOAK PASS: alive + window for full $Minutes minutes"
exit 0
