# soak.ps1 — long-run stability probe: process alive + window present for N minutes.
# usage: soak.ps1 -ExePath <exe> -Minutes 7 -DataDir <dir>
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
Write-Host "soak: $exeName for $Minutes min (started $started)"

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $checkEverySec
    $samples++
    $tgt = Get-Process -Name $exeName -ErrorAction SilentlyContinue | Select-Object -First 1
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

# kill tree
$tgt = Get-Process -Name $exeName -ErrorAction SilentlyContinue | Select-Object -First 1
if ($tgt) {
    $pids = Get-TreePids $tgt.Id
    foreach ($p in $pids) { taskkill /PID $p /F /T 2>$null | Out-Null }
}

if ($aliveGaps -gt 0) { Write-Host "FAIL: process died during soak"; exit 2 }
if ($winSeen -eq 0) { Write-Host "FAIL: window never seen"; exit 3 }
if ($errors.Count -gt 0) { Write-Host "FAIL: error dialog appeared"; exit 4 }
Write-Host "SOAK PASS: alive + window for full $Minutes minutes"
exit 0
