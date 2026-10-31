# soak.ps1 — long-run stability probe: process alive + window present for N minutes.
# usage: soak.ps1 -ExePath <exe> -Minutes 7 -DataDir <dir> [-Launch]
#   -Launch: 启动进程并持有 Process 对象 (死亡时能拿到精确 ExitCode), 否则仅按进程名监控。
param(
    [Parameter(Mandatory=$true)][string]$ExePath,
    [int]$Minutes = 7,
    [string]$DataDir = "",
    [switch]$Launch
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


# 枚举目标进程的全部可见顶层窗口标题 (捕捉无标题判定遗漏的对话框)
Add-Type -TypeDefinition @'
using System;
using System.Text;
using System.Collections.Generic;
public class WinEnum {
    public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
    [System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb, IntPtr lp);
    [System.Runtime.InteropServices.DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
    [System.Runtime.InteropServices.DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder sb, int max);
    [System.Runtime.InteropServices.DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
    public static List<string> Titles(uint targetPid) {
        var outp = new List<string>();
        EnumWindows((h, lp) => {
            uint pid; GetWindowThreadProcessId(h, out pid);
            if (pid == targetPid && IsWindowVisible(h)) {
                var sb = new StringBuilder(256);
                GetWindowText(h, sb, 256);
                outp.Add(sb.ToString());
            }
            return true;
        }, IntPtr.Zero);
        return outp;
    }
}
'@
function Dump-AllWindows([int]$Pid2) {
    try {
        $ts = [WinEnum]::Titles([uint32]$Pid2)
        $vis = @($ts | Where-Object { $_ -ne '' })
        if ($vis.Count -gt 0) { Write-Host ("    [wins] " + (($vis | Select-Object -First 8) -join ' | ')) }
        else { Write-Host '    [wins] (no visible titled windows)' }
    } catch { Write-Host ('    [wins] enum fail: ' + $_.Exception.Message) }
}

# 卡点诊断: 进程活着但无窗口时 — TCP / DNS / 线程状态指纹
function Dump-StuckDiagnostics([System.Diagnostics.Process]$p) {
    try {
        $conns = Get-NetTCPConnection -OwningProcess $p.Id -ErrorAction SilentlyContinue
        if ($conns) {
            $conns | Select-Object -First 12 | ForEach-Object {
                Write-Host ("    [tcp] {0}:{1} -> {2}:{3} state={4}" -f $_.LocalAddress, $_.LocalPort, $_.RemoteAddress, $_.RemotePort, $_.State)
            }
        } else { Write-Host '    [tcp] no sockets owned' }
    } catch { Write-Host ('    [tcp] fail: ' + $_.Exception.Message) }
    try {
        $dns = Get-DnsClientCache -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Entry -Unique | Select-Object -First 20
        if ($dns) { Write-Host ('    [dns] ' + (($dns) -join ', ')) }
    } catch {}
    try {
        $p.Refresh()
        $st = $p.Threads | Group-Object { "{0}/{1}" -f $_.ThreadState, $_.WaitReason } | Sort-Object Count -Descending
        Write-Host ('    [thr] ' + (($st | ForEach-Object { "{0}x{1}" -f $_.Count, $_.Name }) -join '  '))
    } catch { Write-Host ('    [thr] fail: ' + $_.Exception.Message) }
}

# minidump (线程栈内存+线程信息, 不含堆) — 抓启动期卡点的线程调用栈
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public class MiniDumper {
    [DllImport("dbghelp.dll", SetLastError=true)]
    public static extern bool MiniDumpWriteDump(IntPtr hProc, uint pid, IntPtr hFile, uint type, IntPtr exc, IntPtr user, IntPtr comm);
}
'@
function Invoke-MiniDump([int]$Pid2, [string]$OutPath) {
    try {
        $p = Get-Process -Id $Pid2 -ErrorAction Stop
        $fs = [System.IO.File]::Create($OutPath)
        $ok = [MiniDumper]::MiniDumpWriteDump($p.Handle, [uint32]$Pid2, $fs.Handle, [uint32]4355, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
        $fs.Close()
        if ($ok) { Write-Host ('    [dump] saved ' + $OutPath + ' size=' + (Get-Item $OutPath).Length) }
        else { Write-Host ('    [dump] FAILED win32err=' + [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()) }
    } catch { Write-Host ('    [dump] fail: ' + $_.Exception.Message) }
}

# WER/Application 事件日志指纹: 崩溃 (1000) / 挂起 (1002) / .NET 未处理异常 (1026) / WER 汇报 (1001)
function Dump-DeathEvents([datetime]$Since, [string]$ProcName) {
    try {
        $ids = @(1000, 1001, 1002, 1023, 1026)
        $evs = Get-WinEvent -FilterHashtable @{ LogName='Application'; Id=$ids; StartTime=$Since } -ErrorAction SilentlyContinue
        if (-not $evs) { Write-Host "  [death-events] none in Application log"; return }
        foreach ($e in ($evs | Select-Object -First 6)) {
            $msg = ""
            try { $msg = $e.Message } catch {}
            $hit = ($msg -and $msg -match [regex]::Escape($ProcName))
            $head = ($msg -replace "`r`n", " | ")
            if ($head.Length -gt 500) { $head = $head.Substring(0, 500) }
            Write-Host ("  [death-events] {0} id={1} prov={2} hit={3}" -f $e.TimeCreated, $e.Id, $e.ProviderName, $hit)
            Write-Host ("    msg: {0}" -f $head)
        }
    } catch {
        Write-Host ("  [death-events] query failed: {0}" -f $_.Exception.Message)
    }
}

$exeName = [System.IO.Path]::GetFileNameWithoutExtension($ExePath)
$deadline = (Get-Date).AddMinutes($Minutes)
$checkEverySec = 20
$samples = 0
$winSeen = 0
$aliveGaps = 0
$errors = @()
$started = Get-Date
$procObj = $null
$dumpedPid = 0
Write-Host "soak: $exeName for $Minutes min (started $started) launch=$Launch"

if ($Launch) {
    $full = (Resolve-Path $ExePath).Path
    $wd = Split-Path $full -Parent
    Write-Host "launching: $full (wd=$wd)"
    $procObj = Start-Process -FilePath $full -WorkingDirectory $wd -PassThru
    Write-Host ("launched pid={0}" -f $procObj.Id)
    Start-Sleep -Seconds 10
}

$deathReported = $false
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Seconds $checkEverySec
    $samples++
    $tgt = $null
    if ($procObj) {
        try { $procObj.Refresh() } catch {}
        if (-not $procObj.HasExited) {
            $tgt = $procObj
        } else {
            # 死亡: 精确退出码 + 存活时长 + 事件日志
            $ec = $null
            try { $ec = $procObj.ExitCode } catch { $ec = "unreadable" }
            $life = $null
            try { $life = ($procObj.ExitTime - $procObj.StartTime).TotalSeconds } catch {}
            Write-Host ("[{0}] PROCESS EXITED exitcode={1} lifetime={2:N1}s" -f (Get-Date -Format 'HH:mm:ss'), $ec, $life)
            Dump-DeathEvents $started $exeName
            $aliveGaps++
            $deathReported = $true
            if ($aliveGaps -gt 3) { Write-Host "FAIL: process repeatedly gone"; break }
            continue
        }
    } else {
        $tgt = Get-Process -Name $exeName -ErrorAction SilentlyContinue | Select-Object -First 1
        if (-not $tgt) {
            $aliveGaps++
            Write-Host ("[{0}] PROCESS GONE" -f (Get-Date -Format 'HH:mm:ss'))
            if (-not $deathReported) { Dump-DeathEvents $started $exeName; $deathReported = $true }
            if ($aliveGaps -gt 3) { Write-Host "FAIL: process repeatedly gone"; break }
            continue
        }
    }
    $title = ""
    try { $tgt.Refresh(); $title = $tgt.MainWindowTitle } catch {}
    if ($title -and $title.Length -gt 0) {
        $winSeen++
        Write-Host ("[{0}] alive pid={1} window='{2}'" -f (Get-Date -Format 'HH:mm:ss'), $tgt.Id, $title)
        if ($title -like '*Error detected*') { $errors += $title }
    } else {
        Write-Host ("[{0}] alive pid={1} window=(none) threads={2}" -f (Get-Date -Format 'HH:mm:ss'), $tgt.Id, $tgt.Threads.Count)
        if ($samples % 3 -eq 0) { Dump-AllWindows $tgt.Id }
        Dump-StuckDiagnostics $tgt
        if ($samples -ge 3 -and $dumpedPid -ne $tgt.Id) {
            $dumpedPid = $tgt.Id
            Invoke-MiniDump $tgt.Id ("app\minidump_{0}.dmp" -f $tgt.Id)
        }
    }
}

if ($aliveGaps -gt 3) {
    # 死亡退出, 上面已 dump 过, 直接失败返回
    exit 2
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
