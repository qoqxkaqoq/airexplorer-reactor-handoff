# Windows UI 验收探针: 启动候选 exe, 枚举窗口 + PrintWindow 截图 + 采集 .NET 崩溃事件
param(
    [Parameter(Mandatory = $true)][string]$ExePath,
    [int]$WaitSec = 30,
    [string]$OutDir = "probe"
)

$ErrorActionPreference = "Continue"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir "probe.log"
function L($m) { $s = "[{0}] {1}" -f (Get-Date -Format "HH:mm:ss.fff"), $m; Write-Host $s; Add-Content -Path $log -Value $s -Encoding utf8 }

Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

public class WinProbe {
    public delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);
    [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lParam);
    [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint pid);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr hWnd, StringBuilder s, int n);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr hWnd, StringBuilder s, int n);
    [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT r);
    [DllImport("user32.dll")] public static extern IntPtr SendMessageTimeout(IntPtr hWnd, uint msg, IntPtr wp, IntPtr lp, uint flags, uint timeout, out IntPtr res);
    [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, uint msg, IntPtr wp, IntPtr lp);
    [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr hWnd, IntPtr hdc, uint flags);
    [DllImport("user32.dll")] public static extern IntPtr GetWindowDC(IntPtr hWnd);
    [DllImport("user32.dll")] public static extern int ReleaseDC(IntPtr hWnd, IntPtr hdc);
    [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left, Top, Right, Bottom; }

    public class Info {
        public IntPtr Hwnd; public uint Pid; public string Title; public string Class; public bool Visible; public RECT Rect;
    }

    public static List<Info> List(uint pid) {
        var res = new List<Info>();
        EnumWindows((h, l) => {
            uint p; GetWindowThreadProcessId(h, out p);
            if (p != pid) return true;
            var t = new StringBuilder(512); GetWindowTextW(h, t, 512);
            var c = new StringBuilder(256); GetClassNameW(h, c, 256);
            RECT r; GetWindowRect(h, out r);
            res.Add(new Info { Hwnd = h, Pid = p, Title = t.ToString(), Class = c.ToString(), Visible = IsWindowVisible(h), Rect = r });
            return true;
        }, IntPtr.Zero);
        return res;
    }
}
"@

$exe = (Resolve-Path $ExePath).Path
$workdir = Split-Path $exe -Parent
L "exe = $exe"
L "size = $((Get-Item $exe).Length)  md5 = $((Get-FileHash $exe -Algorithm MD5).Hash)"
L "OS = $([Environment]::OSVersion.VersionString)  SessionId = $((Get-Process -Id $PID).SessionId)"

$startTime = Get-Date
$p = Start-Process -FilePath $exe -WorkingDirectory $workdir -PassThru
L "started pid = $($p.Id)"

$deadline = $startTime.AddSeconds($WaitSec)
$shot = 0
$seen = @{}
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 1500
    if ($p.HasExited) { L "process EXITED early, code = $($p.ExitCode)"; break }
    $wins = [WinProbe]::List([uint32]$p.Id)
    foreach ($w in $wins) {
        $key = "$($w.Hwnd)"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = 1
        L ("WINDOW hwnd=0x{0:X} visible={1} class='{2}' title='{3}' rect={4},{5},{6},{7}" -f [int64]$w.Hwnd, $w.Visible, $w.Class, $w.Title, $w.Rect.Left, $w.Rect.Top, $w.Rect.Right, $w.Rect.Bottom)
        if ($w.Visible -and ($w.Rect.Right - $w.Rect.Left) -gt 50) {
            $shot++
            $bmp = New-Object System.Drawing.Bitmap(($w.Rect.Right - $w.Rect.Left), ($w.Rect.Bottom - $w.Rect.Top))
            $g = [System.Drawing.Graphics]::FromImage($bmp)
            $hdc = $g.GetHdc()
            $ok = [WinProbe]::PrintWindow($w.Hwnd, $hdc, 2)
            $g.ReleaseHdc($hdc); $g.Dispose()
            $file = Join-Path $OutDir ("window{0}_hwnd{1}.png" -f $shot, $w.Hwnd)
            $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
            L "  screenshot -> $file (PrintWindow=$ok)"
            try {
                $full = Join-Path $OutDir "screen{0}.png" -f $shot
                $b = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height)
            } catch {}
        }
    }
}

if (-not $p.HasExited) {
    $wins = [WinProbe]::List([uint32]$p.Id)
    L "still alive, windows = $($wins.Count)"
    L "responding = $($p.Responding)  threads = $($p.Threads.Count)  WS(MB) = $([math]::Round($p.WorkingSet64/1MB,1))  CPU = $($p.TotalProcessorTime)"
    try {
        $mods = ($p.Modules | Select-Object -First 40 | ForEach-Object { $_.ModuleName }) -join ","
        L "modules(head40) = $mods"
    } catch { L "modules: $($_.Exception.Message)" }
    ($wins | ForEach-Object { "  hwnd=0x{0:X} visible={1} class='{2}' title='{3}'" -f [int64]$_.Hwnd, $_.Visible, $_.Class, $_.Title }) | ForEach-Object { L $_ }
# 收尾: 尝试关闭模态对话框后抓主窗口 (即使不可见也 PrintWindow)

    $wins = [WinProbe]::List([uint32]$p.Id)
    foreach ($w in $wins) {
        if ($w.Visible -and $w.Class -like "WindowsForms10*" -and $w.Title -notlike "Air Explorer*") {
            L "close dialog: '$($w.Title)'"
            [WinProbe]::PostMessage($w.Hwnd, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
        }
    }
    Start-Sleep -Seconds 4
    $wins = [WinProbe]::List([uint32]$p.Id)
    foreach ($w in $wins) {
        if ($w.Title -like "Air Explorer*") {
            $wd = $w.Rect.Right - $w.Rect.Left; $ht = $w.Rect.Bottom - $w.Rect.Top
            L ("MAIN hwnd=0x{0:X} visible={1} rect={2},{3},{4},{5}" -f [int64]$w.Hwnd, $w.Visible, $w.Rect.Left, $w.Rect.Top, $w.Rect.Right, $w.Rect.Bottom)
            if ($wd -gt 50 -and $ht -gt 50) {
                $bmp = New-Object System.Drawing.Bitmap($wd, $ht)
                $g = [System.Drawing.Graphics]::FromImage($bmp)
                $hdc = $g.GetHdc()
                $ok = [WinProbe]::PrintWindow($w.Hwnd, $hdc, 2)
                $g.ReleaseHdc($hdc); $g.Dispose()
                $file = Join-Path $OutDir "mainwindow.png"
                $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose()
                L "  main screenshot -> $file (PrintWindow=$ok, visible=$($w.Visible))"
            }
        }
    }
    try {
        $p.Kill()
        L "killed"
    } catch { L "kill failed: $($_.Exception.Message)" }
}

# .NET Runtime 崩溃事件 (含异常类型与堆栈)
try {
    $ev = Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $startTime.AddMinutes(-1) } -ErrorAction Stop |
        Where-Object { $_.ProviderName -match '\.NET Runtime|Application Error|Windows Error Reporting' } |
        Select-Object -First 6
    foreach ($e in $ev) {
        L ("EVENT [{0}] {1}: {2}" -f $e.TimeCreated, $e.ProviderName, ($e.Message -replace "`r?`n", " | "))
    }
} catch { L "eventlog: $($_.Exception.Message)" }

L "done"
