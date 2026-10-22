# probe.ps1 -- verify on Windows runner whether an exe really shows a main window.
#
# Acceptance (user-defined): the program starts and a normal main window appears.
#   alive process but no window == FAIL
# CPU time is recorded to tell the two kinds of "no UI" apart:
#   CPU keeps climbing -> stuck in an infinite loop (the known disease here)
#   CPU nearly idle    -> not stuck, just never reaches window creation
#
# NOTE: keep this file pure ASCII. PowerShell 5.1 on Windows runners parses
# UTF-8-without-BOM scripts using the legacy codepage, which corrupts non-ASCII
# bytes and can break parsing entirely.
#
# usage: powershell -File probe.ps1 -ExePath X.exe [-WaitSec 90] [-OutDir out]
param(
    [Parameter(Mandatory = $true)] [string] $ExePath,
    [int] $WaitSec = 60,
    [string] $OutDir = "probe"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$log = Join-Path $OutDir "probe.log"
function W([string]$m) { $t = (Get-Date).ToString("HH:mm:ss.fff"); "$t $m" | Out-File -Append -FilePath $log -Encoding ascii; Write-Host "$t $m" }

W ("exe = " + (Resolve-Path $ExePath).Path)
$fi = Get-Item $ExePath
W ("size = " + $fi.Length + "  md5 = " + (Get-FileHash $ExePath -Algorithm MD5).Hash)
W ("OS = " + [System.Environment]::OSVersion.VersionString + "  SessionId = " + [System.Diagnostics.Process]::GetCurrentProcess().SessionId)

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = (Resolve-Path $ExePath).Path
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.WorkingDirectory = (Resolve-Path (Split-Path $ExePath -Parent)).Path

$proc = [System.Diagnostics.Process]::Start($psi)
W ("started pid = " + $proc.Id)
$so = $proc.StandardOutput.ReadToEndAsync()
$se = $proc.StandardError.ReadToEndAsync()

$deadline = (Get-Date).AddSeconds($WaitSec)
$handle = 0
$title = ""
$firstAt = -1
$maxCpu = 0.0
$busy = 0
$samples = 0

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 2500
    if ($proc.HasExited) { break }
    $proc.Refresh()
    $samples++
    $cpu = $proc.CPU
    $elapsed = [int]((Get-Date) - $proc.StartTime).TotalSeconds
    if ($cpu -gt $maxCpu) { $maxCpu = $cpu }
    if ($elapsed -gt 0) {
        $rate = $cpu / $elapsed
        if ($rate -gt 0.6) { $busy++ }
    }
    if ($proc.MainWindowHandle -ne 0 -and $handle -eq 0) {
        $handle = $proc.MainWindowHandle
        $title = $proc.MainWindowTitle
        $firstAt = $elapsed
        W ("WINDOW at " + $elapsed + "s  handle=" + $handle + "  title=[" + $title + "]")
        break
    }
}

$proc.Refresh()
$exited = $proc.HasExited
$exitCode = -1
if ($exited) { $exitCode = $proc.ExitCode }

if (-not $exited) {
    Start-Sleep -Seconds 2
    $proc.Refresh()
    W ("still alive, windows = " + $(if ($proc.MainWindowHandle -ne 0) { 1 } else { 0 }))
    try {
        W ("responding = " + $proc.Responding + "  threads = " + $proc.Threads.Count +
           "  WS(MB) = " + [math]::Round($proc.WorkingSet64 / 1MB, 1) + "  CPU = " + $proc.CPU)
        $mods = @()
        foreach ($m in $proc.Modules) { $mods += $m.ModuleName }
        W ("modules(count) = " + $mods.Count)
        $forms = $mods | Where-Object { $_ -like "*Windows.Forms*" }
        if ($forms) { W ("WinForms loaded: YES") } else { W ("WinForms loaded: NO") }
    } catch { W ("proc info failed: " + $_.Exception.Message) }
}

# screenshot only when a window actually exists
if ($handle -ne 0) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        Start-Sleep -Seconds 3
        $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($b.Location, ([System.Drawing.Point]::Empty), $b.Size)
        $shot = Join-Path $OutDir "screen.png"
        $bmp.Save($shot, [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose()
        W ("screenshot saved")
    } catch {
        W ("screenshot failed: " + $_.Exception.Message)
    }
}

if (-not $exited) { $proc.Kill(); W ("killed") }
$stdout = $so.Result
$stderr = $se.Result
if ($stdout) { $stdout | Out-File (Join-Path $OutDir "stdout.log") -Encoding ascii }
if ($stderr) { $stderr | Out-File (Join-Path $OutDir "stderr.log") -Encoding ascii }
if ($stderr) { W ("stderr head: " + $stderr.Substring(0, [Math]::Min(900, $stderr.Length))) }

$verdict = "FAIL"
if ($handle -ne 0) { $verdict = "PASS" }
elseif ($busy -gt 3) { $verdict = "FAIL-INFINITE-LOOP" }
elseif ($exited) { $verdict = "FAIL-EXITED(code=$exitCode)" }
else { $verdict = "FAIL-NO-WINDOW-IDLE" }

W ("VERDICT = " + $verdict + "  (window=" + ($handle -ne 0) + " cpu=" + [math]::Round($maxCpu, 1) +
   "s busySamples=" + $busy + "/" + $samples + " title=[" + $title + "])")
W ("done")

$result = [PSCustomObject]@{
    exe        = $fi.Name
    md5        = (Get-FileHash $ExePath -Algorithm MD5).Hash
    hasWindow  = ($handle -ne 0)
    windowTitle = $title
    firstWindowSec = $firstAt
    exited     = $exited
    exitCode   = $exitCode
    maxCpuSec  = [math]::Round($maxCpu, 2)
    busySamples = $busy
    totalSamples = $samples
    verdict    = $verdict
}
$result | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutDir "result.json") -Encoding ascii
Write-Output ("RESULT_JSON " + ($result | ConvertTo-Json -Compress -Depth 5))
