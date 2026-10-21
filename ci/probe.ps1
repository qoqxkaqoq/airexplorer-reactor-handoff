# probe.ps1 — 在 Windows runner 上验证某个 exe 是否真的出现了主窗口
#
# 验收口径(用户明确): 程序启动后出现正常主窗口 UI。
#   进程存活但无窗口 = 失败
# 本脚本同时记录 CPU 时间,用来区分两种"没 UI":
#   CPU 持续走高  -> 死循环卡住(本工程的已知病灶)
#   CPU 几乎不动  -> 没卡死,但是没走到建窗体那一步(别的原因)
#
# 用法: powershell -File probe.ps1 -Exe X.exe [-Seconds 90] [-Out result.json]
param(
    [Parameter(Mandatory = $true)] [string] $Exe,
    [int] $Seconds = 90,
    [string] $Out = ""
)

$name = [System.IO.Path]::GetFileNameWithoutExtension($Exe)
$logDir = "probe_$name"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

$stdoutLog = Join-Path $logDir "stdout.log"
$stderrLog = Join-Path $logDir "stderr.log"

"=== probe: $Exe ===" | Out-File -FilePath (Join-Path $logDir "summary.txt") -Encoding utf8

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = (Resolve-Path $Exe).Path
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.WorkingDirectory = (Get-Location).Path

$proc = [System.Diagnostics.Process]::Start($psi)
# 后台异步读取标准输出,防止管道写满把进程堵住
$so = $proc.StandardOutput.ReadToEndAsync()
$se = $proc.StandardError.ReadToEndAsync()

$deadline = (Get-Date).AddSeconds($Seconds)
$handle = 0
$title = ""
$samples = @()
$prevCpu = 0.0
$firstWindowAt = -1
$elapsed = 0

while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 2500
    $elapsed = [int]((Get-Date) - $proc.StartTime).TotalSeconds
    if ($proc.HasExited) { break }
    $proc.Refresh()
    $cpu = $proc.CPU
    $delta = $cpu - $prevCpu
    $prevCpu = $cpu
    $samples += [PSCustomObject]@{ t = $elapsed; cpu = [math]::Round($cpu, 2); dcpu = [math]::Round($delta, 2); hWnd = $proc.MainWindowHandle; title = $proc.MainWindowTitle }
    if ($proc.MainWindowHandle -ne 0 -and $handle -eq 0) {
        $handle = $proc.MainWindowHandle
        $title = $proc.MainWindowTitle
        $firstWindowAt = $elapsed
        break
    }
}

$proc.Refresh()
$exited = $proc.HasExited
$exitCode = if ($exited) { $proc.ExitCode } else { -1 }
if (-not $exited) {
    # 再采样一次最终状态
    $samples += [PSCustomObject]@{ t = $elapsed; cpu = [math]::Round($proc.CPU, 2); dcpu = 0; hWnd = $proc.MainWindowHandle; title = $proc.MainWindowTitle }
    if ($proc.MainWindowHandle -ne 0 -and $handle -eq 0) {
        $handle = $proc.MainWindowHandle
        $title = $proc.MainWindowTitle
        $firstWindowAt = $elapsed
    }
}

# ---- 有窗口就截图 ----
$shot = ""
if ($handle -ne 0) {
    try {
        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName System.Drawing
        Start-Sleep -Seconds 3
        $b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
        $bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
        $g = [System.Drawing.Graphics]::FromImage($bmp)
        $g.CopyFromScreen($b.Location, ([System.Drawing.Point]::Empty), $b.Size)
        $shot = Join-Path $logDir "screen.png"
        $bmp.Save($shot, [System.Drawing.Imaging.ImageFormat]::Png)
        $g.Dispose(); $bmp.Dispose()
    } catch {
        $shot = "screenshot-failed: " + $_.Exception.Message
    }
}

if (-not $exited) { $proc.Kill() }

$outText = $so.Result
$errText = $se.Result
if ($outText) { $outText | Out-File -FilePath $stdoutLog -Encoding utf8 }
if ($errText) { $errText | Out-File -FilePath $stderrLog -Encoding utf8 }

$maxCpu = 0.0
foreach ($s in $samples) { if ($s.cpu -gt $maxCpu) { $maxCpu = $s.cpu } }
$busy = 0
foreach ($s in $samples) { if ($s.dcpu -gt 1.0) { $busy++ } }

$result = [PSCustomObject]@{
    exe            = $name
    exited         = $exited
    exitCode       = $exitCode
    hasWindow      = ($handle -ne 0)
    windowTitle    = $title
    firstWindowSec = $firstWindowAt
    maxCpuSec      = [math]::Round($maxCpu, 2)
    busySamples    = $busy
    totalSamples   = $samples.Count
    screenshot     = $shot
    stdoutLen      = if ($outText) { $outText.Length } else { 0 }
    stderrLen      = if ($errText) { $errText.Length } else { 0 }
}

$result | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $logDir "result.json") -Encoding utf8
$samples | ConvertTo-Json -Depth 5 | Out-File -FilePath (Join-Path $logDir "samples.json") -Encoding utf8

$verdict = if ($result.hasWindow) { "PASS(有主窗口)" }
           elseif ($busy -gt 3) { "FAIL(疑似死循环, CPU 持续占用)" }
           elseif ($exited) { "FAIL(进程退出, exit=$exitCode)" }
           else { "FAIL(存活但无窗口, CPU 空闲)" }

$line = "{0,-28} {1}" -f $name, $verdict
$line | Tee-Object -FilePath (Join-Path $logDir "summary.txt") -Append
Write-Output ("RESULT|" + $name + "|" + $result.hasWindow + "|" + $verdict + "|cpu=" + $result.maxCpuSec + "|title=" + $title)

if ($result.hasWindow) { Write-Output "  >>> 有 UI! 标题: $title (第 $($result.firstWindowSec) 秒出现)" }
else {
    Write-Output "  >>> 无 UI。CPU 峰值 $($result.maxCpuSec)s / 忙碌采样 $busy/$($samples.Count)"
    if ($errText) { Write-Output ("  stderr 前 800 字: " + $errText.Substring(0, [Math]::Min(800, $errText.Length))) }
}
