param(
  [string]$Exe = "app\AirExplorer.exe",
  [string]$Out = "out\holder.tsv"
)

# hostdump: 在官方 exe 的宿主进程里，把 <Module>{...} 这类"字符串表持有者"的
# 运行时状态导出。目的：拿到 InstantiateStatelessUser 解释器执行后的最终字段值，
# 供脱壳版直接硬编码（绕开"跨模块移植解释器必然 AV"的死结）。
#
# 输出格式（TSV，一行一条）:
#   H|section|text
#   S|type|field|fieldType|value            静态字段
#   I|ownerType|ownerField|field|fieldType|value   对象字段（展开一层）
#   E|...|exception                         取值异常

$ErrorActionPreference = "Continue"

function W([string]$s) {
  [void]$script:lines.Add($s)
}

$script:lines = New-Object System.Collections.ArrayList

function Esc($o) {
  if ($null -eq $o) { return "<null>" }
  $s = [string]$o
  $s = $s.Replace("`t", " ").Replace("`r", " ").Replace("`n", " ")
  if ($s.Length -gt 300) { $s = $s.Substring(0, 300) + "..." }
  return $s
}

function Simple($v) {
  if ($null -eq $v) { return $null }
  $t = $v.GetType()
  if ($t.IsPrimitive -or $t -eq [string] -or $t -eq [decimal]) { return $v }
  return $null
}

W "H|start|$(Get-Date -Format o)"
W "H|exe|$Exe"
W "H|psver|$($PSVersionTable.PSVersion)"

try {
  $asm = [Reflection.Assembly]::LoadFrom((Resolve-Path $Exe).Path)
  W "H|loaded|$($asm.FullName)"
} catch {
  W "H|fatal|LoadFrom: $($_.Exception.ToString())"
  $script:lines | Out-File -FilePath $Out -Encoding utf8
  exit 2
}

try {
  $mod = $asm.ManifestModule
  W "H|module|$($mod.Name)  fullyQualified=$($mod.FullyQualifiedName)"
} catch {
  W "H|fatal|module: $($_.Exception.ToString())"
  $script:lines | Out-File -FilePath $Out -Encoding utf8
  exit 3
}

# 1) 先跑模块初始化器（<Module>::.cctor）。它内部会装 JIT hook、解密 NecroBit、
#    并把 DispatcherInitializer / holder 的静态字段建起来。
$t0 = Get-Date
try {
  [Runtime.CompilerServices.RuntimeHelpers]::RunModuleConstructor($mod.ModuleHandle)
  W "H|modulecctor|ok  elapsed=$([int]((Get-Date) - $t0).TotalMilliseconds)ms"
} catch {
  W "H|modulecctor|throw: $($_.Exception.ToString())"
}

# 2) 枚举类型
$types = $null
try { $types = $mod.GetTypes() } catch { W "H|gettypes|throw: $($_.Exception.ToString())" }
if ($null -eq $types) { $script:lines | Out-File -FilePath $Out -Encoding utf8; exit 4 }
W "H|typecount|$($types.Length)"

$targets = New-Object System.Collections.ArrayList
foreach ($t in $types) {
  $fn = ""
  try { $fn = $t.FullName } catch { continue }
  if ($fn -like "<Module>*") { [void]$targets.Add($t); continue }
  if ($fn -like "CloudClient.Templating.DispatcherInitializer*" -and $fn -notlike "*/?*") { [void]$targets.Add($t); continue }
  if ($fn -eq "CloudClient.Templating.TemplateArgument") { [void]$targets.Add($t); continue }
}
W "H|targetcount|$($targets.Count)"

$statFlags = [Reflection.BindingFlags]"Public,NonPublic,Static"
$instFlags = [Reflection.BindingFlags]"Public,NonPublic,Instance,Static"

foreach ($t in $targets) {
  $tn = "<unknown>"
  try { $tn = $t.FullName } catch { continue }
  $fs = $null
  try { $fs = $t.GetFields($statFlags) } catch { W "E|$tn|*|getfields|$($_.Exception.GetType().Name)"; continue }
  W "H|type|$tn  statics=$($fs.Length)"
  foreach ($f in $fs) {
    $fname = $f.Name
    $ftype = ""
    try { $ftype = $f.FieldType.Name } catch {}
    $v = $null
    $threw = $false
    try { $v = $f.GetValue($null) } catch { $threw = $true; W "E|$tn|$fname|get|$($_.Exception.GetType().Name): $($_.Exception.Message)" }
    if ($threw) { continue }

    $sv = Simple $v
    if ($null -ne $sv -or $null -eq $v) {
      W "S|$tn|$fname|$ftype|$(Esc $sv)"
      continue
    }

    # 非基元：数组 / 集合 / 对象
    $vt = $v.GetType()
    if ($v -is [System.Array]) {
      $len = 0
      try { $len = $v.Length } catch {}
      W "S|$tn|$fname|$ftype|<array len=$len elem=$($vt.GetElementType().Name)>"
      $n = [Math]::Min($len, 64)
      for ($i = 0; $i -lt $n; $i++) {
        $ev = $null
        try { $ev = $v.GetValue($i) } catch {}
        $esv = Simple $ev
        if ($null -ne $esv -or $null -eq $ev) { W "A|$tn|$fname|$i|$(Esc $esv)" }
        else { W "A|$tn|$fname|$i|<obj $($ev.GetType().FullName)>" }
      }
      continue
    }

    W "S|$tn|$fname|$ftype|<object $($vt.FullName)>"
    $ifs = $null
    try { $ifs = $vt.GetFields($instFlags) } catch { continue }
    $cnt = 0
    foreach ($inf in $ifs) {
      if ($cnt -ge 400) { W "I|$tn|$fname|...|...|<truncated>"; break }
      $cnt++
      $ifn = $inf.Name
      $ift = ""
      try { $ift = $inf.FieldType.Name } catch {}
      $iv = $null
      try { $iv = $inf.GetValue($v) } catch { W "E|$tn|$fname.$ifn|get|$($_.Exception.GetType().Name)"; continue }
      $isv = Simple $iv
      if ($null -ne $isv -or $null -eq $iv) { W "I|$tn|$fname|$ifn|$ift|$(Esc $isv)" }
      else { W "I|$tn|$fname|$ifn|$ift|<obj $($iv.GetType().FullName)>" }
    }
  }
}

W "H|end|$(Get-Date -Format o)  total=$($script:lines.Count)"
$dir = Split-Path -Parent $Out
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
$script:lines | Out-File -FilePath $Out -Encoding utf8
Write-Host ("wrote " + $Out + " lines=" + $script:lines.Count)
