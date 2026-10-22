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

# 3) 触发字符串表加载（官方 exe 里解释器能跑），再补一次字节数组导出。
#    InstantiateTransferableProgram 开头有 "调用方必须是本程序集" 的反篡改检查，
#    所以走 SearchStrategy：它是脚本 44 的入口，直接把资源解密进 _ExtractorVisitors。
$script:lines | Out-File -FilePath $Out -Encoding utf8   # 先落盘, 后面若 AV 也不至于全丢
try {
  $di = $asm.GetType("CloudClient.Templating.DispatcherInitializer")
  W "H|di|$($di.FullName)"
  if ($di) {
    $res = $asm.GetManifestResourceStream("GlobalValidator.FactoryValidator")
    if ($null -eq $res) { W "H|resource|<null>" } else { W "H|resource|len=$($res.Length)" }
    $ss = $di.GetMethod("SearchStrategy", [Reflection.BindingFlags]"Static,Public,NonPublic")
    W "H|searchstrategy_method|$($ss -ne $null)"
    if ($ss -and $res) {
      try { $res.Position = 0 } catch {}
      $t1 = Get-Date
      try {
        $null = $ss.Invoke($null, @($res, 0))
        W "H|searchstrategy|ok elapsed=$([int]((Get-Date) - $t1).TotalMilliseconds)ms"
      } catch {
        $ie = $_.Exception.InnerException
        if ($ie) { W "H|searchstrategy|throw: $($ie.ToString())" } else { W "H|searchstrategy|throw: $($_.Exception.ToString())" }
      }
    }
    # 导出 _ExtractorVisitors
    $evf = $di.GetField("_ExtractorVisitors", [Reflection.BindingFlags]"Static,Public,NonPublic")
    if ($evf) {
      $ev = $evf.GetValue($null)
      if ($null -eq $ev) { W "H|extractor|<null>" }
      else {
        W "H|extractor|len=$($ev.Length)"
        $binPath = $Out + ".extractor.bin"
        try { [IO.File]::WriteAllBytes($binPath, $ev); W "H|extractor_bin|$binPath" } catch { W "H|extractor_bin|throw $($_.Exception.Message)" }
        # 头 8 个字符串（验证）
        try {
          $n = 0; $off = 0
          while ($n -lt 8 -and $off + 4 -le $ev.Length) {
            $len = [BitConverter]::ToInt32($ev, $off)
            if ($len -lt 0 -or $off + 4 + $len -gt $ev.Length) { W "A|xstr|$n|<bad len=$len off=$off>"; break }
            $s = [Text.Encoding]::Unicode.GetString($ev, $off + 4, $len)
            W "A|xstr|$n|off=$off len=$len|$(Esc $s)"
            $off += 4 + $len
            $n++
          }
          W "H|extractor_first|ok"
        } catch { W "H|extractor_first|throw $($_.Exception.Message)" }
      }
    }
    # editableMonitorTemplates / _RecommenderTemplates 概览
    try {
      $lt = $di.GetField("editableMonitorTemplates", [Reflection.BindingFlags]"Static,Public,NonPublic").GetValue($null)
      $ri = $di.GetField("_RecommenderTemplates", [Reflection.BindingFlags]"Static,Public,NonPublic").GetValue($null)
      W "H|editableMonitorTemplates|$(if ($null -eq $lt) { '<null>' } else { 'count=' + $lt.Count })"
      W "H|_RecommenderTemplates|$(if ($null -eq $ri) { '<null>' } else { 'count=' + $ri.Count })"
      if ($lt -and $lt.Count -gt 0) {
        for ($i = 0; $i -lt [Math]::Min(20, $lt.Count); $i++) { W "T|$i|$(Esc $lt[$i])" }
      }
    } catch { W "H|lists|throw $($_.Exception.Message)" }
  }
} catch { W "H|trigger|throw: $($_.Exception.ToString())" }

# 4) 委托字段诊断: TrackCompiler 用数据驱动给静态字段赋委托, 目标方法名只能在运行时看到。
#    这一步回答: CheckAlphabeticProject 指向哪个方法? 那个方法在我们的 exe 里是不是桩?
$probeTypes = @(
  "ValidatorParserCollection",
  "CloudClient.Templating.TemplateInitializer",
  "AirExplorer.Values.ArgumentGateway",
  "AirExplorer.Networking.RequestWorker"
)
foreach ($tn in $probeTypes) {
  try {
    $t = $asm.GetType($tn)
    if ($null -eq $t) { W "D|$tn|<type missing>"; continue }
    foreach ($f in $t.GetFields([Reflection.BindingFlags]"Public,NonPublic,Static")) {
      $val = $null
      try { $val = $f.GetValue($null) } catch { W "D|$tn|$($f.Name)|<throw $($_.Exception.GetType().Name)>"; continue }
      if ($null -eq $val) { W "D|$tn|$($f.Name)|<null>"; continue }
      if ($val -is [Delegate]) {
        $dm = $null
        try { $dm = $val.Method } catch {}
        $dt = $null
        try { $dt = $dm.DeclaringType.FullName } catch {}
        $dn = $null
        try { $dn = $dm.Name } catch {}
        W "D|$tn|$($f.Name)|delegate->$dt::$dn"
      } else {
        W "D|$tn|$($f.Name)|$($val.GetType().FullName)"
      }
    }
  } catch { W "D|$tn|<fatal $($_.Exception.GetType().Name)>" }
}

W "H|end|$(Get-Date -Format o)  total=$($script:lines.Count)"
$dir = Split-Path -Parent $Out
if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
$script:lines | Out-File -FilePath $Out -Encoding utf8
Write-Host ("wrote " + $Out + " lines=" + $script:lines.Count)
