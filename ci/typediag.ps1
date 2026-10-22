param([string]$Exe)
# typediag: 逐个类型/字段/方法地触发签名解析, 定位 TypeLoadException 到底出在哪个成员上。
$ErrorActionPreference = "Continue"
$asm = [Reflection.Assembly]::LoadFrom((Resolve-Path $Exe).Path)
$mod = $asm.ManifestModule
Write-Host ("module=" + $mod.Name)
try {
  $types = $mod.GetTypes()
} catch {
  $ie = $_.Exception.InnerException
  if ($null -eq $ie) { $ie = $_.Exception }
  Write-Host ("GetTypes failed: " + $ie.GetType().Name)
  if ($ie -is [Reflection.ReflectionTypeLoadException]) {
    $les = $ie.LoaderExceptions
    Write-Host ("loaderExceptions=" + $les.Length)
    $seen = @{}
    foreach ($le in $les) {
      if ($null -eq $le) { continue }
      $msg = $le.GetType().Name + ": " + $le.Message
      if (-not $seen.ContainsKey($msg)) { $seen[$msg] = 1; Write-Host ("  " + $msg) }
    }
    $types = @($ie.Types | Where-Object { $null -ne $_ })
  } else {
    $types = @()
  }
}
Write-Host ("types=" + $types.Length)
$bad = 0
foreach ($t in $types) {
  $tn = "?"
  try { $tn = $t.FullName } catch { continue }
  try {
    $null = $t.GetFields([Reflection.BindingFlags]"Public,NonPublic,Static,Instance")
  } catch {
    Write-Host ("[FIELDS] " + $tn + "  " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
    $bad++
  }
  try {
    $null = $t.GetMethods([Reflection.BindingFlags]"Public,NonPublic,Static,Instance")
  } catch {
    Write-Host ("[METHODS] " + $tn + "  " + $_.Exception.GetType().Name + ": " + $_.Exception.Message)
    $bad++
  }
}
Write-Host ("bad=" + $bad)
