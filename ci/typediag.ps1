param([string]$Exe)
# typediag: 逐个类型/字段/方法地触发签名解析, 定位 TypeLoadException 到底出在哪个成员上。
$ErrorActionPreference = "Continue"
$asm = [Reflection.Assembly]::LoadFrom((Resolve-Path $Exe).Path)
$mod = $asm.ManifestModule
Write-Host ("module=" + $mod.Name)
$types = $mod.GetTypes()
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
