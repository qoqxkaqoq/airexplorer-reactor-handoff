# token=060041A3 rva=407298 name=UpdatePredictor source=dump_full grp=validator
# {'ilsize': 85, 'maxstack': 6, 'eh': 0}
  IL_0000  ldsfld 0x4001fc4   ; Field:1FC4
  IL_0005  brtrue IL_0046
  IL_000A  call 0x60041a6   ; MethodDef:keogyBbmx
  IL_000F  ldstr 0x70000ce0   ; "sources"
  IL_0014  call 0xa0009d9   ; MemberRef:System.String::Trim
  IL_0019  ldstr 0x70000d2c   ; "loudClient.Clouds.CloudMega.Properties.Resources"
  IL_001E  call 0xa0009f0   ; MemberRef:System.String::Concat
  IL_0023  call 0x600419f   ; MethodDef:StopClient
  IL_0028  ldc.i4 0x200062e
  IL_002D  call 0x6004284   ; MethodDef:VerifyScopeAnnotationInspector
  IL_0032  call 0xa000996   ; MemberRef:System.Type::GetTypeFromHandle
  IL_0037  call 0xa0009f1   ; MemberRef:System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer
  IL_003C  castclass 0x200062e   ; TypeDef#1582
  IL_0041  stsfld 0x4001fc4   ; Field:1FC4
  IL_0046  ldsfld 0x4001fc4   ; Field:1FC4
  IL_004B  ldarg.0
  IL_004C  ldarg.1
  IL_004D  ldarg.2
  IL_004E  ldarg.3
  IL_004F  callvirt 0x6004277   ; MethodDef:Invoke
  IL_0054  ret
