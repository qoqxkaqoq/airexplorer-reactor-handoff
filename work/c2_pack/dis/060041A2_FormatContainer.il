# token=060041A2 rva=407228 name=FormatContainer source=dump_full grp=validator
# {'ilsize': 97, 'maxstack': 7, 'eh': 0}
  IL_0000  ldsfld 0x4001fbb   ; Field:1FBB
  IL_0005  brtrue IL_0050
  IL_000A  call 0x60041a6   ; MethodDef:keogyBbmx
  IL_000F  ldstr 0x70000cfe   ; "rces"
  IL_0014  call 0xa0009d9   ; MemberRef:System.String::Trim
  IL_0019  ldstr 0x70000d0c
  IL_001E  call 0xa0009d9   ; MemberRef:System.String::Trim
  IL_0023  ldstr 0x70000d1e   ; "CloudClient.Clouds.CloudMega.Properties.Resources"
  IL_0028  call 0xa0009f2   ; MemberRef:System.String::Concat
  IL_002D  call 0x600419f   ; MethodDef:StopClient
  IL_0032  ldc.i4 0x200062d
  IL_0037  call 0x6004284   ; MethodDef:VerifyScopeAnnotationInspector
  IL_003C  call 0xa000996   ; MemberRef:System.Type::GetTypeFromHandle
  IL_0041  call 0xa0009f1   ; MemberRef:System.Runtime.InteropServices.Marshal::GetDelegateForFunctionPointer
  IL_0046  castclass 0x200062d   ; TypeDef#1581
  IL_004B  stsfld 0x4001fbb   ; Field:1FBB
  IL_0050  ldsfld 0x4001fbb   ; Field:1FBB
  IL_0055  ldarg.0
  IL_0056  ldarg.1
  IL_0057  ldarg.2
  IL_0058  ldarg.3
  IL_0059  ldarg.s 0x4
  IL_005B  callvirt 0x6004273   ; MethodDef:Invoke
  IL_0060  ret
