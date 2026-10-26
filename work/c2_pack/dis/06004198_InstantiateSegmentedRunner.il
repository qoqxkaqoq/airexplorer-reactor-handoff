# token=06004198 rva=3FDC94 name=InstantiateSegmentedRunner source=dump_full grp=validator
# {'ilsize': 311, 'maxstack': 8, 'eh': 0}
  IL_0000  ldarg.2
  IL_0001  stloc.0
  IL_0002  ldsfld 0x4001fc1   ; Field:1FC1
  IL_0007  brfalse IL_000e
  IL_000C  ldarg.1
  IL_000D  stloc.0
  IL_000E  ldc.i4.0
  IL_000F  conv.i8
  IL_0010  stloc.1
  IL_0011  call 0xa0009db   ; MemberRef:System.IntPtr::get_Size
  IL_0016  ldc.i4.4
  IL_0017  bne.un IL_0030
  IL_001C  ldloc.0
  IL_001D  call 0xa0009db   ; MemberRef:System.IntPtr::get_Size
  IL_0022  ldc.i4.2
  IL_0023  mul
  IL_0024  call 0xa0009dc   ; MemberRef:System.Runtime.InteropServices.Marshal::ReadInt32
  IL_0029  conv.i8
  IL_002A  stloc.1
  IL_002B  br IL_003e
  IL_0030  ldloc.0
  IL_0031  call 0xa0009db   ; MemberRef:System.IntPtr::get_Size
  IL_0036  ldc.i4.2
  IL_0037  mul
  IL_0038  call 0xa0009dd   ; MemberRef:System.Runtime.InteropServices.Marshal::ReadInt64
  IL_003D  stloc.1
  IL_003E  ldsfld 0x4001fda   ; Field:1FDA
  IL_0043  ldloc.1
  IL_0044  box 0x1000066   ; TypeRef:System.Int64
  IL_0049  callvirt 0xa0009de   ; MemberRef:System.Collections.Hashtable::get_Item
  IL_004E  stloc.2
  IL_004F  ldloc.2
  IL_0050  brfalse IL_0124
  IL_0055  ldloc.2
  IL_0056  unbox.any 0x2000629   ; TypeDef#1577
  IL_005B  stloc.3
  IL_005C  ldloc.3
  IL_005D  ldfld 0x4001fe0   ; Field:1FE0
  IL_0062  ldlen
  IL_0063  conv.i4
  IL_0064  call 0xa0009df   ; MemberRef:System.Runtime.InteropServices.Marshal::AllocCoTaskMem
  IL_0069  stloc.s 0x4
  IL_006B  ldloc.3
  IL_006C  ldfld 0x4001fe0   ; Field:1FE0
  IL_0071  ldc.i4.0
  IL_0072  ldloc.s 0x4
  IL_0074  ldloc.3
  IL_0075  ldfld 0x4001fe0   ; Field:1FE0
  IL_007A  ldlen
  IL_007B  conv.i4
  IL_007C  call 0xa0009e0   ; MemberRef:System.Runtime.InteropServices.Marshal::Copy
  IL_0081  ldloc.3
  IL_0082  ldfld 0x4001fdf   ; Field:1FDF
  IL_0087  brfalse IL_00b4
  IL_008C  ldloc.s 0x4
  IL_008E  starg.s 0x4
  IL_0090  ldarg.s 0x5
  IL_0092  ldloc.3
  IL_0093  ldfld 0x4001fe0   ; Field:1FE0
  IL_0098  ldlen
  IL_0099  conv.i4
  IL_009A  unk54
  IL_009B  ldarg.s 0x4
  IL_009D  ldloc.3
  IL_009E  ldfld 0x4001fe0   ; Field:1FE0
  IL_00A3  ldlen
  IL_00A4  conv.i4
  IL_00A5  ldc.i4.s 0x40
  IL_00A7  ldsflda 0x4001fbc   ; Field:1FBC
  IL_00AC  call 0x60041a3   ; MethodDef:UpdatePredictor
  IL_00B1  pop
  IL_00B2  ldc.i4.0
  IL_00B3  ret
  IL_00B4  ldloc.0
  IL_00B5  call 0xa0009db   ; MemberRef:System.IntPtr::get_Size
  IL_00BA  ldc.i4.2
  IL_00BB  mul
  IL_00BC  ldloc.s 0x4
  IL_00BE  call 0xa0009e1   ; MemberRef:System.Runtime.InteropServices.Marshal::WriteIntPtr
  IL_00C3  ldloc.0
  IL_00C4  call 0xa0009db   ; MemberRef:System.IntPtr::get_Size
  IL_00C9  ldc.i4.3
  IL_00CA  mul
  IL_00CB  ldloc.3
  IL_00CC  ldfld 0x4001fe0   ; Field:1FE0
  IL_00D1  ldlen
  IL_00D2  conv.i4
  IL_00D3  call 0xa0009e2   ; MemberRef:System.Runtime.InteropServices.Marshal::WriteInt32
  IL_00D8  ldc.i4.0
  IL_00D9  stloc.s 0x5
  IL_00DB  ldarg.3
  IL_00DC  ldc.i4 0xcea1d7d
  IL_00E1  bne.un IL_00f0
  IL_00E6  ldsfld 0x4001fdd   ; Field:1FDD
  IL_00EB  brfalse IL_011b
  IL_00F0  ldsfld 0x4001fd7   ; Field:1FD7
  IL_00F5  ldarg.0
  IL_00F6  ldarg.1
  IL_00F7  ldarg.2
  IL_00F8  ldarg.3
  IL_00F9  ldarg.s 0x4
  IL_00FB  ldarg.s 0x5
  IL_00FD  callvirt 0x600425d   ; MethodDef:Invoke
  IL_0102  stloc.s 0x5
  IL_0104  ldloc.0
  IL_0105  call 0xa0009db   ; MemberRef:System.IntPtr::get_Size
  IL_010A  ldc.i4.2
  IL_010B  mul
  IL_010C  ldsfld 0xa000066   ; MemberRef:System.IntPtr::Zero
  IL_0111  call 0xa0009e1   ; MemberRef:System.Runtime.InteropServices.Marshal::WriteIntPtr
  IL_0116  br IL_0121
  IL_011B  ldc.i4.1
  IL_011C  stsfld 0x4001fdd   ; Field:1FDD
  IL_0121  ldloc.s 0x5
  IL_0123  ret
  IL_0124  ldsfld 0x4001fd7   ; Field:1FD7
  IL_0129  ldarg.0
  IL_012A  ldarg.1
  IL_012B  ldarg.2
  IL_012C  ldarg.3
  IL_012D  ldarg.s 0x4
  IL_012F  ldarg.s 0x5
  IL_0131  callvirt 0x600425d   ; MethodDef:Invoke
  IL_0136  ret
