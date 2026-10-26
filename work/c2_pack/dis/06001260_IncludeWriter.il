# token=06001260 rva=0BCED8 name=IncludeWriter source=dump_full grp=gfp
# {'ilsize': 454, 'maxstack': 6, 'eh': 0}
  IL_0000  ldc.i4 0x49c3cf3d
  IL_0005  stloc 0
  IL_0009  ldc.i4 0x4
  IL_000E  stloc 2
  IL_0012  ldloc 2
  IL_0016  switch(5) 0xc4,0x133,0x10a,0xf8,0x2f
  IL_002F  nop
  IL_0030  ldc.i4.s 0x1a
  IL_0032  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_0037  ldsfld 0xa000125   ; MemberRef:System.IO.Path::DirectorySeparatorChar
  IL_003C  stloc.s 0x1
  IL_003E  ldloca.s 0x1
  IL_0040  ldsfld 0x40021c6   ; Field:21C6
  IL_0045  call 0x60048b0   ; MethodDef:ExecuteExplorer
  IL_004A  call 0x6003654   ; MethodDef:FetchLiteralListener
  IL_004F  ldsfld 0xa000125   ; MemberRef:System.IO.Path::DirectorySeparatorChar
  IL_0054  stloc.s 0x1
  IL_0056  ldloca.s 0x1
  IL_0058  ldsfld 0x40021c6   ; Field:21C6
  IL_005D  call 0x60048b0   ; MethodDef:ExecuteExplorer
  IL_0062  ldsfld 0x40021c8   ; Field:21C8
  IL_0067  call 0x60048b8   ; MethodDef:ExecuteExplorer
  IL_006C  ldc.i4 0x5eb49204
  IL_0071  not
  IL_0072  ldc.i4 0xaae31e58
  IL_0077  xor
  IL_0078  ldsfld 0x40020b8   ; Field:20B8
  IL_007D  ldfld 0x40020e4   ; Field:20E4
  IL_0082  xor
  IL_0083  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0088  ldsfld 0x4002219   ; Field:2219
  IL_008D  call 0x60049fc   ; MethodDef:ExecuteExplorer
  IL_0092  ldsfld 0x400215a   ; Field:215A
  IL_0097  call 0x6004700   ; MethodDef:ExecuteExplorer
  IL_009C  brtrue IL_00c4
  IL_00A1  ldc.i4 0x1
  IL_00A6  stloc 2
  IL_00AA  ldc.i4 0x3850c172
  IL_00AF  stloc 0
  IL_00B3  br IL_0012
  IL_00B8  ldarg.0
  IL_00B9  call 0x6003c79   ; MethodDef:RequestEditableTag
  IL_00BE  newobj 0xa00028d   ; MemberRef:mrp_tag4#191::.ctor
  IL_00C3  ret
  IL_00C4  ldarg.0
  IL_00C5  newobj 0x6003aed   ; MethodDef:.ctor
  IL_00CA  call 0x6003c7a   ; MethodDef:RequestVirtualStream
  IL_00CF  br IL_0187
  IL_00D4  ldarg.0
  IL_00D5  callvirt 0x6003c80   ; MethodDef:InstantiateAllocator
  IL_00DA  pop
  IL_00DB  ldloc 0
  IL_00DF  ldc.i4 0xfe48174b
  IL_00E4  add
  IL_00E5  stloc 2
  IL_00E9  ldloc 0
  IL_00ED  ldc.i4 0x75b60151
  IL_00F2  add
  IL_00F3  stloc 0
  IL_00F7  br IL_0012
  IL_00FC  ldarg.0
  IL_00FD  call 0x6003c79   ; MethodDef:RequestEditableTag
  IL_0102  ldarg.0
  IL_0103  ldfld 0x4000774   ; Field:0774
  IL_0108  callvirt 0x6003ad9   ; MethodDef:RequestPassiveDistributor
  IL_010D  br IL_00b8
  IL_0112  ldloc.s 0x3
  IL_0114  call 0x6003b5f   ; MethodDef:op_Implicit
  IL_0119  brfalse IL_01c3
  IL_011E  ldloc 0
  IL_0122  ldc.i4 0xd8768ac1
  IL_0127  add
  IL_0128  stloc 2
  IL_012C  ldloc 0
  IL_0130  ldc.i4 0xda2e7379
  IL_0135  add
  IL_0136  stloc 0
  IL_013A  br IL_0012
  IL_013F  call 0x6003654   ; MethodDef:FetchLiteralListener
  IL_0144  ldc.i4 0x633267a5
  IL_0149  ldc.i4 0x2566b758
  IL_014E  sub
  IL_014F  ldc.i4 0x233c3565
  IL_0154  xor
  IL_0155  ldsfld 0x40020b8   ; Field:20B8
  IL_015A  ldfld 0x40020c5   ; Field:20C5
  IL_015F  xor
  IL_0160  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0165  ldsfld 0x4002160   ; Field:2160
  IL_016A  call 0x6004718   ; MethodDef:ExecuteExplorer
  IL_016F  call 0x6003654   ; MethodDef:FetchLiteralListener
  IL_0174  ldc.i4.0
  IL_0175  ldc.i4.s 0x30
  IL_0177  ldsfld 0x40024df   ; Field:24DF
  IL_017C  call 0x6005514   ; MethodDef:ExecuteExplorer
  IL_0181  pop
  IL_0182  br IL_00c4
  IL_0187  ldarg.0
  IL_0188  call 0x6003c79   ; MethodDef:RequestEditableTag
  IL_018D  ldarg.0
  IL_018E  call 0x6003c68   ; MethodDef:RequestActiveProc
  IL_0193  callvirt 0x6003adf   ; MethodDef:DisplayExternalQueue
  IL_0198  br IL_019d
  IL_019D  ldarg.0
  IL_019E  ldarg.0
  IL_019F  call 0x6003c79   ; MethodDef:RequestEditableTag
  IL_01A4  ldc.i4.1
  IL_01A5  callvirt 0x6003c7e   ; MethodDef:CalcBuffer
  IL_01AA  stloc.s 0x3
  IL_01AC  ldc.i4 0x2
  IL_01B1  stloc 2
  IL_01B5  ldc.i4 0x2789753f
  IL_01BA  stloc 0
  IL_01BE  br IL_0012
  IL_01C3  ldloc.s 0x3
  IL_01C5  ret
