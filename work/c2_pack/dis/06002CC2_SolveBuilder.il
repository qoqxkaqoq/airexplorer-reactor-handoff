# token=06002CC2 rva=2619C8 name=SolveBuilder source=dump_full grp=gfp
# {'ilsize': 871, 'maxstack': 6, 'eh': 0}
  IL_0000  ldc.i4 0x56c0f6f6
  IL_0005  stloc 0
  IL_0009  ldc.i4 0x4
  IL_000E  stloc 3
  IL_0012  ldloc 3
  IL_0016  switch(9) 0x2db,0x33f,0x30b,0x8e,0x2f,0xa6,0x5f,0x170,0x1d1
  IL_003F  nop
  IL_0040  ldarg.1
  IL_0041  brfalse IL_029c
  IL_0046  ldloc 0
  IL_004A  ldc.i4 0xa93f090b
  IL_004F  add
  IL_0050  stloc 3
  IL_0054  ldloc 0
  IL_0058  ldc.i4 0xd6d81583
  IL_005D  add
  IL_005E  stloc 0
  IL_0062  br IL_0012
  IL_0067  ldloc.s 0x2
  IL_0069  ldarg.1
  IL_006A  ldarg.2
  IL_006B  ldnull
  IL_006C  callvirt 0x60032dc   ; MethodDef:FetchDividedAllocator
  IL_0071  br IL_0286
  IL_0076  ldarg.1
  IL_0077  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_007C  ldsfld 0x40021fd   ; Field:21FD
  IL_0081  call 0x600498c   ; MethodDef:ExecuteExplorer
  IL_0086  ldc.i4 0x8
  IL_008B  stloc 3
  IL_008F  ldc.i4 0x21997597
  IL_0094  stloc 0
  IL_0098  brtrue IL_0012
  IL_009D  br IL_0207
  IL_00A2  ldarg.2
  IL_00A3  isinst 0x200059d   ; TypeDef#1437
  IL_00A8  brfalse IL_019d
  IL_00AD  br IL_0229
  IL_00B2  ldarg.1
  IL_00B3  isinst 0x200059d   ; TypeDef#1437
  IL_00B8  callvirt 0x6003d1c   ; MethodDef:FilterAttribute
  IL_00BD  ldloc 0
  IL_00C1  ldc.i4 0xcc190542
  IL_00C6  add
  IL_00C7  stloc 3
  IL_00CB  ldloc 0
  IL_00CF  ldc.i4 0xcda128db
  IL_00D4  add
  IL_00D5  stloc 0
  IL_00D9  brfalse IL_0012
  IL_00DE  ldloc 0
  IL_00E2  ldc.i4 0xfe77dc6e
  IL_00E7  add
  IL_00E8  stloc 3
  IL_00EC  ldloc 0
  IL_00F0  ldc.i4 0x6ec22942
  IL_00F5  add
  IL_00F6  stloc 0
  IL_00FA  br IL_0012
  IL_00FF  ret
  IL_0100  ldloc.s 0x2
  IL_0102  ldsfld 0x40027c0   ; Field:27C0
  IL_0107  call 0x6006098   ; MethodDef:ExecuteExplorer
  IL_010C  br IL_0366
  IL_0111  call 0x6002a1d   ; MethodDef:FillHandler
  IL_0116  ldc.i4 0x1ad6be49
  IL_011B  ldc.i4 0x3ca50018
  IL_0120  xor
  IL_0121  ldsfld 0x40020b8   ; Field:20B8
  IL_0126  ldfld 0x40020ee   ; Field:20EE
  IL_012B  xor
  IL_012C  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0131  callvirt 0x6002a21   ; MethodDef:ParseResponsiveEnumerator
  IL_0136  call 0x6002a1d   ; MethodDef:FillHandler
  IL_013B  ldc.i4 0xfea8e036
  IL_0140  ldc.i4 0x2
  IL_0145  shl
  IL_0146  ldc.i4 0x974176aa
  IL_014B  xor
  IL_014C  ldsfld 0x40020b8   ; Field:20B8
  IL_0151  ldfld 0x4002086   ; Field:2086
  IL_0156  xor
  IL_0157  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_015C  callvirt 0x6002a21   ; MethodDef:ParseResponsiveEnumerator
  IL_0161  ldc.i4.0
  IL_0162  ldc.i4.s 0x40
  IL_0164  ldsfld 0x40024df   ; Field:24DF
  IL_0169  call 0x6005514   ; MethodDef:ExecuteExplorer
  IL_016E  pop
  IL_016F  br IL_02fa
  IL_0174  ldc.i4.0
  IL_0175  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_017A  stloc.s 0x1
  IL_017C  ldloc 0
  IL_0180  ldc.i4 0x8fb5b327
  IL_0185  add
  IL_0186  stloc 3
  IL_018A  ldloc 0
  IL_018E  ldc.i4 0x9182417
  IL_0193  add
  IL_0194  stloc 0
  IL_0198  br IL_0012
  IL_019D  ldarg.1
  IL_019E  isinst 0x200059d   ; TypeDef#1437
  IL_01A3  ldc.i4 0x0
  IL_01A8  stloc 3
  IL_01AC  ldc.i4 0x1882399
  IL_01B1  stloc 0
  IL_01B5  brfalse IL_0012
  IL_01BA  ldc.i4 0x5
  IL_01BF  stloc 3
  IL_01C3  ldc.i4 0x33e6fabe
  IL_01C8  stloc 0
  IL_01CC  br IL_0012
  IL_01D1  ldarg.2
  IL_01D2  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_01D7  ldsfld 0x40021fd   ; Field:21FD
  IL_01DC  call 0x600498c   ; MethodDef:ExecuteExplorer
  IL_01E1  brtrue IL_019d
  IL_01E6  ldloc 0
  IL_01EA  ldc.i4 0xde668a6c
  IL_01EF  add
  IL_01F0  stloc 3
  IL_01F4  ldloc 0
  IL_01F8  ldc.i4 0xf65e5815
  IL_01FD  add
  IL_01FE  stloc 0
  IL_0202  br IL_0012
  IL_0207  ldarg.1
  IL_0208  isinst 0x200059d   ; TypeDef#1437
  IL_020D  brtrue IL_0229
  IL_0212  ldc.i4 0x8
  IL_0217  stloc 3
  IL_021B  ldc.i4 0x21997597
  IL_0220  stloc 0
  IL_0224  br IL_0012
  IL_0229  call 0x6002a1d   ; MethodDef:FillHandler
  IL_022E  ldc.i4 0x6ff26cde
  IL_0233  ldc.i4 0x28b2367
  IL_0238  xor
  IL_0239  ldsfld 0x40020b8   ; Field:20B8
  IL_023E  ldfld 0x40020a8   ; Field:20A8
  IL_0243  xor
  IL_0244  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0249  callvirt 0x6002a21   ; MethodDef:ParseResponsiveEnumerator
  IL_024E  call 0x6002a1d   ; MethodDef:FillHandler
  IL_0253  ldc.i4 0xcc121a1d
  IL_0258  ldc.i4 0xa4e27377
  IL_025D  xor
  IL_025E  ldsfld 0x40020b8   ; Field:20B8
  IL_0263  ldfld 0x40020b2   ; Field:20B2
  IL_0268  xor
  IL_0269  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_026E  callvirt 0x6002a21   ; MethodDef:ParseResponsiveEnumerator
  IL_0273  ldc.i4.0
  IL_0274  ldc.i4.s 0x40
  IL_0276  ldsfld 0x40024df   ; Field:24DF
  IL_027B  call 0x6005514   ; MethodDef:ExecuteExplorer
  IL_0280  pop
  IL_0281  br IL_00ff
  IL_0286  ldloc.s 0x2
  IL_0288  ldsfld 0x4002935   ; Field:2935
  IL_028D  call 0x600666c   ; MethodDef:ExecuteExplorer
  IL_0292  brtrue IL_0366
  IL_0297  br IL_0100
  IL_029C  call 0x6002a1d   ; MethodDef:FillHandler
  IL_02A1  ldc.i4 0xc4d77a99
  IL_02A6  ldc.i4 0x935f9d92
  IL_02AB  xor
  IL_02AC  ldsfld 0x40020b8   ; Field:20B8
  IL_02B1  ldfld 0x40020ba   ; Field:20BA
  IL_02B6  xor
  IL_02B7  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_02BC  callvirt 0x6002a21   ; MethodDef:ParseResponsiveEnumerator
  IL_02C1  call 0x6002a1d   ; MethodDef:FillHandler
  IL_02C6  ldc.i4 0xcc121a1d
  IL_02CB  ldc.i4 0xea65ff34
  IL_02D0  xor
  IL_02D1  ldsfld 0x40020b8   ; Field:20B8
  IL_02D6  ldfld 0x40020ee   ; Field:20EE
  IL_02DB  xor
  IL_02DC  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_02E1  callvirt 0x6002a21   ; MethodDef:ParseResponsiveEnumerator
  IL_02E6  ldc.i4.0
  IL_02E7  ldc.i4.s 0x40
  IL_02E9  ldsfld 0x40024df   ; Field:24DF
  IL_02EE  call 0x6005514   ; MethodDef:ExecuteExplorer
  IL_02F3  pop
  IL_02F4  br IL_02f9
  IL_02F9  ret
  IL_02FA  ret
  IL_02FB  newobj 0x60032d1   ; MethodDef:.ctor
  IL_0300  stloc.s 0x2
  IL_0302  ldloc 0
  IL_0306  ldc.i4 0xfe77dc6d
  IL_030B  add
  IL_030C  stloc 3
  IL_0310  ldloc 0
  IL_0314  ldc.i4 0x5845c4b1
  IL_0319  add
  IL_031A  stloc 0
  IL_031E  br IL_0012
  IL_0323  ldarg.1
  IL_0324  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_0329  ldloc.s 0x1
  IL_032B  ldsfld 0x4002140   ; Field:2140
  IL_0330  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_0335  ldloc 0
  IL_0339  ldc.i4 0x869d8f0e
  IL_033E  add
  IL_033F  stloc 3
  IL_0343  ldloc 0
  IL_0347  ldc.i4 0x8825b2a7
  IL_034C  add
  IL_034D  stloc 0
  IL_0351  brfalse IL_0012
  IL_0356  br IL_0111
  IL_035B  ldarg.2
  IL_035C  brtrue IL_0076
  IL_0361  br IL_029c
  IL_0366  ret
