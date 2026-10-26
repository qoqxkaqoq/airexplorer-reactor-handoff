# token=06002F2F rva=286AC4 name=RunPolicy source=dump_full grp=gfp
# {'ilsize': 1464, 'maxstack': 6, 'eh': 0}
  IL_0000  ldc.i4 0xcfad3a2
  IL_0005  stloc 1
  IL_0009  ldc.i4 0x1
  IL_000E  stloc 2
  IL_0012  ldloc 2
  IL_0016  switch(12) 0x19a,0x23,0x50f,0x46e,0x27c,0x3a4,0x386,0x21a,0x17d,0x10c,0x3f5,0x383
  IL_004B  nop
  IL_004C  ldarg.1
  IL_004D  callvirt 0x6003d1c   ; MethodDef:FilterAttribute
  IL_0052  brfalse IL_0595
  IL_0057  br IL_04cc
  IL_005C  ldarg.1
  IL_005D  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_0062  call 0x6002fb1   ; MethodDef:SetupObserver
  IL_0067  ldsfld 0x4002140   ; Field:2140
  IL_006C  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_0071  ldc.i4 0xb
  IL_0076  stloc 2
  IL_007A  ldc.i4 0x133d1ebe
  IL_007F  stloc 1
  IL_0083  brfalse IL_0012
  IL_0088  ldc.i4 0x3
  IL_008D  stloc 2
  IL_0091  ldc.i4 0x39f3f09e
  IL_0096  stloc 1
  IL_009A  br IL_0012
  IL_009F  nop
  IL_00A0  ldc.i4 0xb
  IL_00A5  stloc 2
  IL_00A9  ldc.i4 0x133d1ebe
  IL_00AE  stloc 1
  IL_00B2  br IL_0012
  IL_00B7  nop
  IL_00B8  ldc.i4 0xb
  IL_00BD  stloc 2
  IL_00C1  ldc.i4 0x133d1ebe
  IL_00C6  stloc 1
  IL_00CA  br IL_0012
  IL_00CF  ldarg.1
  IL_00D0  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_00D5  ldc.i4.s 0xd
  IL_00D7  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_00DC  ldsfld 0x4002140   ; Field:2140
  IL_00E1  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_00E6  ldc.i4 0x5
  IL_00EB  stloc 2
  IL_00EF  ldc.i4 0x34aca727
  IL_00F4  stloc 1
  IL_00F8  brfalse IL_0012
  IL_00FD  ldc.i4 0x6
  IL_0102  stloc 2
  IL_0106  ldc.i4 0x51fcfcff
  IL_010B  stloc 1
  IL_010F  br IL_0012
  IL_0114  ldc.i4 0xbe33214f
  IL_0119  ldc.i4 0x8a7e909e
  IL_011E  xor
  IL_011F  ldsfld 0x40020b8   ; Field:20B8
  IL_0124  ldfld 0x4002100   ; Field:2100
  IL_0129  xor
  IL_012A  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_012F  stloc.s 0x0
  IL_0131  br IL_02e9
  IL_0136  ldsfld 0x4002207   ; Field:2207
  IL_013B  call 0x60049b4   ; MethodDef:ExecuteExplorer
  IL_0140  ldsfld 0x4002208   ; Field:2208
  IL_0145  call 0x60049b8   ; MethodDef:ExecuteExplorer
  IL_014A  ldsfld 0x4002209   ; Field:2209
  IL_014F  call 0x60049bc   ; MethodDef:ExecuteExplorer
  IL_0154  ldc.i4.6
  IL_0155  ldc.i4 0xb
  IL_015A  stloc 2
  IL_015E  ldc.i4 0x133d1ebe
  IL_0163  stloc 1
  IL_0167  blt IL_0012
  IL_016C  br IL_005c
  IL_0171  nop
  IL_0172  ldc.i4 0xb
  IL_0177  stloc 2
  IL_017B  ldc.i4 0x133d1ebe
  IL_0180  stloc 1
  IL_0184  br IL_0012
  IL_0189  ldarg.1
  IL_018A  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_018F  ldc.i4.s 0x10
  IL_0191  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_0196  ldsfld 0x4002140   ; Field:2140
  IL_019B  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_01A0  brfalse IL_0435
  IL_01A5  ldloc 1
  IL_01A9  ldc.i4 0xa79d88b3
  IL_01AE  add
  IL_01AF  stloc 2
  IL_01B3  ldloc 1
  IL_01B7  ldc.i4 0xd687053b
  IL_01BC  add
  IL_01BD  stloc 1
  IL_01C1  br IL_0012
  IL_01C6  ldc.i4 0x97d40b94
  IL_01CB  ldc.i4 0xfbc9c2b1
  IL_01D0  xor
  IL_01D1  ldsfld 0x40020b8   ; Field:20B8
  IL_01D6  ldfld 0x40020fb   ; Field:20FB
  IL_01DB  xor
  IL_01DC  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_01E1  stloc.s 0x0
  IL_01E3  br IL_00b7
  IL_01E8  nop
  IL_01E9  ldc.i4 0xb
  IL_01EE  stloc 2
  IL_01F2  ldc.i4 0x133d1ebe
  IL_01F7  stloc 1
  IL_01FB  br IL_0012
  IL_0200  ldc.i4 0x85312d3f
  IL_0205  ldc.i4 0x89adb380
  IL_020A  add
  IL_020B  ldc.i4 0x28b4d601
  IL_0210  xor
  IL_0211  ldsfld 0x40020b8   ; Field:20B8
  IL_0216  ldfld 0x40020bf   ; Field:20BF
  IL_021B  xor
  IL_021C  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0221  stloc.s 0x0
  IL_0223  br IL_009f
  IL_0228  ldc.i4.m1
  IL_0229  ret
  IL_022A  ldarg.1
  IL_022B  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_0230  ldc.i4.s 0x11
  IL_0232  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_0237  ldsfld 0x4002140   ; Field:2140
  IL_023C  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_0241  brfalse IL_00cf
  IL_0246  br IL_050b
  IL_024B  nop
  IL_024C  ldc.i4 0xb
  IL_0251  stloc 2
  IL_0255  ldc.i4 0x133d1ebe
  IL_025A  stloc 1
  IL_025E  br IL_0012
  IL_0263  ldarg.1
  IL_0264  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_0269  ldc.i4 0xa0e112f2
  IL_026E  ldc.i4 0xd6ab0079
  IL_0273  xor
  IL_0274  ldsfld 0x40020b8   ; Field:20B8
  IL_0279  ldfld 0x40020e8   ; Field:20E8
  IL_027E  xor
  IL_027F  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0284  ldsfld 0x4002230   ; Field:2230
  IL_0289  call 0x6004a58   ; MethodDef:ExecuteExplorer
  IL_028E  brfalse IL_0136
  IL_0293  br IL_0301
  IL_0298  ldarg.1
  IL_0299  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_029E  ldc.i4 0xf31b0c07
  IL_02A3  ldc.i4 0x9a69bc91
  IL_02A8  xor
  IL_02A9  ldsfld 0x40020b8   ; Field:20B8
  IL_02AE  ldfld 0x40020ab   ; Field:20AB
  IL_02B3  xor
  IL_02B4  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_02B9  ldsfld 0x4002230   ; Field:2230
  IL_02BE  call 0x6004a58   ; MethodDef:ExecuteExplorer
  IL_02C3  brfalse IL_0263
  IL_02C8  ldloc 1
  IL_02CC  ldc.i4 0x91f7d506
  IL_02D1  add
  IL_02D2  stloc 2
  IL_02D6  ldloc 1
  IL_02DA  ldc.i4 0x96d24765
  IL_02DF  add
  IL_02E0  stloc 1
  IL_02E4  br IL_0012
  IL_02E9  nop
  IL_02EA  ldc.i4 0xb
  IL_02EF  stloc 2
  IL_02F3  ldc.i4 0x133d1ebe
  IL_02F8  stloc 1
  IL_02FC  br IL_0012
  IL_0301  ldarg.1
  IL_0302  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_0307  ldc.i4 0x5c81b045
  IL_030C  ldc.i4 0x77012a4f
  IL_0311  xor
  IL_0312  ldsfld 0x40020b8   ; Field:20B8
  IL_0317  ldfld 0x40020c6   ; Field:20C6
  IL_031C  xor
  IL_031D  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0322  ldarg.1
  IL_0323  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_0328  ldc.i4 0xb1e6986d
  IL_032D  ldc.i4 0x9124117e
  IL_0332  xor
  IL_0333  ldsfld 0x40020b8   ; Field:20B8
  IL_0338  ldfld 0x40020d5   ; Field:20D5
  IL_033D  xor
  IL_033E  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0343  ldsfld 0x4002149   ; Field:2149
  IL_0348  call 0x60046bc   ; MethodDef:ExecuteExplorer
  IL_034D  ldc.i4 0x2c05b3c1
  IL_0352  ldc.i4 0xd253a9a
  IL_0357  xor
  IL_0358  ldsfld 0x40020b8   ; Field:20B8
  IL_035D  ldfld 0x40020f7   ; Field:20F7
  IL_0362  xor
  IL_0363  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0368  ldsfld 0x4002446   ; Field:2446
  IL_036D  call 0x60052b0   ; MethodDef:ExecuteExplorer
  IL_0372  ldsfld 0x4002154   ; Field:2154
  IL_0377  call 0x60046e8   ; MethodDef:ExecuteExplorer
  IL_037C  stloc.s 0x0
  IL_037E  br IL_01e8
  IL_0383  ldloc.s 0x0
  IL_0385  ldsfld 0x40021fd   ; Field:21FD
  IL_038A  call 0x600498c   ; MethodDef:ExecuteExplorer
  IL_038F  ldc.i4.0
  IL_0390  ble IL_0228
  IL_0395  br IL_0502
  IL_039A  ldc.i4 0xd18dbb51
  IL_039F  ldc.i4 0x87c422d7
  IL_03A4  xor
  IL_03A5  ldsfld 0x40020b8   ; Field:20B8
  IL_03AA  ldfld 0x40020de   ; Field:20DE
  IL_03AF  xor
  IL_03B0  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_03B5  stloc.s 0x0
  IL_03B7  br IL_0171
  IL_03BC  ldarg.1
  IL_03BD  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_03C2  ldc.i4.s 0x27
  IL_03C4  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_03C9  ldsfld 0x4002140   ; Field:2140
  IL_03CE  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_03D3  ldloc 1
  IL_03D7  ldc.i4 0xcb5358e1
  IL_03DC  add
  IL_03DD  stloc 2
  IL_03E1  ldloc 1
  IL_03E5  ldc.i4 0x23b5d028
  IL_03EA  add
  IL_03EB  stloc 1
  IL_03EF  brfalse IL_0012
  IL_03F4  br IL_0200
  IL_03F9  ldarg.1
  IL_03FA  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_03FF  ldc.i4.5
  IL_0400  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_0405  ldsfld 0x4002140   ; Field:2140
  IL_040A  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_040F  ldloc 1
  IL_0413  ldc.i4 0xc0e92658
  IL_0418  add
  IL_0419  stloc 2
  IL_041D  ldloc 1
  IL_0421  ldc.i4 0x38148888
  IL_0426  add
  IL_0427  stloc 1
  IL_042B  brfalse IL_0012
  IL_0430  br IL_055b
  IL_0435  ldarg.1
  IL_0436  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_043B  ldc.i4 0xb1e6986d
  IL_0440  ldc.i4 0xdc35921a
  IL_0445  xor
  IL_0446  ldsfld 0x40020b8   ; Field:20B8
  IL_044B  ldfld 0x40020c7   ; Field:20C7
  IL_0450  xor
  IL_0451  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0456  ldsfld 0x4002140   ; Field:2140
  IL_045B  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_0460  ldc.i4 0x4
  IL_0465  stloc 2
  IL_0469  ldc.i4 0x6e082afa
  IL_046E  stloc 1
  IL_0472  brfalse IL_0012
  IL_0477  ldc.i4 0x9
  IL_047C  stloc 2
  IL_0480  ldc.i4 0x92cf600
  IL_0485  stloc 1
  IL_0489  br IL_0012
  IL_048E  ldc.i4 0xffb54807
  IL_0493  ldc.i4 0x92621ba4
  IL_0498  xor
  IL_0499  ldsfld 0x40020b8   ; Field:20B8
  IL_049E  ldfld 0x40020c7   ; Field:20C7
  IL_04A3  xor
  IL_04A4  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_04A9  stloc.s 0x0
  IL_04AB  ldloc 1
  IL_04AF  ldc.i4 0xc60c0f6d
  IL_04B4  add
  IL_04B5  stloc 2
  IL_04B9  ldloc 1
  IL_04BD  ldc.i4 0xd9492e20
  IL_04C2  add
  IL_04C3  stloc 1
  IL_04C7  br IL_0012
  IL_04CC  ldstr 0x70000001
  IL_04D1  stloc.s 0x0
  IL_04D3  ldc.i4 0xa
  IL_04D8  stloc 2
  IL_04DC  ldc.i4 0x3f16d9af
  IL_04E1  stloc 1
  IL_04E5  br IL_0012
  IL_04EA  nop
  IL_04EB  ldc.i4 0xb
  IL_04F0  stloc 2
  IL_04F4  ldc.i4 0x133d1ebe
  IL_04F9  stloc 1
  IL_04FD  br IL_0012
  IL_0502  ldarg.0
  IL_0503  ldloc.s 0x0
  IL_0505  call 0x6002f30   ; MethodDef:AggregateJoinedAdapter
  IL_050A  ret
  IL_050B  ldc.i4 0xfea8e036
  IL_0510  ldc.i4 0x2
  IL_0515  shl
  IL_0516  ldc.i4 0xf3734d13
  IL_051B  xor
  IL_051C  ldsfld 0x40020b8   ; Field:20B8
  IL_0521  ldfld 0x40020ad   ; Field:20AD
  IL_0526  xor
  IL_0527  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_052C  stloc.s 0x0
  IL_052E  br IL_024b
  IL_0533  ldc.i4 0xc106069b
  IL_0538  ldc.i4 0x5
  IL_053D  shr
  IL_053E  ldc.i4 0xd3f0e8ed
  IL_0543  xor
  IL_0544  ldsfld 0x40020b8   ; Field:20B8
  IL_0549  ldfld 0x400209f   ; Field:209F
  IL_054E  xor
  IL_054F  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0554  stloc.s 0x0
  IL_0556  br IL_057d
  IL_055B  ldc.i4 0xd8262bca
  IL_0560  ldc.i4 0xb154bdda
  IL_0565  xor
  IL_0566  ldsfld 0x40020b8   ; Field:20B8
  IL_056B  ldfld 0x40020ab   ; Field:20AB
  IL_0570  xor
  IL_0571  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0576  stloc.s 0x0
  IL_0578  br IL_04ea
  IL_057D  nop
  IL_057E  ldc.i4 0xb
  IL_0583  stloc 2
  IL_0587  ldc.i4 0x133d1ebe
  IL_058C  stloc 1
  IL_0590  br IL_0012
  IL_0595  ldarg.0
  IL_0596  ldc.i4 0xb4339f88
  IL_059B  neg
  IL_059C  ldc.i4 0x1953dd43
  IL_05A1  xor
  IL_05A2  ldsfld 0x40020b8   ; Field:20B8
  IL_05A7  ldfld 0x40020cd   ; Field:20CD
  IL_05AC  xor
  IL_05AD  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_05B2  call 0x6002f30   ; MethodDef:AggregateJoinedAdapter
  IL_05B7  ret
