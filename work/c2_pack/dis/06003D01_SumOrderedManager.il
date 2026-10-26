# token=06003D01 rva=359170 name=SumOrderedManager source=dump_full grp=gfp
# {'ilsize': 2076, 'maxstack': 5, 'eh': 2}
# EH clauses (60 bytes):
#   flags=2 try=[0002+0407) handler=[0101+0508) classOrFilter=00000013 pad=00000000
#   flags=0 try=[0002+01D3) handler=[0168+033B) classOrFilter=0000008C pad=00000000
  IL_0000  ldc.i4 0x54d765a4
  IL_0005  stloc 8
  IL_0009  ldc.i4 0xd
  IL_000E  stloc 14
  IL_0012  ldloc 14
  IL_0016  switch(21) 0x630,0x730,0x6a2,0x54a,0xf4,0x6d8,0x7b6,0x70e,0x60d,0x15f,0x666,0xd8,0x74b,0x53,0x52b,0x5fc,0x6d2,0x7ad,0x5ce,0x6c2,0xde
  IL_006F  nop
  IL_0070  ldc.i4.1
  IL_0071  stloc.s 0x0
  IL_0073  br IL_06a5
  IL_0078  ldarg.0
  IL_0079  ldarg.1
  IL_007A  unk50
  IL_007B  stfld 0x4001bf7   ; Field:1BF7
  IL_0080  ldc.i4 0x14
  IL_0085  stloc 14
  IL_0089  ldc.i4 0x20406c7c
  IL_008E  stloc 8
  IL_0092  br IL_0012
  IL_0097  ldarg.0
  IL_0098  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_009D  ldc.i4 0xcc121a1d
  IL_00A2  ldc.i4 0x94827c6b
  IL_00A7  xor
  IL_00A8  ldsfld 0x40020b8   ; Field:20B8
  IL_00AD  ldfld 0x40020c1   ; Field:20C1
  IL_00B2  xor
  IL_00B3  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_00B8  ldsfld 0x4002140   ; Field:2140
  IL_00BD  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_00C2  ldc.i4 0x4
  IL_00C7  stloc 14
  IL_00CB  ldc.i4 0x1162e579
  IL_00D0  stloc 8
  IL_00D4  brfalse IL_0012
  IL_00D9  br IL_00eb
  IL_00DE  ldc.i4.0
  IL_00DF  stloc.s 0x0
  IL_00E1  br IL_07e4
  IL_00E6  br IL_0819
  IL_00EB  call 0x6003023   ; MethodDef:RequestLiteralModule
  IL_00F0  callvirt 0xa000301   ; MemberRef:mrp_tag4#36::GetEnumerator
  IL_00F5  stloc.s 0xb
  IL_00F7  br IL_0407
  IL_00FC  ldarg.1
  IL_00FD  unk50
  IL_00FE  ldloc.s 0x4
  IL_0100  callvirt 0xa000758   ; MemberRef:mrp_tag4#548::Add
  IL_0105  ldloc 8
  IL_0109  ldc.i4 0x83240e2d
  IL_010E  add
  IL_010F  stloc 14
  IL_0113  ldloc 8
  IL_0117  ldc.i4 0xcf5da97d
  IL_011C  add
  IL_011D  stloc 8
  IL_0121  br IL_0012
  IL_0126  ldc.i4.5
  IL_0127  ldarg.0
  IL_0128  newobj 0x6003cff   ; MethodDef:.ctor
  IL_012D  stloc.s 0x1
  IL_012F  br IL_051b
  IL_0134  ldarg.0
  IL_0135  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_013A  ldc.i4 0x4ac3315e
  IL_013F  ldc.i4 0x3
  IL_0144  shl
  IL_0145  ldc.i4 0x3f6b3a66
  IL_014A  xor
  IL_014B  ldsfld 0x40020b8   ; Field:20B8
  IL_0150  ldfld 0x40020ab   ; Field:20AB
  IL_0155  xor
  IL_0156  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_015B  ldsfld 0x4002230   ; Field:2230
  IL_0160  call 0x6004a58   ; MethodDef:ExecuteExplorer
  IL_0165  brfalse IL_0819
  IL_016A  ldloc 8
  IL_016E  ldc.i4 0xee9d1a9a
  IL_0173  add
  IL_0174  stloc 14
  IL_0178  ldloc 8
  IL_017C  ldc.i4 0x6072d973
  IL_0181  add
  IL_0182  stloc 8
  IL_0186  br IL_0012
  IL_018B  ldloc.s 0x13
  IL_018D  ldloc.s 0x7
  IL_018F  ldlen
  IL_0190  conv.i4
  IL_0191  ldloc 8
  IL_0195  ldc.i4 0xa9042a1f
  IL_019A  add
  IL_019B  stloc 14
  IL_019F  ldloc 8
  IL_01A3  ldc.i4 0xd9a77e9d
  IL_01A8  add
  IL_01A9  stloc 8
  IL_01AD  blt IL_0012
  IL_01B2  ldloc 8
  IL_01B6  ldc.i4 0xcf5cab83
  IL_01BB  add
  IL_01BC  stloc 14
  IL_01C0  ldloc 8
  IL_01C4  ldc.i4 0xed263f37
  IL_01C9  add
  IL_01CA  stloc 8
  IL_01CE  br IL_0012
  IL_01D3  ldc.i4 0x5345bd6
  IL_01D8  stloc 8
  IL_01DC  ldc.i4 0x0
  IL_01E1  stloc 14
  IL_01E5  ldloc 14
  IL_01E9  switch(4) 0x1f2,0x2a2,0x308,0x294
  IL_01FE  nop
  IL_01FF  nop
  IL_0200  ldc.i4 0x3
  IL_0205  stloc 14
  IL_0209  ldc.i4 0xf235d5f
  IL_020E  stloc 8
  IL_0212  br IL_01e5
  IL_0217  ldloc.s 0xf
  IL_0219  callvirt 0x6002ff5   ; MethodDef:AlignConvertibleTracer
  IL_021E  ldsfld 0x400221b   ; Field:221B
  IL_0223  call 0x6004a04   ; MethodDef:ExecuteExplorer
  IL_0228  ldarg.0
  IL_0229  newobj 0x6003cfe   ; MethodDef:.ctor
  IL_022E  stloc.s 0x10
  IL_0230  ldc.i4 0x2
  IL_0235  stloc 14
  IL_0239  ldc.i4 0x205bf27
  IL_023E  stloc 8
  IL_0242  br IL_01e5
  IL_0247  ldloc.s 0xf
  IL_0249  callvirt 0x6002ff2   ; MethodDef:ProcessSymbolicThread
  IL_024E  ldc.i4 0x3
  IL_0253  stloc 14
  IL_0257  ldc.i4 0xf235d5f
  IL_025C  stloc 8
  IL_0260  brtrue IL_01e5
  IL_0265  ldc.i4 0x1
  IL_026A  stloc 14
  IL_026E  ldc.i4 0x7a13298
  IL_0273  stloc 8
  IL_0277  br IL_01e5
  IL_027C  ldloc.s 0x12
  IL_027E  ldsfld 0x400217e   ; Field:217E
  IL_0283  call 0x6004790   ; MethodDef:ExecuteExplorer
  IL_0288  castclass 0x2000476   ; TypeDef#1142
  IL_028D  stloc.s 0xf
  IL_028F  br IL_0247
  IL_0294  ldloc.s 0x12
  IL_0296  ldsfld 0x4002172   ; Field:2172
  IL_029B  call 0x6004760   ; MethodDef:ExecuteExplorer
  IL_02A0  brtrue IL_027c
  IL_02A5  br IL_0336
  IL_02AA  ldloc.s 0xf
  IL_02AC  callvirt 0x6002ff5   ; MethodDef:AlignConvertibleTracer
  IL_02B1  ldsfld 0x400221b   ; Field:221B
  IL_02B6  call 0x6004a04   ; MethodDef:ExecuteExplorer
  IL_02BB  ldc.i4 0x99ad3746
  IL_02C0  ldc.i4 0x12ef99bc
  IL_02C5  sub
  IL_02C6  ldc.i4 0x985d504c
  IL_02CB  xor
  IL_02CC  ldsfld 0x40020b8   ; Field:20B8
  IL_02D1  ldfld 0x4002089   ; Field:2089
  IL_02D6  xor
  IL_02D7  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_02DC  ldsfld 0x400215d   ; Field:215D
  IL_02E1  call 0x600470c   ; MethodDef:ExecuteExplorer
  IL_02E6  ldloc 8
  IL_02EA  ldc.i4 0xf85ecd6b
  IL_02EF  add
  IL_02F0  stloc 14
  IL_02F4  ldloc 8
  IL_02F8  ldc.i4 0x7822ac7
  IL_02FD  add
  IL_02FE  stloc 8
  IL_0302  brtrue IL_01e5
  IL_0307  br IL_0217
  IL_030C  ldarg.1
  IL_030D  unk50
  IL_030E  ldloc.s 0x10
  IL_0310  callvirt 0xa000758   ; MemberRef:mrp_tag4#548::Add
  IL_0315  ldloc 8
  IL_0319  ldc.i4 0xfdfa40dc
  IL_031E  add
  IL_031F  stloc 14
  IL_0323  ldloc 8
  IL_0327  ldc.i4 0xd1d9e38
  IL_032C  add
  IL_032D  stloc 8
  IL_0331  br IL_01e5
  IL_0336  leave IL_03c7
  IL_033B  ldc.i4 0xd5272e8
  IL_0340  stloc 8
  IL_0344  ldc.i4 0x1
  IL_0349  stloc 14
  IL_034D  ldloc 14
  IL_0351  switch(3) 0x3ad,0x35e,0x38d
  IL_0362  nop
  IL_0363  ldloc.s 0x12
  IL_0365  isinst 0x1000062   ; TypeRef:System.IDisposable
  IL_036A  stloc.s 0x11
  IL_036C  ldloc 8
  IL_0370  ldc.i4 0xf2ad8d1a
  IL_0375  add
  IL_0376  stloc 14
  IL_037A  ldloc 8
  IL_037E  ldc.i4 0x13c8fc5d
  IL_0383  add
  IL_0384  stloc 8
  IL_0388  br IL_034d
  IL_038D  ldloc.s 0x11
  IL_038F  brfalse IL_03c6
  IL_0394  ldloc 8
  IL_0398  ldc.i4 0xdee490bb
  IL_039D  add
  IL_039E  stloc 14
  IL_03A2  ldloc 8
  IL_03A6  ldc.i4 0x107d5fbf
  IL_03AB  add
  IL_03AC  stloc 8
  IL_03B0  br IL_034d
  IL_03B5  ldloc.s 0x11
  IL_03B7  ldsfld 0x4002109   ; Field:2109
  IL_03BC  call 0x60045bc   ; MethodDef:ExecuteExplorer
  IL_03C1  br IL_03c6
  IL_03C6  endfinally
  IL_03C7  ldarg.0
  IL_03C8  ldarg.1
  IL_03C9  unk50
  IL_03CA  stfld 0x4001bf7   ; Field:1BF7
  IL_03CF  ldc.i4 0xa
  IL_03D4  stloc 14
  IL_03D8  ldc.i4 0x56a2275a
  IL_03DD  stloc 8
  IL_03E1  br IL_0012
  IL_03E6  ldc.i4.s 0x11
  IL_03E8  ldarg.0
  IL_03E9  newobj 0x6003cff   ; MethodDef:.ctor
  IL_03EE  stloc.s 0x4
  IL_03F0  ldc.i4 0xb
  IL_03F5  stloc 14
  IL_03F9  ldc.i4 0x7cdbf1d9
  IL_03FE  stloc 8
  IL_0402  br IL_0012
  IL_0407  ldc.i4 0x1c31566c
  IL_040C  stloc 8
  IL_0410  ldc.i4 0x0
  IL_0415  stloc 14
  IL_0419  ldloc 14
  IL_041D  switch(4) 0x426,0x443,0x4cb,0x475
  IL_0432  nop
  IL_0433  nop
  IL_0434  ldc.i4 0x3
  IL_0439  stloc 14
  IL_043D  ldc.i4 0x84d557b
  IL_0442  stloc 8
  IL_0446  br IL_0419
  IL_044B  ldloca.s 0xb
  IL_044D  call 0xa000302   ; MemberRef:mrp_tag4#228::get_Current
  IL_0452  stloc.s 0xc
  IL_0454  ldloc 8
  IL_0458  ldc.i4 0xdc2fc234
  IL_045D  add
  IL_045E  stloc 14
  IL_0462  ldloc 8
  IL_0466  ldc.i4 0x3fe418d
  IL_046B  add
  IL_046C  stloc 8
  IL_0470  br IL_0419
  IL_0475  ldloca.s 0xb
  IL_0477  call 0xa000303   ; MemberRef:mrp_tag4#228::MoveNext
  IL_047C  ldloc 8
  IL_0480  ldc.i4 0xf7b2aa86
  IL_0485  add
  IL_0486  stloc 14
  IL_048A  ldloc 8
  IL_048E  ldc.i4 0x1b82e853
  IL_0493  add
  IL_0494  stloc 8
  IL_0498  brtrue IL_0419
  IL_049D  br IL_0503
  IL_04A2  ldloc.s 0xd
  IL_04A4  ldc.i4.1
  IL_04A5  callvirt 0x6003d1d   ; MethodDef:CountControllableTransmitter
  IL_04AA  br IL_04af
  IL_04AF  ldarg.1
  IL_04B0  unk50
  IL_04B1  ldloc.s 0xd
  IL_04B3  callvirt 0xa000758   ; MemberRef:mrp_tag4#548::Add
  IL_04B8  ldc.i4 0x3
  IL_04BD  stloc 14
  IL_04C1  ldc.i4 0x84d557b
  IL_04C6  stloc 8
  IL_04CA  br IL_0419
  IL_04CF  ldc.i4 0x350acef
  IL_04D4  ldc.i4 0x8f9bbc2
  IL_04D9  xor
  IL_04DA  ldsfld 0x40020b8   ; Field:20B8
  IL_04DF  ldfld 0x40020e4   ; Field:20E4
  IL_04E4  xor
  IL_04E5  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_04EA  ldloc.s 0xc
  IL_04EC  ldsfld 0x4002160   ; Field:2160
  IL_04F1  call 0x6004718   ; MethodDef:ExecuteExplorer
  IL_04F6  ldarg.0
  IL_04F7  newobj 0x6003cfe   ; MethodDef:.ctor
  IL_04FC  stloc.s 0xd
  IL_04FE  br IL_04a2
  IL_0503  leave IL_0078
  IL_0508  ldloca.s 0xb
  IL_050A  constrained. 452985060   ; TypeSpec
  IL_0510  callvirt 0xa00008f   ; MemberRef:System.IDisposable::Dispose
  IL_0515  br IL_051a
  IL_051A  endfinally
  IL_051B  ldarg.1
  IL_051C  unk50
  IL_051D  ldloc.s 0x1
  IL_051F  callvirt 0xa000758   ; MemberRef:mrp_tag4#548::Add
  IL_0524  ldc.i4 0x8
  IL_0529  stloc 14
  IL_052D  ldc.i4 0x2b817dd8
  IL_0532  stloc 8
  IL_0536  br IL_0012
  IL_053B  ldc.i4.0
  IL_053C  stloc.s 0x13
  IL_053E  br IL_0668
  IL_0543  ldsfld 0x4002207   ; Field:2207
  IL_0548  call 0x60049b4   ; MethodDef:ExecuteExplorer
  IL_054D  ldsfld 0x4002208   ; Field:2208
  IL_0552  call 0x60049b8   ; MethodDef:ExecuteExplorer
  IL_0557  ldsfld 0x4002209   ; Field:2209
  IL_055C  call 0x60049bc   ; MethodDef:ExecuteExplorer
  IL_0561  ldc.i4.6
  IL_0562  blt IL_0819
  IL_0567  br IL_0696
  IL_056C  ldarg.0
  IL_056D  newobj 0xa00075a   ; MemberRef:mrp_tag4#548::.ctor
  IL_0572  stfld 0x4001bf7   ; Field:1BF7
  IL_0577  ldc.i4 0xc
  IL_057C  stloc 14
  IL_0580  ldc.i4 0x5c1e396e
  IL_0585  stloc 8
  IL_0589  br IL_0012
  IL_058E  ldloc.s 0x13
  IL_0590  ldc.i4.1
  IL_0591  add
  IL_0592  stloc.s 0x13
  IL_0594  ldloc 8
  IL_0598  ldc.i4 0xb19a1737
  IL_059D  add
  IL_059E  stloc 14
  IL_05A2  ldloc 8
  IL_05A6  ldc.i4 0x895ed1e
  IL_05AB  add
  IL_05AC  stloc 8
  IL_05B0  br IL_0012
  IL_05B5  ldarg.0
  IL_05B6  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_05BB  ldc.i4.s 0x11
  IL_05BD  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_05C2  ldsfld 0x4002140   ; Field:2140
  IL_05C7  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_05CC  brfalse IL_0097
  IL_05D1  br IL_056c
  IL_05D6  ldarg.1
  IL_05D7  unk50
  IL_05D8  ldloc.s 0x5
  IL_05DA  callvirt 0xa000758   ; MemberRef:mrp_tag4#548::Add
  IL_05DF  ldloc 8
  IL_05E3  ldc.i4 0xa43fab04
  IL_05E8  add
  IL_05E9  stloc 14
  IL_05ED  ldloc 8
  IL_05F1  ldc.i4 0xb83708b1
  IL_05F6  add
  IL_05F7  stloc 8
  IL_05FB  br IL_0012
  IL_0600  ldarg.0
  IL_0601  newobj 0xa00075a   ; MemberRef:mrp_tag4#548::.ctor
  IL_0606  stfld 0x4001bf7   ; Field:1BF7
  IL_060B  br IL_0126
  IL_0610  ldloc.s 0x7
  IL_0612  ldloc.s 0x13
  IL_0614  ldelem.ref
  IL_0615  stloc.s 0x9
  IL_0617  br IL_061c
  IL_061C  ldloc.s 0x9
  IL_061E  ldarg.0
  IL_061F  newobj 0x6003cfe   ; MethodDef:.ctor
  IL_0624  stloc.s 0xa
  IL_0626  ldc.i4 0x1
  IL_062B  stloc 14
  IL_062F  ldc.i4 0x7261a7a
  IL_0634  stloc 8
  IL_0638  br IL_0012
  IL_063D  ldc.i4.s 0x27
  IL_063F  ldarg.0
  IL_0640  newobj 0x6003cff   ; MethodDef:.ctor
  IL_0645  stloc.s 0x2
  IL_0647  ldloc 8
  IL_064B  ldc.i4 0xd47e822a
  IL_0650  add
  IL_0651  stloc 14
  IL_0655  ldloc 8
  IL_0659  ldc.i4 0x3ad0190e
  IL_065E  add
  IL_065F  stloc 8
  IL_0663  br IL_0012
  IL_0668  nop
  IL_0669  ldc.i4 0x9
  IL_066E  stloc 14
  IL_0672  ldc.i4 0x56fbd5f0
  IL_0677  stloc 8
  IL_067B  br IL_0012
  IL_0680  ldarg.1
  IL_0681  unk50
  IL_0682  ldloc.s 0x3
  IL_0684  callvirt 0xa000758   ; MemberRef:mrp_tag4#548::Add
  IL_0689  br IL_03e6
  IL_068E  ldc.i4.0
  IL_068F  stloc.s 0x0
  IL_0691  br IL_0819
  IL_0696  ldc.i4.s 0x63
  IL_0698  ldarg.0
  IL_0699  newobj 0x6003cff   ; MethodDef:.ctor
  IL_069E  stloc.s 0x6
  IL_06A0  br IL_07ab
  IL_06A5  ldarg.0
  IL_06A6  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_06AB  ldc.i4.s 0x10
  IL_06AD  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_06B2  ldsfld 0x4002140   ; Field:2140
  IL_06B7  call 0x6004698   ; MethodDef:ExecuteExplorer
  IL_06BC  brfalse IL_05b5
  IL_06C1  br IL_0600
  IL_06C6  ldarg.0
  IL_06C7  callvirt 0x6003bb4   ; MethodDef:OpenResponsiveNotifier
  IL_06CC  call 0x600300a   ; MethodDef:DefineModule
  IL_06D1  ldsfld 0x40028fa   ; Field:28FA
  IL_06D6  call 0x6006580   ; MethodDef:ExecuteExplorer
  IL_06DB  stloc.s 0x12
  IL_06DD  br IL_01d3
  IL_06E2  ldc.i4.0
  IL_06E3  stloc.s 0x0
  IL_06E5  br IL_07e9
  IL_06EA  ldarg.1
  IL_06EB  unk50
  IL_06EC  ldloc.s 0x2
  IL_06EE  callvirt 0xa000758   ; MemberRef:mrp_tag4#548::Add
  IL_06F3  ldloc 8
  IL_06F7  ldc.i4 0x99ae692b
  IL_06FC  add
  IL_06FD  stloc 14
  IL_0701  ldloc 8
  IL_0705  ldc.i4 0xbf4c2c9
  IL_070A  add
  IL_070B  stloc 8
  IL_070F  br IL_0012
  IL_0714  ldarg.0
  IL_0715  ldfld 0x4001bf7   ; Field:1BF7
  IL_071A  ldloc.s 0xa
  IL_071C  callvirt 0xa000758   ; MemberRef:mrp_tag4#548::Add
  IL_0721  ldloc 8
  IL_0725  ldc.i4 0xd9b484ea
  IL_072A  add
  IL_072B  stloc 14
  IL_072F  ldloc 8
  IL_0733  ldc.i4 0x281a6db9
  IL_0738  add
  IL_0739  stloc 8
  IL_073D  br IL_0012
  IL_0742  ldloc.s 0xa
  IL_0744  ldc.i4.1
  IL_0745  callvirt 0x6003d1d   ; MethodDef:CountControllableTransmitter
  IL_074A  ldloc 8
  IL_074E  ldc.i4 0xd20f0a80
  IL_0753  add
  IL_0754  stloc 14
  IL_0758  ldloc 8
  IL_075C  ldc.i4 0xf85a8594
  IL_0761  add
  IL_0762  stloc 8
  IL_0766  br IL_0012
  IL_076B  ldsfld 0x4002c28   ; Field:2C28
  IL_0770  call 0x6007238   ; MethodDef:ExecuteExplorer
  IL_0775  stloc.s 0x7
  IL_0777  br IL_053b
  IL_077C  ldloc.s 0xa
  IL_077E  ldloc.s 0x9
  IL_0780  call 0x6002faf   ; MethodDef:ModelAdaptableSolver
  IL_0785  callvirt 0x6003bad   ; MethodDef:ParseHiddenTokenizer
  IL_078A  ldloc 8
  IL_078E  ldc.i4 0xf8d9e58d
  IL_0793  add
  IL_0794  stloc 14
  IL_0798  ldloc 8
  IL_079C  ldc.i4 0x26cadb0b
  IL_07A1  add
  IL_07A2  stloc 8
  IL_07A6  br IL_0012
  IL_07AB  ldarg.1
  IL_07AC  unk50
  IL_07AD  ldloc.s 0x6
  IL_07AF  callvirt 0xa000758   ; MemberRef:mrp_tag4#548::Add
  IL_07B4  br IL_00e6
  IL_07B9  ldc.i4.s 0xd
  IL_07BB  ldarg.0
  IL_07BC  newobj 0x6003cff   ; MethodDef:.ctor
  IL_07C1  stloc.s 0x3
  IL_07C3  ldloc 8
  IL_07C7  ldc.i4 0x8db9a651
  IL_07CC  add
  IL_07CD  stloc 14
  IL_07D1  ldloc 8
  IL_07D5  ldc.i4 0xab01fa82
  IL_07DA  add
  IL_07DB  stloc 8
  IL_07DF  br IL_0012
  IL_07E4  br IL_0819
  IL_07E9  br IL_0819
  IL_07EE  ldc.i4.s 0x12
  IL_07F0  ldarg.0
  IL_07F1  newobj 0x6003cff   ; MethodDef:.ctor
  IL_07F6  stloc.s 0x5
  IL_07F8  ldloc 8
  IL_07FC  ldc.i4 0xb3c664bc
  IL_0801  add
  IL_0802  stloc 14
  IL_0806  ldloc 8
  IL_080A  ldc.i4 0xf86b9b4
  IL_080F  add
  IL_0810  stloc 8
  IL_0814  br IL_0012
  IL_0819  ldloc.s 0x0
  IL_081B  ret
