# token=060004AA rva=01F760 name=RequestAdvancedCompressor source=dump_full grp=gfp
# vault: fat0=56 maxstack=00093013 locals=9 ticket=fe875d51 chunk=1dfe0e01 blocks=1
# {'ilsize': 847, 'maxstack': 9, 'eh': 0}
  IL_0000  ldc.i4 0x1d14b32b
  IL_0005  stloc 1
  IL_0009  ldc.i4 0x0
  IL_000E  stloc 2
  IL_0012  ldloc 2
  IL_0016  switch(9) 0x1f,0x28d,0x171,0x13d,0x2ba,0x3f,0x32c,0x246,0x26b
  IL_003F  nop
  IL_0040  ldarg.0
  IL_0041  call 0x60004a7   ; MethodDef:RequestGroupedReporter
  IL_0046  br IL_032b
  IL_004B  ldarg.0
  IL_004C  ldfld 0x40002ea   ; Field:02EA
  IL_0051  ldarg.0
  IL_0052  ldftn 100664496   ; MethodDef:SendInterruptibleResolver
  IL_0058  newobj 0xa000156   ; MemberRef:System.IO.FileSystemEventHandler::.ctor
  IL_005D  ldsfld 0x400221f   ; Field:221F
  IL_0062  call 0x6004a14   ; MethodDef:ExecuteExplorer
  IL_0067  ldloc 1
  IL_006B  ldc.i4 0xf6b6226e
  IL_0070  add
  IL_0071  stloc 2
  IL_0075  ldloc 1
  IL_0079  ldc.i4 0x4bcb86ca
  IL_007E  add
  IL_007F  stloc 1
  IL_0083  br IL_0012
  IL_0088  ldarg.0
  IL_0089  ldloc.s 0x4
  IL_008B  ldc.i4 0x5eb49204
  IL_0090  not
  IL_0091  ldc.i4 0x9d91200b
  IL_0096  xor
  IL_0097  ldsfld 0x40020b8   ; Field:20B8
  IL_009C  ldfld 0x40020b3   ; Field:20B3
  IL_00A1  xor
  IL_00A2  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_00A7  newobj 0xa000157   ; MemberRef:System.IO.FileSystemWatcher::.ctor
  IL_00AC  dup
  IL_00AD  ldc.i4.s 0x1d
  IL_00AF  ldsfld 0x400221c   ; Field:221C
  IL_00B4  call 0x6004a08   ; MethodDef:ExecuteExplorer
  IL_00B9  stfld 0x40002ea   ; Field:02EA
  IL_00BE  ldc.i4 0x7
  IL_00C3  stloc 2
  IL_00C7  ldc.i4 0x691ec25f
  IL_00CC  stloc 1
  IL_00D0  br IL_0012
  IL_00D5  ldc.i4 0x8e47f937
  IL_00DA  ldc.i4 0xf809982e
  IL_00DF  xor
  IL_00E0  ldsfld 0x40020b8   ; Field:20B8
  IL_00E5  ldfld 0x40020e8   ; Field:20E8
  IL_00EA  xor
  IL_00EB  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_00F0  br IL_0347
  IL_00F5  ldarg.0
  IL_00F6  ldfld 0x40002ea   ; Field:02EA
  IL_00FB  ldarg.0
  IL_00FC  ldftn 100664496   ; MethodDef:SendInterruptibleResolver
  IL_0102  newobj 0xa000156   ; MemberRef:System.IO.FileSystemEventHandler::.ctor
  IL_0107  ldsfld 0x400221e   ; Field:221E
  IL_010C  call 0x6004a10   ; MethodDef:ExecuteExplorer
  IL_0111  ldc.i4 0x5
  IL_0116  stloc 2
  IL_011A  ldc.i4 0x949dd95
  IL_011F  stloc 1
  IL_0123  br IL_0012
  IL_0128  ldarg.0
  IL_0129  ldloc.s 0x3
  IL_012B  callvirt 0x600046c   ; MethodDef:StoreSequentialContainer
  IL_0130  newobj 0xa000158   ; MemberRef:System.Diagnostics.Eventing.Reader.EventLogWatcher::.ctor
  IL_0135  stfld 0x40002eb   ; Field:02EB
  IL_013A  ldc.i4 0x1
  IL_013F  stloc 2
  IL_0143  ldc.i4 0x6e914eda
  IL_0148  stloc 1
  IL_014C  br IL_0012
  IL_0151  ldarg.0
  IL_0152  ldfld 0x40002ea   ; Field:02EA
  IL_0157  ldarg.0
  IL_0158  ldftn 100664496   ; MethodDef:SendInterruptibleResolver
  IL_015E  newobj 0xa000154   ; MemberRef:System.IO.RenamedEventHandler::.ctor
  IL_0163  ldsfld 0x4002220   ; Field:2220
  IL_0168  call 0x6004a18   ; MethodDef:ExecuteExplorer
  IL_016D  br IL_0333
  IL_0172  ldloc.s 0x3
  IL_0174  callvirt 0x600046c   ; MethodDef:StoreSequentialContainer
  IL_0179  ldc.i4.0
  IL_017A  ldsfld 0x4002200   ; Field:2200
  IL_017F  call 0x6004998   ; MethodDef:ExecuteExplorer
  IL_0184  br IL_0128
  IL_0189  call 0x600049d   ; MethodDef:ReceiveBasicConsumer
  IL_018E  ldloc 1
  IL_0192  ldc.i4 0xde080f22
  IL_0197  add
  IL_0198  stloc 2
  IL_019C  ldloc 1
  IL_01A0  ldc.i4 0x4b391f3e
  IL_01A5  add
  IL_01A6  stloc 1
  IL_01AA  brfalse IL_0012
  IL_01AF  ldloc 1
  IL_01B3  ldc.i4 0x92ceefe6
  IL_01B8  add
  IL_01B9  stloc 2
  IL_01BD  ldloc 1
  IL_01C1  ldc.i4 0xaaa7cdda
  IL_01C6  add
  IL_01C7  stloc 1
  IL_01CB  br IL_0012
  IL_01D0  ldloc.s 0x5
  IL_01D2  ldsfld 0x400221a   ; Field:221A
  IL_01D7  call 0x6004a00   ; MethodDef:ExecuteExplorer
  IL_01DC  ldsfld 0x400221b   ; Field:221B
  IL_01E1  call 0x6004a04   ; MethodDef:ExecuteExplorer
  IL_01E6  ldc.i4 0x38b09bdf
  IL_01EB  not
  IL_01EC  ldc.i4 0xd9b989ba
  IL_01F1  xor
  IL_01F2  ldsfld 0x40020b8   ; Field:20B8
  IL_01F7  ldfld 0x40020c5   ; Field:20C5
  IL_01FC  xor
  IL_01FD  call 0x6004196   ; MethodDef:InstantiateTransferableProgram
  IL_0202  ldsfld 0x4002219   ; Field:2219
  IL_0207  call 0x60049fc   ; MethodDef:ExecuteExplorer
  IL_020C  br IL_0347
  IL_0211  ldarg.0
  IL_0212  call 0x600048b   ; MethodDef:SendEditableValidator
  IL_0217  callvirt 0x60004bc   ; MethodDef:SendTransformableConfig
  IL_021C  ldc.i4 0x2
  IL_0221  stloc 2
  IL_0225  ldc.i4 0x21f7f0e2
  IL_022A  stloc 1
  IL_022E  brtrue IL_0012
  IL_0233  ldc.i4 0x8
  IL_0238  stloc 2
  IL_023C  ldc.i4 0xcdd6847
  IL_0241  stloc 1
  IL_0245  br IL_0012
  IL_024A  ldarg.0
  IL_024B  ldfld 0x40002ea   ; Field:02EA
  IL_0250  ldarg.0
  IL_0251  ldftn 100664496   ; MethodDef:SendInterruptibleResolver
  IL_0257  newobj 0xa000156   ; MemberRef:System.IO.FileSystemEventHandler::.ctor
  IL_025C  ldsfld 0x400221d   ; Field:221D
  IL_0261  call 0x6004a0c   ; MethodDef:ExecuteExplorer
  IL_0266  br IL_00f5
  IL_026B  ldarg.0
  IL_026C  ldfld 0x40002e4   ; Field:02E4
  IL_0271  ldarg.0
  IL_0272  call 0x600048b   ; MethodDef:SendEditableValidator
  IL_0277  callvirt 0x60004ba   ; MethodDef:SendCombinedContext
  IL_027C  ldsfld 0x4002219   ; Field:2219
  IL_0281  call 0x60049fc   ; MethodDef:ExecuteExplorer
  IL_0286  stloc.s 0x0
  IL_0288  ldloc 1
  IL_028C  ldc.i4 0xf32297bb
  IL_0291  add
  IL_0292  stloc 2
  IL_0296  ldloc 1
  IL_029A  ldc.i4 0x151a889b
  IL_029F  add
  IL_02A0  stloc 1
  IL_02A4  br IL_0012
  IL_02A9  ldarg.0
  IL_02AA  ldfld 0x40002eb   ; Field:02EB
  IL_02AF  ldarg.0
  IL_02B0  ldftn 100664497   ; MethodDef:SendStaticSynchronizer
  IL_02B6  newobj 0xa000155   ; MemberRef:mrp_tag4#102::.ctor
  IL_02BB  ldsfld 0x4002221   ; Field:2221
  IL_02C0  call 0x6004a1c   ; MethodDef:ExecuteExplorer
  IL_02C5  br IL_034e
  IL_02CA  ldloc.s 0x0
  IL_02CC  ldarg.0
  IL_02CD  call 0x600048b   ; MethodDef:SendEditableValidator
  IL_02D2  callvirt 0x60004b6   ; MethodDef:RequestBasicEngine
  IL_02D7  ldarg.0
  IL_02D8  call 0x600048b   ; MethodDef:SendEditableValidator
  IL_02DD  callvirt 0x60004b8   ; MethodDef:ClearGeneralTokenizer
  IL_02E2  ldsfld 0x40021a0   ; Field:21A0
  IL_02E7  call 0x6004818   ; MethodDef:ExecuteExplorer
  IL_02EC  newobj 0xa000144   ; MemberRef:mrp_tag4#71::.ctor
  IL_02F1  ldarg.0
  IL_02F2  call 0x6000492   ; MethodDef:RequestScopeController
  IL_02F7  ldarg.0
  IL_02F8  call 0x6000496   ; MethodDef:RequestPortableStruct
  IL_02FD  ldarg.0
  IL_02FE  call 0x6000498   ; MethodDef:LeadStruct
  IL_0303  ldarg.0
  IL_0304  call 0x600049a   ; MethodDef:RequestCustomSystem
  IL_0309  newobj 0x6000461   ; MethodDef:.ctor
  IL_030E  stloc.s 0x3
  IL_0310  br IL_0172
  IL_0315  ldloc.s 0x5
  IL_0317  ldsfld 0x400221a   ; Field:221A
  IL_031C  call 0x6004a00   ; MethodDef:ExecuteExplorer
  IL_0321  brtrue IL_01d0
  IL_0326  br IL_00d5
  IL_032B  ldnull
  IL_032C  stloc.s 0x0
  IL_032E  br IL_0211
  IL_0333  ret
  IL_0334  ldc.i4.s 0x25
  IL_0336  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_033B  newobj 0xa00015a   ; MemberRef:System.IO.DirectoryInfo::.ctor
  IL_0340  stloc.s 0x5
  IL_0342  br IL_0315
  IL_0347  stloc.s 0x4
  IL_0349  br IL_0088
  IL_034E  ret
