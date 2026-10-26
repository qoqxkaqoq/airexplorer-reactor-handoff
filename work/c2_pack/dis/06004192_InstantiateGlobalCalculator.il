# token=06004192 rva=3FAFD0 name=InstantiateGlobalCalculator source=dump_full grp=validator
# {'ilsize': 8970, 'maxstack': 7, 'eh': 4}
# EH clauses (116 bytes):
#   flags=4 try=[0000+0A9B) handler=[00AB+0B46) classOrFilter=0000000B pad=0200003D
#   flags=0 try=[0000+0BE0) handler=[16A3+2283) classOrFilter=00000026 pad=0200003D
#   flags=0 try=[0000+00FB) handler=[0894+098F) classOrFilter=00000026 pad=0200003D
#   flags=0 try=[0000+0B51) handler=[0070+0BC1) classOrFilter=0000001E pad=0200003D
  IL_0000  ldc.i4 0x68537b95
  IL_0005  stloc 0
  IL_0009  ldc.i4 0x8
  IL_000E  stloc 31
  IL_0012  ldloc 31
  IL_0016  switch(14) 0x22cd,0xa3,0x227d,0x57,0x991,0xa1e,0xa1c,0x97,0x3f,0x9e4,0x9e0,0x22cc,0xa66,0x87
  IL_0053  nop
  IL_0054  ldsfld 0x4001fcd   ; Field:1FCD
  IL_0059  brtrue IL_2309
  IL_005E  ldloc 0
  IL_0062  ldc.i4 0x97ac8470
  IL_0067  add
  IL_0068  stloc 31
  IL_006C  ldloc 0
  IL_0070  ldc.i4 0xec3bd359
  IL_0075  add
  IL_0076  stloc 0
  IL_007A  br IL_0012
  IL_007F  ldnull
  IL_0080  stloc.s 0x17
  IL_0082  br IL_0a9b
  IL_0087  ldloc.s 0x2
  IL_0089  brfalse IL_0bdf
  IL_008E  ldloc 0
  IL_0092  ldc.i4 0x942e134a
  IL_0097  add
  IL_0098  stloc 31
  IL_009C  ldloc 0
  IL_00A0  ldc.i4 0xd7746077
  IL_00A5  add
  IL_00A6  stloc 0
  IL_00AA  br IL_0012
  IL_00AF  ldnull
  IL_00B0  stloc.s 0xd
  IL_00B2  ldloc 0
  IL_00B6  ldc.i4 0x9f845472
  IL_00BB  add
  IL_00BC  stloc 31
  IL_00C0  ldloc 0
  IL_00C4  ldc.i4 0xbeb68f7
  IL_00C9  add
  IL_00CA  stloc 0
  IL_00CE  br IL_0012
  IL_00D3  ldloc.s 0xc
  IL_00D5  ldloc 0
  IL_00D9  ldc.i4 0xd05af02c
  IL_00DE  add
  IL_00DF  stloc 31
  IL_00E3  ldloc 0
  IL_00E7  ldc.i4 0x4f47852b
  IL_00EC  add
  IL_00ED  stloc 0
  IL_00F1  brfalse IL_0012
  IL_00F6  br IL_0a72
  IL_00FB  ldc.i4 0x2b3bb0aa
  IL_0100  stloc 0
  IL_0104  ldc.i4 0x15
  IL_0109  stloc 31
  IL_010D  ldloc 31
  IL_0111  switch(36) 0x5a8,0x52e,0x63e,0x7c1,0x44f,0x16b,0x2c2,0x72c,0x3c2,0x6ee,0x234,0x674,0x532,0x7bf,0x180,0x317,0x40b,0x6a2,0x1de,0x36c,0x78e,0x16e,0x5d6,0x46d,0x4be,0x4eb,0x524,0x3c8,0x2d4,0x666,0x2ca,0x3c3,0x247,0x726,0x5dc,0x65e
  IL_01A6  nop
  IL_01A7  ldloc.s 0x2
  IL_01A9  ldc.i4.3
  IL_01AA  ldc.i4.1
  IL_01AB  ldc.i4.1
  IL_01AC  newobj 0xa000518   ; MemberRef:System.IO.FileStream::.ctor
  IL_01B1  stloc.s 0x14
  IL_01B3  ldloc 0
  IL_01B7  ldc.i4 0xd4c44f56
  IL_01BC  add
  IL_01BD  stloc 31
  IL_01C1  ldloc 0
  IL_01C5  ldc.i4 0x216c4a08
  IL_01CA  add
  IL_01CB  stloc 0
  IL_01CF  br IL_010d
  IL_01D4  ldloc.s 0x14
  IL_01D6  ldloc.s 0x20
  IL_01D8  conv.u8
  IL_01D9  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_01DE  br IL_06aa
  IL_01E3  ldloc.s 0x1a
  IL_01E5  call 0x60041e7   ; MethodDef:CheckIdentifiableConfig
  IL_01EA  ldloc.s 0x1a
  IL_01EC  call 0x60041e7   ; MethodDef:CheckIdentifiableConfig
  IL_01F1  stloc.s 0xa
  IL_01F3  ldloc.s 0x8
  IL_01F5  ldloc.s 0x3
  IL_01F7  ldloc.s 0x1a
  IL_01F9  call 0x60041e8   ; MethodDef:ParseComparator
  IL_01FE  conv.u8
  IL_01FF  stloc.s 0x1b
  IL_0201  ldloc 0
  IL_0205  ldc.i4 0x8cf9bdde
  IL_020A  add
  IL_020B  stloc 31
  IL_020F  ldloc 0
  IL_0213  ldc.i4 0xb2b905fb
  IL_0218  add
  IL_0219  stloc 0
  IL_021D  br IL_010d
  IL_0222  ldloc.s 0xd
  IL_0224  ldc.i4.0
  IL_0225  newarr 0x100005b   ; TypeRef:System.Byte
  IL_022A  ldc.i4.0
  IL_022B  ldc.i4.0
  IL_022C  call 0x60041ea   ; MethodDef:CheckScalableTransmitter
  IL_0231  pop
  IL_0232  ldloc 0
  IL_0236  ldc.i4 0xb900b2c2
  IL_023B  add
  IL_023C  stloc 31
  IL_0240  ldloc 0
  IL_0244  ldc.i4 0x33bde75d
  IL_0249  add
  IL_024A  stloc 0
  IL_024E  br IL_010d
  IL_0253  ldloc.s 0x1c
  IL_0255  ldc.i4.0
  IL_0256  ldloc 0
  IL_025A  ldc.i4 0xa7bae0c6
  IL_025F  add
  IL_0260  stloc 31
  IL_0264  ldloc 0
  IL_0268  ldc.i4 0xbed000b8
  IL_026D  add
  IL_026E  stloc 0
  IL_0272  bgt.un IL_010d
  IL_0277  ldloc 0
  IL_027B  ldc.i4 0xe8eae00b
  IL_0280  add
  IL_0281  stloc 31
  IL_0285  ldloc 0
  IL_0289  ldc.i4 0xfadfccce
  IL_028E  add
  IL_028F  stloc 0
  IL_0293  br IL_010d
  IL_0298  ldloc.s 0x1b
  IL_029A  ldloc.s 0x11
  IL_029C  ldloc 0
  IL_02A0  ldc.i4 0xb11cfb92
  IL_02A5  add
  IL_02A6  stloc 31
  IL_02AA  ldloc 0
  IL_02AE  ldc.i4 0xda323882
  IL_02B3  add
  IL_02B4  stloc 0
  IL_02B8  bgt IL_010d
  IL_02BD  ldloc 0
  IL_02C1  ldc.i4 0xd6eac311
  IL_02C6  add
  IL_02C7  stloc 31
  IL_02CB  ldloc 0
  IL_02CF  ldc.i4 0x52550fa0
  IL_02D4  add
  IL_02D5  stloc 0
  IL_02D9  br IL_010d
  IL_02DE  ldloc.s 0x14
  IL_02E0  ldc.i4 0x168
  IL_02E5  conv.i8
  IL_02E6  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_02EB  br IL_0394
  IL_02F0  ldloc.s 0x11
  IL_02F2  ldloc.s 0x22
  IL_02F4  ldloc 0
  IL_02F8  ldc.i4 0x8495b370
  IL_02FD  add
  IL_02FE  stloc 31
  IL_0302  ldloc 0
  IL_0306  ldc.i4 0xadaaf060
  IL_030B  add
  IL_030C  stloc 0
  IL_0310  bge IL_010d
  IL_0315  ldloc 0
  IL_0319  ldc.i4 0xd6eac30d
  IL_031E  add
  IL_031F  stloc 31
  IL_0323  ldloc 0
  IL_0327  ldc.i4 0x519fc278
  IL_032C  add
  IL_032D  stloc 0
  IL_0331  br IL_010d
  IL_0336  ldloc.s 0x1b
  IL_0338  ldloc.s 0x11
  IL_033A  sub
  IL_033B  ldloc.s 0x1c
  IL_033D  conv.u8
  IL_033E  call 0x60041e9   ; MethodDef:CheckStaticCompiler
  IL_0343  conv.u4
  IL_0344  stloc.s 0x13
  IL_0346  ldloc 0
  IL_034A  ldc.i4 0xd3af256d
  IL_034F  add
  IL_0350  stloc 31
  IL_0354  ldloc 0
  IL_0358  ldc.i4 0xdd036608
  IL_035D  add
  IL_035E  stloc 0
  IL_0362  br IL_010d
  IL_0367  ldc.i4 0x10000
  IL_036C  newarr 0x100005b   ; TypeRef:System.Byte
  IL_0371  stloc.s 0x12
  IL_0373  ldloc 0
  IL_0377  ldc.i4 0xaebf3da8
  IL_037C  add
  IL_037D  stloc 31
  IL_0381  ldloc 0
  IL_0385  ldc.i4 0x2044390b
  IL_038A  add
  IL_038B  stloc 0
  IL_038F  br IL_010d
  IL_0394  nop
  IL_0395  ldc.i4 0x14
  IL_039A  stloc 31
  IL_039E  ldc.i4 0x53910de0
  IL_03A3  stloc 0
  IL_03A7  br IL_010d
  IL_03AC  ldloc.s 0x1e
  IL_03AE  ldc.i4.1
  IL_03AF  add
  IL_03B0  stloc.s 0x1e
  IL_03B2  ldloc 0
  IL_03B6  ldc.i4 0xee0b1344
  IL_03BB  add
  IL_03BC  stloc 31
  IL_03C0  ldloc 0
  IL_03C4  ldc.i4 0x21d082d1
  IL_03C9  add
  IL_03CA  stloc 0
  IL_03CE  br IL_010d
  IL_03D3  ldloc.s 0xd
  IL_03D5  ldloc.s 0x14
  IL_03D7  ldc.i4 0x98
  IL_03DC  ldloc.s 0x12
  IL_03DE  call 0x60041e2   ; MethodDef:HandlePool
  IL_03E3  br IL_0712
  IL_03E8  ldloc.s 0x11
  IL_03EA  ldloc.s 0x22
  IL_03EC  ldloc 0
  IL_03F0  ldc.i4 0xd6eac2fb
  IL_03F5  add
  IL_03F6  stloc 31
  IL_03FA  ldloc 0
  IL_03FE  ldc.i4 0x33b9d8f
  IL_0403  add
  IL_0404  stloc 0
  IL_0408  blt IL_010d
  IL_040D  ldloc 0
  IL_0411  ldc.i4 0xd3af2568
  IL_0416  add
  IL_0417  stloc 31
  IL_041B  ldloc 0
  IL_041F  ldc.i4 0x35c6c715
  IL_0424  add
  IL_0425  stloc 0
  IL_0429  br IL_010d
  IL_042E  ldloc.s 0x1b
  IL_0430  ldloc.s 0xa
  IL_0432  conv.u8
  IL_0433  add
  IL_0434  stloc.s 0x22
  IL_0436  ldloc 0
  IL_043A  ldc.i4 0xda40b7e8
  IL_043F  add
  IL_0440  stloc 31
  IL_0444  ldloc 0
  IL_0448  ldc.i4 0x285fc217
  IL_044D  add
  IL_044E  stloc 0
  IL_0452  br IL_010d
  IL_0457  ldloc.s 0x14
  IL_0459  ldloc.s 0x9
  IL_045B  ldc.i4.s 0x20
  IL_045D  add
  IL_045E  conv.u8
  IL_045F  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_0464  ldloc 0
  IL_0468  ldc.i4 0x9ddbf1b2
  IL_046D  add
  IL_046E  stloc 31
  IL_0472  ldloc 0
  IL_0476  ldc.i4 0x10e233d7
  IL_047B  add
  IL_047C  stloc 0
  IL_0480  br IL_010d
  IL_0485  nop
  IL_0486  ldc.i4 0x1a
  IL_048B  stloc 31
  IL_048F  ldc.i4 0x33c56fa7
  IL_0494  stloc 0
  IL_0498  br IL_010d
  IL_049D  ldloc.s 0x14
  IL_049F  ldc.i4 0x178
  IL_04A4  conv.i8
  IL_04A5  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_04AA  ldloc 0
  IL_04AE  ldc.i4 0xdef88473
  IL_04B3  add
  IL_04B4  stloc 31
  IL_04B8  ldloc 0
  IL_04BC  ldc.i4 0x3289923f
  IL_04C1  add
  IL_04C2  stloc 0
  IL_04C6  br IL_010d
  IL_04CB  ldsfld 0x4001fcd   ; Field:1FCD
  IL_04D0  ldloc.s 0xd
  IL_04D2  call 0x60041ed   ; MethodDef:VerifyVirtualMatcher
  IL_04D7  ldloc.s 0x17
  IL_04D9  ldloc.s 0x18
  IL_04DB  call 0x60041ee   ; MethodDef:VerifyDynamicStrategy
  IL_04E0  ldc.i4.0
  IL_04E1  ceq
  IL_04E3  stloc.s 0xc
  IL_04E5  br IL_0977
  IL_04EA  ldloc.s 0x22
  IL_04EC  ldloc.s 0x11
  IL_04EE  sub
  IL_04EF  conv.u4
  IL_04F0  stloc.s 0x4
  IL_04F2  ldloc 0
  IL_04F6  ldc.i4 0x854b0086
  IL_04FB  add
  IL_04FC  stloc 31
  IL_0500  ldloc 0
  IL_0504  ldc.i4 0xe99d71c3
  IL_0509  add
  IL_050A  stloc 0
  IL_050E  br IL_010d
  IL_0513  ldloc.s 0x14
  IL_0515  ldloc.s 0x3
  IL_0517  ldloc.s 0x1e
  IL_0519  ldc.i4.s 0x28
  IL_051B  mul
  IL_051C  conv.i8
  IL_051D  add
  IL_051E  ldc.i4.s 0x10
  IL_0520  conv.i8
  IL_0521  add
  IL_0522  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_0527  ldloc 0
  IL_052B  ldc.i4 0xf3fc2941
  IL_0530  add
  IL_0531  stloc 31
  IL_0535  ldloc 0
  IL_0539  ldc.i4 0x8e8faf2
  IL_053E  add
  IL_053F  stloc 0
  IL_0543  br IL_010d
  IL_0548  ldloc.s 0x1e
  IL_054A  ldloc.s 0x8
  IL_054C  ldloc 0
  IL_0550  ldc.i4 0xcc3a9072
  IL_0555  add
  IL_0556  stloc 31
  IL_055A  ldloc 0
  IL_055E  ldc.i4 0xd83e673a
  IL_0563  add
  IL_0564  stloc 0
  IL_0568  blt IL_010d
  IL_056D  ldloc 0
  IL_0571  ldc.i4 0xf3fc2931
  IL_0576  add
  IL_0577  stloc 31
  IL_057B  ldloc 0
  IL_057F  ldc.i4 0x3afb765e
  IL_0584  add
  IL_0585  stloc 0
  IL_0589  br IL_010d
  IL_058E  ldloc.s 0x18
  IL_0590  call 0x60041ec   ; MethodDef:ValidateEditableMember
  IL_0595  ldloc 0
  IL_0599  ldc.i4 0xc6dea0d0
  IL_059E  add
  IL_059F  stloc 31
  IL_05A3  ldloc 0
  IL_05A7  ldc.i4 0x274824a7
  IL_05AC  add
  IL_05AD  stloc 0
  IL_05B1  br IL_010d
  IL_05B6  ldloc.s 0x14
  IL_05B8  ldloc.s 0x1b
  IL_05BA  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_05BF  ldloc 0
  IL_05C3  ldc.i4 0x8542cb81
  IL_05C8  add
  IL_05C9  stloc 31
  IL_05CD  ldloc 0
  IL_05D1  ldc.i4 0xeea983ca
  IL_05D6  add
  IL_05D7  stloc 0
  IL_05DB  br IL_010d
  IL_05E0  ldloc.s 0x1a
  IL_05E2  call 0x60041e7   ; MethodDef:CheckIdentifiableConfig
  IL_05E7  stloc.s 0x1c
  IL_05E9  ldloc 0
  IL_05ED  ldc.i4 0xeb132e30
  IL_05F2  add
  IL_05F3  stloc 31
  IL_05F7  ldloc 0
  IL_05FB  ldc.i4 0xfe7a09d6
  IL_0600  add
  IL_0601  stloc 0
  IL_0605  br IL_010d
  IL_060A  ldloc.s 0x14
  IL_060C  call 0x60041e6   ; MethodDef:VerifyVerifier
  IL_0611  stloc.s 0x11
  IL_0613  ldloc 0
  IL_0617  ldc.i4 0xe8eae002
  IL_061C  add
  IL_061D  stloc 31
  IL_0621  ldloc 0
  IL_0625  ldc.i4 0x37cde481
  IL_062A  add
  IL_062B  stloc 0
  IL_062F  br IL_010d
  IL_0634  ldloc.s 0x14
  IL_0636  newobj 0xa00029f   ; MemberRef:System.IO.BinaryReader::.ctor
  IL_063B  stloc.s 0x1a
  IL_063D  ldloc 0
  IL_0641  ldc.i4 0xb358055d
  IL_0646  add
  IL_0647  stloc 31
  IL_064B  ldloc 0
  IL_064F  ldc.i4 0x498c7c5
  IL_0654  add
  IL_0655  stloc 0
  IL_0659  br IL_010d
  IL_065E  ldc.i4.0
  IL_065F  stloc.s 0x1e
  IL_0661  br IL_0485
  IL_0666  nop
  IL_0667  ldc.i4 0x20
  IL_066C  stloc 31
  IL_0670  ldc.i4 0x58451f50
  IL_0675  stloc 0
  IL_0679  br IL_010d
  IL_067E  ldloc.s 0x1a
  IL_0680  ldloc.s 0xa
  IL_0682  call 0x60041eb   ; MethodDef:ValidateScheduledRole
  IL_0687  stloc.s 0x18
  IL_0689  ldloc 0
  IL_068D  ldc.i4 0x969947a6
  IL_0692  add
  IL_0693  stloc 31
  IL_0697  ldloc 0
  IL_069B  ldc.i4 0xcfbaa6ce
  IL_06A0  add
  IL_06A1  stloc 0
  IL_06A5  br IL_010d
  IL_06AA  nop
  IL_06AB  ldc.i4 0x20
  IL_06B0  stloc 31
  IL_06B4  ldc.i4 0x58451f50
  IL_06B9  stloc 0
  IL_06BD  br IL_010d
  IL_06C2  ldloc.s 0xd
  IL_06C4  ldloc.s 0x14
  IL_06C6  ldloc.s 0x1c
  IL_06C8  ldloc.s 0x12
  IL_06CA  call 0x60041e2   ; MethodDef:HandlePool
  IL_06CF  br IL_07ff
  IL_06D4  ldloc.s 0x14
  IL_06D6  dup
  IL_06D7  call 0x60041e6   ; MethodDef:VerifyVerifier
  IL_06DC  ldloc.s 0x4
  IL_06DE  conv.u8
  IL_06DF  add
  IL_06E0  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_06E5  br IL_0666
  IL_06EA  ldloc.s 0x1c
  IL_06EC  ldloc.s 0x4
  IL_06EE  sub
  IL_06EF  stloc.s 0x1c
  IL_06F1  ldloc 0
  IL_06F5  ldc.i4 0xab2a7063
  IL_06FA  add
  IL_06FB  stloc 31
  IL_06FF  ldloc 0
  IL_0703  ldc.i4 0x12205db4
  IL_0708  add
  IL_0709  stloc 0
  IL_070D  br IL_010d
  IL_0712  ldloc.s 0x1a
  IL_0714  call 0x60041e3   ; MethodDef:VerifyDetailedConnection
  IL_0719  ldc.i4 0x20b
  IL_071E  ceq
  IL_0720  ldc.i4.0
  IL_0721  ceq
  IL_0723  dup
  IL_0724  brtrue IL_0872
  IL_0729  br IL_086b
  IL_072E  ldloc.s 0x1c
  IL_0730  ldloc.s 0x13
  IL_0732  sub
  IL_0733  stloc.s 0x1c
  IL_0735  ldloc 0
  IL_0739  ldc.i4 0xfbd7ab99
  IL_073E  add
  IL_073F  stloc 31
  IL_0743  ldloc 0
  IL_0747  ldc.i4 0x541ccac9
  IL_074C  add
  IL_074D  stloc 0
  IL_0751  br IL_010d
  IL_0756  ldloc.s 0x4
  IL_0758  ldloc.s 0x1c
  IL_075A  ldloc 0
  IL_075E  ldc.i4 0x9bad8ecd
  IL_0763  add
  IL_0764  stloc 31
  IL_0768  ldloc 0
  IL_076C  ldc.i4 0xada27b90
  IL_0771  add
  IL_0772  stloc 0
  IL_0776  bge.un IL_010d
  IL_077B  ldloc 0
  IL_077F  ldc.i4 0xee0b133b
  IL_0784  add
  IL_0785  stloc 31
  IL_0789  ldloc 0
  IL_078D  ldc.i4 0x42e0a2d2
  IL_0792  add
  IL_0793  stloc 0
  IL_0797  br IL_010d
  IL_079C  ldloc.s 0xd
  IL_079E  ldloc.s 0x14
  IL_07A0  ldloc.s 0x13
  IL_07A2  ldloc.s 0x12
  IL_07A4  call 0x60041e2   ; MethodDef:HandlePool
  IL_07A9  ldloc 0
  IL_07AD  ldc.i4 0xf6abbf7f
  IL_07B2  add
  IL_07B3  stloc 31
  IL_07B7  ldloc 0
  IL_07BB  ldc.i4 0xfad413e5
  IL_07C0  add
  IL_07C1  stloc 0
  IL_07C5  br IL_010d
  IL_07CA  ldloc.s 0x1a
  IL_07CC  call 0x60041e7   ; MethodDef:CheckIdentifiableConfig
  IL_07D1  ldloc.s 0x8
  IL_07D3  ldloc.s 0x3
  IL_07D5  ldloc.s 0x1a
  IL_07D7  call 0x60041e8   ; MethodDef:ParseComparator
  IL_07DC  stloc.s 0x9
  IL_07DE  ldloc 0
  IL_07E2  ldc.i4 0xac6ef230
  IL_07E7  add
  IL_07E8  stloc 31
  IL_07EC  ldloc 0
  IL_07F0  ldc.i4 0xe930073
  IL_07F5  add
  IL_07F6  stloc 0
  IL_07FA  br IL_010d
  IL_07FF  nop
  IL_0800  ldc.i4 0x13
  IL_0805  stloc 31
  IL_0809  ldc.i4 0x11f4ecd6
  IL_080E  stloc 0
  IL_0812  br IL_010d
  IL_0817  ldloc.s 0x14
  IL_0819  ldloc.s 0x19
  IL_081B  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_0820  ldloc 0
  IL_0824  ldc.i4 0xb1e0f5e7
  IL_0829  add
  IL_082A  stloc 31
  IL_082E  ldloc 0
  IL_0832  ldc.i4 0xf4ab1128
  IL_0837  add
  IL_0838  stloc 0
  IL_083C  br IL_010d
  IL_0841  ldloc.s 0x1a
  IL_0843  call 0x60041e7   ; MethodDef:CheckIdentifiableConfig
  IL_0848  stloc.s 0x20
  IL_084A  ldloc 0
  IL_084E  ldc.i4 0xec992465
  IL_0853  add
  IL_0854  stloc 31
  IL_0858  ldloc 0
  IL_085C  ldc.i4 0x51a7df6
  IL_0861  add
  IL_0862  stloc 0
  IL_0866  br IL_010d
  IL_086B  ldc.i4.s 0x70
  IL_086D  br IL_0879
  IL_0872  ldc.i4.s 0x60
  IL_0874  br IL_0879
  IL_0879  stloc.s 0x7
  IL_087B  ldloc.s 0x14
  IL_087D  ldc.i4 0x98
  IL_0882  conv.i8
  IL_0883  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_0888  ldloc.s 0x14
  IL_088A  ldloc.s 0x12
  IL_088C  ldc.i4.0
  IL_088D  ldloc.s 0x7
  IL_088F  call 0x60041e4   ; MethodDef:UpdateLocator
  IL_0894  pop
  IL_0895  ldloc.s 0x12
  IL_0897  ldc.i4.s 0x40
  IL_0899  ldc.i4.0
  IL_089A  stelem.i1
  IL_089B  ldloc.s 0x12
  IL_089D  ldc.i4.s 0x41
  IL_089F  ldc.i4.0
  IL_08A0  stelem.i1
  IL_08A1  ldloc.s 0x12
  IL_08A3  ldc.i4.s 0x42
  IL_08A5  ldc.i4.0
  IL_08A6  stelem.i1
  IL_08A7  ldloc.s 0x12
  IL_08A9  ldc.i4.s 0x43
  IL_08AB  ldc.i4.0
  IL_08AC  stelem.i1
  IL_08AD  ldloc.s 0xd
  IL_08AF  ldloc.s 0x12
  IL_08B1  ldc.i4.0
  IL_08B2  ldloc.s 0x7
  IL_08B4  call 0x60041e5   ; MethodDef:CheckAutomatableQueue
  IL_08B9  ldloc.s 0x14
  IL_08BB  ldloc.s 0x12
  IL_08BD  ldc.i4.0
  IL_08BE  ldc.i4 0x80
  IL_08C3  call 0x60041e4   ; MethodDef:UpdateLocator
  IL_08C8  pop
  IL_08C9  ldloc.s 0x12
  IL_08CB  ldc.i4.s 0x20
  IL_08CD  ldc.i4.0
  IL_08CE  stelem.i1
  IL_08CF  ldloc.s 0x12
  IL_08D1  ldc.i4.s 0x21
  IL_08D3  ldc.i4.0
  IL_08D4  stelem.i1
  IL_08D5  ldloc.s 0x12
  IL_08D7  ldc.i4.s 0x22
  IL_08D9  ldc.i4.0
  IL_08DA  stelem.i1
  IL_08DB  ldloc.s 0x12
  IL_08DD  ldc.i4.s 0x23
  IL_08DF  ldc.i4.0
  IL_08E0  stelem.i1
  IL_08E1  ldloc.s 0x12
  IL_08E3  ldc.i4.s 0x24
  IL_08E5  ldc.i4.0
  IL_08E6  stelem.i1
  IL_08E7  ldloc.s 0x12
  IL_08E9  ldc.i4.s 0x25
  IL_08EB  ldc.i4.0
  IL_08EC  stelem.i1
  IL_08ED  ldloc.s 0x12
  IL_08EF  ldc.i4.s 0x26
  IL_08F1  ldc.i4.0
  IL_08F2  stelem.i1
  IL_08F3  ldloc.s 0x12
  IL_08F5  ldc.i4.s 0x27
  IL_08F7  ldc.i4.0
  IL_08F8  stelem.i1
  IL_08F9  ldloc.s 0xd
  IL_08FB  ldloc.s 0x12
  IL_08FD  ldc.i4.0
  IL_08FE  ldc.i4 0x80
  IL_0903  call 0x60041e5   ; MethodDef:CheckAutomatableQueue
  IL_0908  ldloc.s 0x14
  IL_090A  call 0x60041e6   ; MethodDef:VerifyVerifier
  IL_090F  stloc.s 0x3
  IL_0911  ldloc.s 0x14
  IL_0913  ldc.i4 0x86
  IL_0918  conv.i8
  IL_0919  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_091E  ldloc.s 0x1a
  IL_0920  call 0x60041e3   ; MethodDef:VerifyDetailedConnection
  IL_0925  stloc.s 0x8
  IL_0927  ldloc.s 0x14
  IL_0929  ldloc.s 0x3
  IL_092B  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_0930  ldloc.s 0xd
  IL_0932  ldloc.s 0x14
  IL_0934  ldloc.s 0x8
  IL_0936  ldc.i4.s 0x28
  IL_0938  mul
  IL_0939  ldloc.s 0x12
  IL_093B  call 0x60041e2   ; MethodDef:HandlePool
  IL_0940  ldloc.s 0x14
  IL_0942  call 0x60041e6   ; MethodDef:VerifyVerifier
  IL_0947  stloc.s 0x19
  IL_0949  ldc.i4 0x17
  IL_094E  stloc 31
  IL_0952  ldc.i4 0x21077ba1
  IL_0957  stloc 0
  IL_095B  brfalse IL_010d
  IL_0960  ldc.i4 0x1e
  IL_0965  stloc 31
  IL_0969  ldc.i4 0x714c3009
  IL_096E  stloc 0
  IL_0972  br IL_010d
  IL_0977  nop
  IL_0978  ldc.i4 0x6
  IL_097D  stloc 31
  IL_0981  ldc.i4 0x34718b84
  IL_0986  stloc 0
  IL_098A  leave IL_0012
  IL_098F  pop
  IL_0990  br IL_0995
  IL_0995  ldc.i4.1
  IL_0996  stloc.s 0xc
  IL_0998  br IL_099d
  IL_099D  nop
  IL_099E  ldc.i4 0x6
  IL_09A3  stloc 31
  IL_09A7  ldc.i4 0x34718b84
  IL_09AC  stloc 0
  IL_09B0  leave IL_0012
  IL_09B5  ldtoken 0x2000622   ; TypeDef#1570
  IL_09BA  call 0x60041cb   ; MethodDef:SortRole
  IL_09BF  callvirt 0xa000997   ; MemberRef:System.Type::get_Assembly
  IL_09C4  call 0x60041cc   ; MethodDef:ValidateFilteredTransaction
  IL_09C9  stloc.s 0x2
  IL_09CB  ldloc 0
  IL_09CF  ldc.i4 0xaca491cb
  IL_09D4  add
  IL_09D5  stloc 31
  IL_09D9  ldloc 0
  IL_09DD  ldc.i4 0x18767e7f
  IL_09E2  add
  IL_09E3  stloc 0
  IL_09E7  br IL_0012
  IL_09EC  ldc.i4.0
  IL_09ED  stloc.s 0xc
  IL_09EF  br IL_2309
  IL_09F4  ldloc.s 0xc
  IL_09F6  ldloc 0
  IL_09FA  ldc.i4 0xb90c5289
  IL_09FF  add
  IL_0A00  stloc 31
  IL_0A04  ldloc 0
  IL_0A08  ldc.i4 0xe8b16266
  IL_0A0D  add
  IL_0A0E  stloc 0
  IL_0A12  brtrue IL_0012
  IL_0A17  ldloc 0
  IL_0A1B  ldc.i4 0xd05af022
  IL_0A20  add
  IL_0A21  stloc 31
  IL_0A25  ldloc 0
  IL_0A29  ldc.i4 0xde5151d6
  IL_0A2E  add
  IL_0A2F  stloc 0
  IL_0A33  br IL_0012
  IL_0A38  nop
  IL_0A39  br IL_0b51
  IL_0A3E  call 0x60041c9   ; MethodDef:VerifyAlphabeticObject
  IL_0A43  ldc.i4.1
  IL_0A44  call 0x60041ca   ; MethodDef:CheckAdjustableExplorer
  IL_0A49  ldloc 0
  IL_0A4D  ldc.i4 0xab70b114
  IL_0A52  add
  IL_0A53  stloc 31
  IL_0A57  ldloc 0
  IL_0A5B  ldc.i4 0xc51fd997
  IL_0A60  add
  IL_0A61  stloc 0
  IL_0A65  br IL_0012
  IL_0A6A  ldc.i4.0
  IL_0A6B  stloc.s 0xc
  IL_0A6D  br IL_0be0
  IL_0A72  ldtoken 0x2000622   ; TypeDef#1570
  IL_0A77  call 0x60041cb   ; MethodDef:SortRole
  IL_0A7C  callvirt 0xa000997   ; MemberRef:System.Type::get_Assembly
  IL_0A81  call 0x60041f0   ; MethodDef:FillResolver
  IL_0A86  call 0x60041f1   ; MethodDef:ValidateSortedDispatcher
  IL_0A8B  ldstr 0x70000a26   ; "loudOneDriveForBusiness.Properties.Resources"
  IL_0A90  call 0x60041f2   ; MethodDef:CheckExpandableParameter
  IL_0A95  newobj 0xa000252   ; MemberRef:System.Exception::.ctor
  IL_0A9A  throw
  IL_0A9B  ldc.i4 0x7f628c8
  IL_0AA0  stloc 0
  IL_0AA4  ldc.i4 0x0
  IL_0AA9  stloc 31
  IL_0AAD  ldloc 31
  IL_0AB1  switch(3) 0xaba,0xafd,0xaf0
  IL_0AC2  nop
  IL_0AC3  call 0x60041ce   ; MethodDef:PlayStrategy
  IL_0AC8  stloc.s 0xd
  IL_0ACA  ldloc 0
  IL_0ACE  ldc.i4 0xf809d739
  IL_0AD3  add
  IL_0AD4  stloc 31
  IL_0AD8  ldloc 0
  IL_0ADC  ldc.i4 0xd7c8a71
  IL_0AE1  add
  IL_0AE2  stloc 0
  IL_0AE6  br IL_0aad
  IL_0AEB  leave IL_2309
  IL_0AF0  ldloc.s 0x2
  IL_0AF2  call 0x60041d0   ; MethodDef:ValidateGlobalParser
  IL_0AF7  brtrue IL_0b2e
  IL_0AFC  br IL_0aeb
  IL_0B01  ldstr 0x70000a42   ; "OneDriveForBusiness.Properties.Resources"
  IL_0B06  call 0x60041cf   ; MethodDef:CheckRandomFinalizer
  IL_0B0B  stloc.s 0x17
  IL_0B0D  ldloc 0
  IL_0B11  ldc.i4 0xea8d4cc9
  IL_0B16  add
  IL_0B17  stloc 31
  IL_0B1B  ldloc 0
  IL_0B1F  ldc.i4 0x5188b2d0
  IL_0B24  add
  IL_0B25  stloc 0
  IL_0B29  br IL_0aad
  IL_0B2E  nop
  IL_0B2F  ldc.i4 0xc
  IL_0B34  stloc 31
  IL_0B38  ldc.i4 0x3016f90e
  IL_0B3D  stloc 0
  IL_0B41  leave IL_0012
  IL_0B46  pop
  IL_0B47  br IL_0b4c
  IL_0B4C  leave IL_2309
  IL_0B51  ldc.i4 0x2a41522d
  IL_0B56  stloc 0
  IL_0B5A  ldc.i4 0x1
  IL_0B5F  stloc 31
  IL_0B63  ldloc 31
  IL_0B67  switch(2) 0xb99,0xb74
  IL_0B74  nop
  IL_0B75  ldloc.s 0x1a
  IL_0B77  brfalse IL_0ba9
  IL_0B7C  ldloc 0
  IL_0B80  ldc.i4 0xd5beadd3
  IL_0B85  add
  IL_0B86  stloc 31
  IL_0B8A  ldloc 0
  IL_0B8E  ldc.i4 0xfff4b9ac
  IL_0B93  add
  IL_0B94  stloc 0
  IL_0B98  br IL_0b63
  IL_0B9D  ldloc.s 0x1a
  IL_0B9F  call 0x60041ef   ; MethodDef:ChangeField
  IL_0BA4  br IL_0ba9
  IL_0BA9  nop
  IL_0BAA  ldc.i4 0x1
  IL_0BAF  stloc 31
  IL_0BB3  ldc.i4 0x2fa50fde
  IL_0BB8  stloc 0
  IL_0BBC  leave IL_0012
  IL_0BC1  pop
  IL_0BC2  br IL_0bc7
  IL_0BC7  nop
  IL_0BC8  ldc.i4 0x1
  IL_0BCD  stloc 31
  IL_0BD1  ldc.i4 0x2fa50fde
  IL_0BD6  stloc 0
  IL_0BDA  leave IL_0012
  IL_0BDF  ret
  IL_0BE0  ldsfld 0x4001fbe   ; Field:1FBE
  IL_0BE5  ldstr 0x70000a4c   ; "neDriveForBusiness.Properties.Resources"
  IL_0BEA  call 0x60041d1   ; MethodDef:CheckRemoteProfiler
  IL_0BEF  newobj 0x6004264   ; MethodDef:.ctor
  IL_0BF4  dup
  IL_0BF5  call 0x60041d2   ; MethodDef:ProcessParameter
  IL_0BFA  ldc.i4.0
  IL_0BFB  conv.i8
  IL_0BFC  call 0x60041d3   ; MethodDef:ValidateSequentialSpec
  IL_0C01  dup
  IL_0C02  dup
  IL_0C03  call 0x60041d2   ; MethodDef:ProcessParameter
  IL_0C08  call 0x60041d4   ; MethodDef:ValidateMonoModule
  IL_0C0D  conv.i4
  IL_0C0E  call 0x60041d5   ; MethodDef:RateMonitor
  IL_0C13  stloc.s 0x16
  IL_0C15  ldc.i4 0x20
  IL_0C1A  newarr 0x100005b   ; TypeRef:System.Byte
  IL_0C1F  stloc 21
  IL_0C23  ldloc 21
  IL_0C27  ldc.i4 0x0
  IL_0C2C  ldc.i4 0x68
  IL_0C31  ldc.i4 0x3a
  IL_0C36  add
  IL_0C37  stelem.i1
  IL_0C38  ldc.i4 0xc0
  IL_0C3D  ldc.i4 0x40
  IL_0C42  sub
  IL_0C43  stloc 6
  IL_0C47  ldloc 21
  IL_0C4B  ldc.i4 0x0
  IL_0C50  ldloc 6
  IL_0C54  stelem.i1
  IL_0C55  ldloc 21
  IL_0C59  ldc.i4 0x0
  IL_0C5E  ldc.i4 0x32
  IL_0C63  ldc.i4 0x49
  IL_0C68  add
  IL_0C69  stelem.i1
  IL_0C6A  ldloc 21
  IL_0C6E  ldc.i4 0x0
  IL_0C73  ldc.i4 0xc9
  IL_0C78  ldc.i4 0x43
  IL_0C7D  sub
  IL_0C7E  stelem.i1
  IL_0C7F  ldc.i4 0x8e
  IL_0C84  ldc.i4 0x4a
  IL_0C89  add
  IL_0C8A  stloc 6
  IL_0C8E  ldloc 21
  IL_0C92  ldc.i4 0x0
  IL_0C97  ldloc 6
  IL_0C9B  stelem.i1
  IL_0C9C  ldc.i4 0x93
  IL_0CA1  ldc.i4 0x31
  IL_0CA6  sub
  IL_0CA7  stloc 14
  IL_0CAB  ldloc 21
  IL_0CAF  ldc.i4 0x1
  IL_0CB4  ldloc 14
  IL_0CB8  stelem.i1
  IL_0CB9  ldloc 21
  IL_0CBD  ldc.i4 0x1
  IL_0CC2  ldc.i4 0xcf
  IL_0CC7  ldc.i4 0x45
  IL_0CCC  sub
  IL_0CCD  stelem.i1
  IL_0CCE  ldloc 21
  IL_0CD2  ldc.i4 0x1
  IL_0CD7  ldc.i4 0x3
  IL_0CDC  ldc.i4 0x5e
  IL_0CE1  add
  IL_0CE2  stelem.i1
  IL_0CE3  ldloc 21
  IL_0CE7  ldc.i4 0x1
  IL_0CEC  ldc.i4 0x83
  IL_0CF1  ldc.i4 0x2b
  IL_0CF6  sub
  IL_0CF7  stelem.i1
  IL_0CF8  ldloc 21
  IL_0CFC  ldc.i4 0x1
  IL_0D01  ldc.i4 0xa2
  IL_0D06  ldc.i4 0x52
  IL_0D0B  add
  IL_0D0C  stelem.i1
  IL_0D0D  ldloc 21
  IL_0D11  ldc.i4 0x2
  IL_0D16  ldc.i4 0x12
  IL_0D1B  ldc.i4 0x4
  IL_0D20  add
  IL_0D21  stelem.i1
  IL_0D22  ldloc 21
  IL_0D26  ldc.i4 0x2
  IL_0D2B  ldc.i4 0xb5
  IL_0D30  ldc.i4 0x3c
  IL_0D35  sub
  IL_0D36  stelem.i1
  IL_0D37  ldc.i4 0xa0
  IL_0D3C  ldc.i4 0x35
  IL_0D41  sub
  IL_0D42  stloc 6
  IL_0D46  ldloc 21
  IL_0D4A  ldc.i4 0x2
  IL_0D4F  ldloc 6
  IL_0D53  stelem.i1
  IL_0D54  ldc.i4 0xde
  IL_0D59  ldc.i4 0x4a
  IL_0D5E  sub
  IL_0D5F  stloc 6
  IL_0D63  ldloc 21
  IL_0D67  ldc.i4 0x2
  IL_0D6C  ldloc 6
  IL_0D70  stelem.i1
  IL_0D71  ldc.i4 0x26
  IL_0D76  ldc.i4 0x2d
  IL_0D7B  add
  IL_0D7C  stloc 6
  IL_0D80  ldloc 21
  IL_0D84  ldc.i4 0x2
  IL_0D89  ldloc 6
  IL_0D8D  stelem.i1
  IL_0D8E  ldloc 21
  IL_0D92  ldc.i4 0x2
  IL_0D97  ldc.i4 0xf6
  IL_0D9C  ldc.i4 0x7c
  IL_0DA1  sub
  IL_0DA2  stelem.i1
  IL_0DA3  ldc.i4 0x10
  IL_0DA8  ldc.i4 0x2f
  IL_0DAD  add
  IL_0DAE  stloc 6
  IL_0DB2  ldloc 21
  IL_0DB6  ldc.i4 0x3
  IL_0DBB  ldloc 6
  IL_0DBF  stelem.i1
  IL_0DC0  ldloc 21
  IL_0DC4  ldc.i4 0x3
  IL_0DC9  ldc.i4 0x33
  IL_0DCE  ldc.i4 0x59
  IL_0DD3  add
  IL_0DD4  stelem.i1
  IL_0DD5  ldc.i4 0x13
  IL_0DDA  ldc.i4 0x76
  IL_0DDF  add
  IL_0DE0  stloc 6
  IL_0DE4  ldloc 21
  IL_0DE8  ldc.i4 0x3
  IL_0DED  ldloc 6
  IL_0DF1  stelem.i1
  IL_0DF2  ldc.i4 0xb3
  IL_0DF7  ldc.i4 0x3b
  IL_0DFC  sub
  IL_0DFD  stloc 6
  IL_0E01  ldloc 21
  IL_0E05  ldc.i4 0x3
  IL_0E0A  ldloc 6
  IL_0E0E  stelem.i1
  IL_0E0F  ldc.i4 0x5c
  IL_0E14  ldc.i4 0x37
  IL_0E19  sub
  IL_0E1A  stloc 14
  IL_0E1E  ldloc 21
  IL_0E22  ldc.i4 0x3
  IL_0E27  ldloc 14
  IL_0E2B  stelem.i1
  IL_0E2C  ldloc 21
  IL_0E30  ldc.i4 0x4
  IL_0E35  ldc.i4 0x42
  IL_0E3A  ldc.i4 0x75
  IL_0E3F  add
  IL_0E40  stelem.i1
  IL_0E41  ldc.i4 0x35
  IL_0E46  ldc.i4 0x2f
  IL_0E4B  add
  IL_0E4C  stloc 6
  IL_0E50  ldloc 21
  IL_0E54  ldc.i4 0x4
  IL_0E59  ldloc 6
  IL_0E5D  stelem.i1
  IL_0E5E  ldc.i4 0x4b
  IL_0E63  ldc.i4 0x18
  IL_0E68  add
  IL_0E69  stloc 6
  IL_0E6D  ldloc 21
  IL_0E71  ldc.i4 0x4
  IL_0E76  ldloc 6
  IL_0E7A  stelem.i1
  IL_0E7B  ldloc 21
  IL_0E7F  ldc.i4 0x4
  IL_0E84  ldc.i4 0x4a
  IL_0E89  ldc.i4 0x38
  IL_0E8E  add
  IL_0E8F  stelem.i1
  IL_0E90  ldloc 21
  IL_0E94  ldc.i4 0x4
  IL_0E99  ldc.i4 0x75
  IL_0E9E  ldc.i4 0x1d
  IL_0EA3  add
  IL_0EA4  stelem.i1
  IL_0EA5  ldloc 21
  IL_0EA9  ldc.i4 0x5
  IL_0EAE  ldc.i4 0xb0
  IL_0EB3  ldc.i4 0x3a
  IL_0EB8  sub
  IL_0EB9  stelem.i1
  IL_0EBA  ldc.i4 0x7c
  IL_0EBF  ldc.i4 0x56
  IL_0EC4  add
  IL_0EC5  stloc 14
  IL_0EC9  ldloc 21
  IL_0ECD  ldc.i4 0x5
  IL_0ED2  ldloc 14
  IL_0ED6  stelem.i1
  IL_0ED7  ldc.i4 0x93
  IL_0EDC  ldc.i4 0x4a
  IL_0EE1  add
  IL_0EE2  stloc 14
  IL_0EE6  ldloc 21
  IL_0EEA  ldc.i4 0x5
  IL_0EEF  ldloc 14
  IL_0EF3  stelem.i1
  IL_0EF4  ldloc 21
  IL_0EF8  ldc.i4 0x6
  IL_0EFD  ldc.i4 0x69
  IL_0F02  ldc.i4 0x8
  IL_0F07  add
  IL_0F08  stelem.i1
  IL_0F09  ldloc 21
  IL_0F0D  ldc.i4 0x6
  IL_0F12  ldc.i4 0xb0
  IL_0F17  ldc.i4 0x3a
  IL_0F1C  sub
  IL_0F1D  stelem.i1
  IL_0F1E  ldc.i4 0x7a
  IL_0F23  ldc.i4 0x54
  IL_0F28  add
  IL_0F29  stloc 14
  IL_0F2D  ldloc 21
  IL_0F31  ldc.i4 0x6
  IL_0F36  ldloc 14
  IL_0F3A  stelem.i1
  IL_0F3B  ldc.i4 0xb8
  IL_0F40  ldc.i4 0x66
  IL_0F45  sub
  IL_0F46  stloc 14
  IL_0F4A  ldloc 21
  IL_0F4E  ldc.i4 0x6
  IL_0F53  ldloc 14
  IL_0F57  stelem.i1
  IL_0F58  ldc.i4 0x2
  IL_0F5D  ldc.i4 0x4
  IL_0F62  add
  IL_0F63  stloc 14
  IL_0F67  ldloc 21
  IL_0F6B  ldc.i4 0x7
  IL_0F70  ldloc 14
  IL_0F74  stelem.i1
  IL_0F75  ldc.i4 0x9d
  IL_0F7A  ldc.i4 0x34
  IL_0F7F  sub
  IL_0F80  stloc 14
  IL_0F84  ldloc 21
  IL_0F88  ldc.i4 0x7
  IL_0F8D  ldloc 14
  IL_0F91  stelem.i1
  IL_0F92  ldc.i4 0xce
  IL_0F97  ldc.i4 0x44
  IL_0F9C  sub
  IL_0F9D  stloc 6
  IL_0FA1  ldloc 21
  IL_0FA5  ldc.i4 0x7
  IL_0FAA  ldloc 6
  IL_0FAE  stelem.i1
  IL_0FAF  ldloc 21
  IL_0FB3  ldc.i4 0x7
  IL_0FB8  ldc.i4 0x78
  IL_0FBD  ldc.i4 0x52
  IL_0FC2  add
  IL_0FC3  stelem.i1
  IL_0FC4  ldc.i4 0x88
  IL_0FC9  ldc.i4 0x34
  IL_0FCE  sub
  IL_0FCF  stloc 14
  IL_0FD3  ldloc 21
  IL_0FD7  ldc.i4 0x7
  IL_0FDC  ldloc 14
  IL_0FE0  stelem.i1
  IL_0FE1  ldloc 21
  IL_0FE5  ldc.i4 0x8
  IL_0FEA  ldc.i4 0xee
  IL_0FEF  ldc.i4 0x4f
  IL_0FF4  sub
  IL_0FF5  stelem.i1
  IL_0FF6  ldc.i4 0x99
  IL_0FFB  ldc.i4 0x33
  IL_1000  sub
  IL_1001  stloc 6
  IL_1005  ldloc 21
  IL_1009  ldc.i4 0x8
  IL_100E  ldloc 6
  IL_1012  stelem.i1
  IL_1013  ldc.i4 0x55
  IL_1018  ldc.i4 0x46
  IL_101D  sub
  IL_101E  stloc 6
  IL_1022  ldloc 21
  IL_1026  ldc.i4 0x8
  IL_102B  ldloc 6
  IL_102F  stelem.i1
  IL_1030  ldloc 21
  IL_1034  ldc.i4 0x9
  IL_1039  ldc.i4 0xc2
  IL_103E  ldc.i4 0x40
  IL_1043  sub
  IL_1044  stelem.i1
  IL_1045  ldloc 21
  IL_1049  ldc.i4 0x9
  IL_104E  ldc.i4 0xbe
  IL_1053  ldc.i4 0x3f
  IL_1058  sub
  IL_1059  stelem.i1
  IL_105A  ldloc 21
  IL_105E  ldc.i4 0x9
  IL_1063  ldc.i4 0xf2
  IL_1068  ldc.i4 0x50
  IL_106D  sub
  IL_106E  stelem.i1
  IL_106F  ldc.i4 0x4b
  IL_1074  ldc.i4 0x16
  IL_1079  add
  IL_107A  stloc 14
  IL_107E  ldloc 21
  IL_1082  ldc.i4 0x9
  IL_1087  ldloc 14
  IL_108B  stelem.i1
  IL_108C  ldc.i4 0x5f
  IL_1091  ldc.i4 0x10
  IL_1096  add
  IL_1097  stloc 14
  IL_109B  ldloc 21
  IL_109F  ldc.i4 0x9
  IL_10A4  ldloc 14
  IL_10A8  stelem.i1
  IL_10A9  ldloc 21
  IL_10AD  ldc.i4 0x9
  IL_10B2  ldc.i4 0x77
  IL_10B7  ldc.i4 0x30
  IL_10BC  add
  IL_10BD  stelem.i1
  IL_10BE  ldloc 21
  IL_10C2  ldc.i4 0xa
  IL_10C7  ldc.i4 0x8e
  IL_10CC  ldc.i4 0x2f
  IL_10D1  sub
  IL_10D2  stelem.i1
  IL_10D3  ldc.i4 0x48
  IL_10D8  ldc.i4 0x69
  IL_10DD  add
  IL_10DE  stloc 14
  IL_10E2  ldloc 21
  IL_10E6  ldc.i4 0xa
  IL_10EB  ldloc 14
  IL_10EF  stelem.i1
  IL_10F0  ldloc 21
  IL_10F4  ldc.i4 0xa
  IL_10F9  ldc.i4 0xc4
  IL_10FE  ldc.i4 0x41
  IL_1103  sub
  IL_1104  stelem.i1
  IL_1105  ldloc 21
  IL_1109  ldc.i4 0xa
  IL_110E  ldc.i4 0x50
  IL_1113  ldc.i4 0x37
  IL_1118  add
  IL_1119  stelem.i1
  IL_111A  ldc.i4 0xb0
  IL_111F  ldc.i4 0x3a
  IL_1124  sub
  IL_1125  stloc 6
  IL_1129  ldloc 21
  IL_112D  ldc.i4 0xa
  IL_1132  ldloc 6
  IL_1136  stelem.i1
  IL_1137  ldloc 21
  IL_113B  ldc.i4 0xa
  IL_1140  ldc.i4 0xa2
  IL_1145  ldc.i4 0x37
  IL_114A  add
  IL_114B  stelem.i1
  IL_114C  ldloc 21
  IL_1150  ldc.i4 0xb
  IL_1155  ldc.i4 0x7d
  IL_115A  ldc.i4 0x29
  IL_115F  sub
  IL_1160  stelem.i1
  IL_1161  ldloc 21
  IL_1165  ldc.i4 0xb
  IL_116A  ldc.i4 0xf
  IL_116F  ldc.i4 0x50
  IL_1174  add
  IL_1175  stelem.i1
  IL_1176  ldloc 21
  IL_117A  ldc.i4 0xb
  IL_117F  ldc.i4 0x96
  IL_1184  ldc.i4 0x32
  IL_1189  sub
  IL_118A  stelem.i1
  IL_118B  ldc.i4 0xb4
  IL_1190  ldc.i4 0x3c
  IL_1195  sub
  IL_1196  stloc 6
  IL_119A  ldloc 21
  IL_119E  ldc.i4 0xb
  IL_11A3  ldloc 6
  IL_11A7  stelem.i1
  IL_11A8  ldc.i4 0xf3
  IL_11AD  ldc.i4 0x51
  IL_11B2  sub
  IL_11B3  stloc 6
  IL_11B7  ldloc 21
  IL_11BB  ldc.i4 0xc
  IL_11C0  ldloc 6
  IL_11C4  stelem.i1
  IL_11C5  ldloc 21
  IL_11C9  ldc.i4 0xc
  IL_11CE  ldc.i4 0xa1
  IL_11D3  ldc.i4 0x35
  IL_11D8  sub
  IL_11D9  stelem.i1
  IL_11DA  ldloc 21
  IL_11DE  ldc.i4 0xc
  IL_11E3  ldc.i4 0x76
  IL_11E8  ldc.i4 0x16
  IL_11ED  add
  IL_11EE  stelem.i1
  IL_11EF  ldc.i4 0xfc
  IL_11F4  ldc.i4 0x54
  IL_11F9  sub
  IL_11FA  stloc 6
  IL_11FE  ldloc 21
  IL_1202  ldc.i4 0xc
  IL_1207  ldloc 6
  IL_120B  stelem.i1
  IL_120C  ldloc 21
  IL_1210  ldc.i4 0xc
  IL_1215  ldc.i4 0xde
  IL_121A  ldc.i4 0x4a
  IL_121F  sub
  IL_1220  stelem.i1
  IL_1221  ldc.i4 0xd0
  IL_1226  ldc.i4 0x2c
  IL_122B  add
  IL_122C  stloc 6
  IL_1230  ldloc 21
  IL_1234  ldc.i4 0xc
  IL_1239  ldloc 6
  IL_123D  stelem.i1
  IL_123E  ldloc 21
  IL_1242  ldc.i4 0xd
  IL_1247  ldc.i4 0x37
  IL_124C  ldc.i4 0x6d
  IL_1251  add
  IL_1252  stelem.i1
  IL_1253  ldc.i4 0xa8
  IL_1258  ldc.i4 0x38
  IL_125D  sub
  IL_125E  stloc 6
  IL_1262  ldloc 21
  IL_1266  ldc.i4 0xd
  IL_126B  ldloc 6
  IL_126F  stelem.i1
  IL_1270  ldc.i4 0xe6
  IL_1275  ldc.i4 0x4c
  IL_127A  sub
  IL_127B  stloc 14
  IL_127F  ldloc 21
  IL_1283  ldc.i4 0xd
  IL_1288  ldloc 14
  IL_128C  stelem.i1
  IL_128D  ldloc 21
  IL_1291  ldc.i4 0xd
  IL_1296  ldc.i4 0x42
  IL_129B  ldc.i4 0x21
  IL_12A0  add
  IL_12A1  stelem.i1
  IL_12A2  ldloc 21
  IL_12A6  ldc.i4 0xd
  IL_12AB  ldc.i4 0x43
  IL_12B0  ldc.i4 0x6c
  IL_12B5  add
  IL_12B6  stelem.i1
  IL_12B7  ldloc 21
  IL_12BB  ldc.i4 0xd
  IL_12C0  ldc.i4 0x4e
  IL_12C5  ldc.i4 0x42
  IL_12CA  add
  IL_12CB  stelem.i1
  IL_12CC  ldc.i4 0x5f
  IL_12D1  ldc.i4 0x42
  IL_12D6  add
  IL_12D7  stloc 6
  IL_12DB  ldloc 21
  IL_12DF  ldc.i4 0xe
  IL_12E4  ldloc 6
  IL_12E8  stelem.i1
  IL_12E9  ldloc 21
  IL_12ED  ldc.i4 0xe
  IL_12F2  ldc.i4 0x31
  IL_12F7  ldc.i4 0x4
  IL_12FC  add
  IL_12FD  stelem.i1
  IL_12FE  ldloc 21
  IL_1302  ldc.i4 0xe
  IL_1307  ldc.i4 0xaf
  IL_130C  ldc.i4 0x3a
  IL_1311  sub
  IL_1312  stelem.i1
  IL_1313  ldloc 21
  IL_1317  ldc.i4 0xe
  IL_131C  ldc.i4 0x91
  IL_1321  ldc.i4 0x30
  IL_1326  sub
  IL_1327  stelem.i1
  IL_1328  ldc.i4 0xd1
  IL_132D  ldc.i4 0x45
  IL_1332  sub
  IL_1333  stloc 14
  IL_1337  ldloc 21
  IL_133B  ldc.i4 0xe
  IL_1340  ldloc 14
  IL_1344  stelem.i1
  IL_1345  ldc.i4 0x6a
  IL_134A  ldc.i4 0x64
  IL_134F  add
  IL_1350  stloc 14
  IL_1354  ldloc 21
  IL_1358  ldc.i4 0xe
  IL_135D  ldloc 14
  IL_1361  stelem.i1
  IL_1362  ldloc 21
  IL_1366  ldc.i4 0xf
  IL_136B  ldc.i4 0x8c
  IL_1370  ldc.i4 0x2e
  IL_1375  sub
  IL_1376  stelem.i1
  IL_1377  ldloc 21
  IL_137B  ldc.i4 0xf
  IL_1380  ldc.i4 0x17
  IL_1385  ldc.i4 0x39
  IL_138A  add
  IL_138B  stelem.i1
  IL_138C  ldloc 21
  IL_1390  ldc.i4 0xf
  IL_1395  ldc.i4 0xe0
  IL_139A  ldc.i4 0x4a
  IL_139F  sub
  IL_13A0  stelem.i1
  IL_13A1  ldloc 21
  IL_13A5  ldc.i4 0xf
  IL_13AA  ldc.i4 0xca
  IL_13AF  ldc.i4 0x43
  IL_13B4  sub
  IL_13B5  stelem.i1
  IL_13B6  ldloc 21
  IL_13BA  ldc.i4 0xf
  IL_13BF  ldc.i4 0x60
  IL_13C4  ldc.i4 0x36
  IL_13C9  sub
  IL_13CA  stelem.i1
  IL_13CB  ldloc 21
  IL_13CF  ldc.i4 0x10
  IL_13D4  ldc.i4 0x26
  IL_13D9  ldc.i4 0x20
  IL_13DE  add
  IL_13DF  stelem.i1
  IL_13E0  ldloc 21
  IL_13E4  ldc.i4 0x10
  IL_13E9  ldc.i4 0xf6
  IL_13EE  ldc.i4 0x52
  IL_13F3  sub
  IL_13F4  stelem.i1
  IL_13F5  ldloc 21
  IL_13F9  ldc.i4 0x10
  IL_13FE  ldc.i4 0xca
  IL_1403  ldc.i4 0x3
  IL_1408  add
  IL_1409  stelem.i1
  IL_140A  ldloc 21
  IL_140E  ldc.i4 0x11
  IL_1413  ldc.i4 0xa
  IL_1418  ldc.i4 0x2e
  IL_141D  add
  IL_141E  stelem.i1
  IL_141F  ldc.i4 0xae
  IL_1424  ldc.i4 0x3a
  IL_1429  sub
  IL_142A  stloc 14
  IL_142E  ldloc 21
  IL_1432  ldc.i4 0x11
  IL_1437  ldloc 14
  IL_143B  stelem.i1
  IL_143C  ldloc 21
  IL_1440  ldc.i4 0x11
  IL_1445  ldc.i4 0x5f
  IL_144A  ldc.i4 0x26
  IL_144F  sub
  IL_1450  stelem.i1
  IL_1451  ldloc 21
  IL_1455  ldc.i4 0x12
  IL_145A  ldc.i4 0xd8
  IL_145F  ldc.i4 0x48
  IL_1464  sub
  IL_1465  stelem.i1
  IL_1466  ldc.i4 0x66
  IL_146B  ldc.i4 0x5a
  IL_1470  add
  IL_1471  stloc 14
  IL_1475  ldloc 21
  IL_1479  ldc.i4 0x12
  IL_147E  ldloc 14
  IL_1482  stelem.i1
  IL_1483  ldloc 21
  IL_1487  ldc.i4 0x12
  IL_148C  ldc.i4 0x4e
  IL_1491  ldc.i4 0xf
  IL_1496  add
  IL_1497  stelem.i1
  IL_1498  ldloc 21
  IL_149C  ldc.i4 0x12
  IL_14A1  ldc.i4 0x18
  IL_14A6  ldc.i4 0x57
  IL_14AB  add
  IL_14AC  stelem.i1
  IL_14AD  ldc.i4 0x23
  IL_14B2  ldc.i4 0x2f
  IL_14B7  add
  IL_14B8  stloc 6
  IL_14BC  ldloc 21
  IL_14C0  ldc.i4 0x12
  IL_14C5  ldloc 6
  IL_14C9  stelem.i1
  IL_14CA  ldc.i4 0x94
  IL_14CF  ldc.i4 0x6b
  IL_14D4  sub
  IL_14D5  stloc 6
  IL_14D9  ldloc 21
  IL_14DD  ldc.i4 0x12
  IL_14E2  ldloc 6
  IL_14E6  stelem.i1
  IL_14E7  ldc.i4 0x85
  IL_14EC  ldc.i4 0x2c
  IL_14F1  sub
  IL_14F2  stloc 14
  IL_14F6  ldloc 21
  IL_14FA  ldc.i4 0x13
  IL_14FF  ldloc 14
  IL_1503  stelem.i1
  IL_1504  ldloc 21
  IL_1508  ldc.i4 0x13
  IL_150D  ldc.i4 0xda
  IL_1512  ldc.i4 0x48
  IL_1517  sub
  IL_1518  stelem.i1
  IL_1519  ldc.i4 0xb0
  IL_151E  ldc.i4 0x27
  IL_1523  add
  IL_1524  stloc 14
  IL_1528  ldloc 21
  IL_152C  ldc.i4 0x13
  IL_1531  ldloc 14
  IL_1535  stelem.i1
  IL_1536  ldloc 21
  IL_153A  ldc.i4 0x14
  IL_153F  ldc.i4 0xea
  IL_1544  ldc.i4 0x4e
  IL_1549  sub
  IL_154A  stelem.i1
  IL_154B  ldc.i4 0xdb
  IL_1550  ldc.i4 0x49
  IL_1555  sub
  IL_1556  stloc 6
  IL_155A  ldloc 21
  IL_155E  ldc.i4 0x14
  IL_1563  ldloc 6
  IL_1567  stelem.i1
  IL_1568  ldloc 21
  IL_156C  ldc.i4 0x14
  IL_1571  ldc.i4 0x16
  IL_1576  ldc.i4 0x54
  IL_157B  add
  IL_157C  stelem.i1
  IL_157D  ldloc 21
  IL_1581  ldc.i4 0x14
  IL_1586  ldc.i4 0xc1
  IL_158B  ldc.i4 0x40
  IL_1590  sub
  IL_1591  stelem.i1
  IL_1592  ldc.i4 0x92
  IL_1597  ldc.i4 0x33
  IL_159C  add
  IL_159D  stloc 14
  IL_15A1  ldloc 21
  IL_15A5  ldc.i4 0x14
  IL_15AA  ldloc 14
  IL_15AE  stelem.i1
  IL_15AF  ldloc 21
  IL_15B3  ldc.i4 0x15
  IL_15B8  ldc.i4 0x11
  IL_15BD  ldc.i4 0x1d
  IL_15C2  add
  IL_15C3  stelem.i1
  IL_15C4  ldc.i4 0xb0
  IL_15C9  ldc.i4 0x3a
  IL_15CE  sub
  IL_15CF  stloc 6
  IL_15D3  ldloc 21
  IL_15D7  ldc.i4 0x15
  IL_15DC  ldloc 6
  IL_15E0  stelem.i1
  IL_15E1  ldloc 21
  IL_15E5  ldc.i4 0x15
  IL_15EA  ldc.i4 0xda
  IL_15EF  ldc.i4 0x48
  IL_15F4  sub
  IL_15F5  stelem.i1
  IL_15F6  ldloc 21
  IL_15FA  ldc.i4 0x15
  IL_15FF  ldc.i4 0xcc
  IL_1604  ldc.i4 0x44
  IL_1609  sub
  IL_160A  stelem.i1
  IL_160B  ldc.i4 0x9c
  IL_1610  ldc.i4 0x34
  IL_1615  sub
  IL_1616  stloc 14
  IL_161A  ldloc 21
  IL_161E  ldc.i4 0x15
  IL_1623  ldloc 14
  IL_1627  stelem.i1
  IL_1628  ldc.i4 0x7e
  IL_162D  ldc.i4 0x19
  IL_1632  sub
  IL_1633  stloc 14
  IL_1637  ldloc 21
  IL_163B  ldc.i4 0x15
  IL_1640  ldloc 14
  IL_1644  stelem.i1
  IL_1645  ldloc 21
  IL_1649  ldc.i4 0x16
  IL_164E  ldc.i4 0xec
  IL_1653  ldc.i4 0x4e
  IL_1658  sub
  IL_1659  stelem.i1
  IL_165A  ldc.i4 0xa2
  IL_165F  ldc.i4 0x36
  IL_1664  sub
  IL_1665  stloc 6
  IL_1669  ldloc 21
  IL_166D  ldc.i4 0x16
  IL_1672  ldloc 6
  IL_1676  stelem.i1
  IL_1677  ldc.i4 0x56
  IL_167C  ldc.i4 0x22
  IL_1681  add
  IL_1682  stloc 6
  IL_1686  ldloc 21
  IL_168A  ldc.i4 0x16
  IL_168F  ldloc 6
  IL_1693  stelem.i1
  IL_1694  ldloc 21
  IL_1698  ldc.i4 0x16
  IL_169D  ldc.i4 0x8c
  IL_16A2  ldc.i4 0x2e
  IL_16A7  sub
  IL_16A8  stelem.i1
  IL_16A9  ldc.i4 0xc0
  IL_16AE  ldc.i4 0x40
  IL_16B3  sub
  IL_16B4  stloc 6
  IL_16B8  ldloc 21
  IL_16BC  ldc.i4 0x16
  IL_16C1  ldloc 6
  IL_16C5  stelem.i1
  IL_16C6  ldc.i4 0x57
  IL_16CB  ldc.i4 0x37
  IL_16D0  sub
  IL_16D1  stloc 6
  IL_16D5  ldloc 21
  IL_16D9  ldc.i4 0x16
  IL_16DE  ldloc 6
  IL_16E2  stelem.i1
  IL_16E3  ldloc 21
  IL_16E7  ldc.i4 0x17
  IL_16EC  ldc.i4 0x7
  IL_16F1  ldc.i4 0x1b
  IL_16F6  add
  IL_16F7  stelem.i1
  IL_16F8  ldloc 21
  IL_16FC  ldc.i4 0x17
  IL_1701  ldc.i4 0xc0
  IL_1706  ldc.i4 0x40
  IL_170B  sub
  IL_170C  stelem.i1
  IL_170D  ldc.i4 0x7f
  IL_1712  ldc.i4 0x2a
  IL_1717  sub
  IL_1718  stloc 14
  IL_171C  ldloc 21
  IL_1720  ldc.i4 0x17
  IL_1725  ldloc 14
  IL_1729  stelem.i1
  IL_172A  ldloc 21
  IL_172E  ldc.i4 0x17
  IL_1733  ldc.i4 0x50
  IL_1738  ldc.i4 0x6c
  IL_173D  add
  IL_173E  stelem.i1
  IL_173F  ldloc 21
  IL_1743  ldc.i4 0x18
  IL_1748  ldc.i4 0xb5
  IL_174D  ldc.i4 0x3c
  IL_1752  sub
  IL_1753  stelem.i1
  IL_1754  ldc.i4 0xf
  IL_1759  ldc.i4 0x79
  IL_175E  add
  IL_175F  stloc 14
  IL_1763  ldloc 21
  IL_1767  ldc.i4 0x18
  IL_176C  ldloc 14
  IL_1770  stelem.i1
  IL_1771  ldloc 21
  IL_1775  ldc.i4 0x18
  IL_177A  ldc.i4 0x52
  IL_177F  ldc.i4 0x50
  IL_1784  add
  IL_1785  stelem.i1
  IL_1786  ldloc 21
  IL_178A  ldc.i4 0x18
  IL_178F  ldc.i4 0xbc
  IL_1794  ldc.i4 0x3e
  IL_1799  sub
  IL_179A  stelem.i1
  IL_179B  ldc.i4 0xc8
  IL_17A0  ldc.i4 0x0
  IL_17A5  add
  IL_17A6  stloc 6
  IL_17AA  ldloc 21
  IL_17AE  ldc.i4 0x18
  IL_17B3  ldloc 6
  IL_17B7  stelem.i1
  IL_17B8  ldloc 21
  IL_17BC  ldc.i4 0x19
  IL_17C1  ldc.i4 0xc5
  IL_17C6  ldc.i4 0x41
  IL_17CB  sub
  IL_17CC  stelem.i1
  IL_17CD  ldloc 21
  IL_17D1  ldc.i4 0x19
  IL_17D6  ldc.i4 0x50
  IL_17DB  ldc.i4 0x2e
  IL_17E0  add
  IL_17E1  stelem.i1
  IL_17E2  ldc.i4 0xa6
  IL_17E7  ldc.i4 0x37
  IL_17EC  sub
  IL_17ED  stloc 6
  IL_17F1  ldloc 21
  IL_17F5  ldc.i4 0x19
  IL_17FA  ldloc 6
  IL_17FE  stelem.i1
  IL_17FF  ldc.i4 0x33
  IL_1804  ldc.i4 0x6a
  IL_1809  add
  IL_180A  stloc 14
  IL_180E  ldloc 21
  IL_1812  ldc.i4 0x19
  IL_1817  ldloc 14
  IL_181B  stelem.i1
  IL_181C  ldc.i4 0xd5
  IL_1821  ldc.i4 0x47
  IL_1826  sub
  IL_1827  stloc 6
  IL_182B  ldloc 21
  IL_182F  ldc.i4 0x1a
  IL_1834  ldloc 6
  IL_1838  stelem.i1
  IL_1839  ldc.i4 0x8d
  IL_183E  ldc.i4 0x2f
  IL_1843  sub
  IL_1844  stloc 6
  IL_1848  ldloc 21
  IL_184C  ldc.i4 0x1a
  IL_1851  ldloc 6
  IL_1855  stelem.i1
  IL_1856  ldc.i4 0x74
  IL_185B  ldc.i4 0x58
  IL_1860  sub
  IL_1861  stloc 14
  IL_1865  ldloc 21
  IL_1869  ldc.i4 0x1a
  IL_186E  ldloc 14
  IL_1872  stelem.i1
  IL_1873  ldloc 21
  IL_1877  ldc.i4 0x1b
  IL_187C  ldc.i4 0x6c
  IL_1881  ldc.i4 0x6c
  IL_1886  add
  IL_1887  stelem.i1
  IL_1888  ldc.i4 0x35
  IL_188D  ldc.i4 0x68
  IL_1892  add
  IL_1893  stloc 14
  IL_1897  ldloc 21
  IL_189B  ldc.i4 0x1b
  IL_18A0  ldloc 14
  IL_18A4  stelem.i1
  IL_18A5  ldc.i4 0x36
  IL_18AA  ldc.i4 0x10
  IL_18AF  sub
  IL_18B0  stloc 6
  IL_18B4  ldloc 21
  IL_18B8  ldc.i4 0x1b
  IL_18BD  ldloc 6
  IL_18C1  stelem.i1
  IL_18C2  ldc.i4 0x50
  IL_18C7  ldc.i4 0x5f
  IL_18CC  add
  IL_18CD  stloc 6
  IL_18D1  ldloc 21
  IL_18D5  ldc.i4 0x1c
  IL_18DA  ldloc 6
  IL_18DE  stelem.i1
  IL_18DF  ldc.i4 0x47
  IL_18E4  ldc.i4 0x34
  IL_18E9  add
  IL_18EA  stloc 14
  IL_18EE  ldloc 21
  IL_18F2  ldc.i4 0x1c
  IL_18F7  ldloc 14
  IL_18FB  stelem.i1
  IL_18FC  ldloc 21
  IL_1900  ldc.i4 0x1c
  IL_1905  ldc.i4 0xfc
  IL_190A  ldc.i4 0x54
  IL_190F  sub
  IL_1910  stelem.i1
  IL_1911  ldc.i4 0xbd
  IL_1916  ldc.i4 0x3f
  IL_191B  sub
  IL_191C  stloc 14
  IL_1920  ldloc 21
  IL_1924  ldc.i4 0x1c
  IL_1929  ldloc 14
  IL_192D  stelem.i1
  IL_192E  ldloc 21
  IL_1932  ldc.i4 0x1c
  IL_1937  ldc.i4 0x8a
  IL_193C  ldc.i4 0x2e
  IL_1941  sub
  IL_1942  stelem.i1
  IL_1943  ldloc 21
  IL_1947  ldc.i4 0x1c
  IL_194C  ldc.i4 0xb3
  IL_1951  ldc.i4 0x3a
  IL_1956  add
  IL_1957  stelem.i1
  IL_1958  ldc.i4 0x3e
  IL_195D  ldc.i4 0x66
  IL_1962  add
  IL_1963  stloc 6
  IL_1967  ldloc 21
  IL_196B  ldc.i4 0x1d
  IL_1970  ldloc 6
  IL_1974  stelem.i1
  IL_1975  ldc.i4 0x11
  IL_197A  ldc.i4 0x65
  IL_197F  add
  IL_1980  stloc 6
  IL_1984  ldloc 21
  IL_1988  ldc.i4 0x1d
  IL_198D  ldloc 6
  IL_1991  stelem.i1
  IL_1992  ldc.i4 0x9f
  IL_1997  ldc.i4 0x2c
  IL_199C  add
  IL_199D  stloc 14
  IL_19A1  ldloc 21
  IL_19A5  ldc.i4 0x1d
  IL_19AA  ldloc 14
  IL_19AE  stelem.i1
  IL_19AF  ldloc 21
  IL_19B3  ldc.i4 0x1e
  IL_19B8  ldc.i4 0x42
  IL_19BD  ldc.i4 0x9
  IL_19C2  add
  IL_19C3  stelem.i1
  IL_19C4  ldc.i4 0xdb
  IL_19C9  ldc.i4 0x49
  IL_19CE  sub
  IL_19CF  stloc 6
  IL_19D3  ldloc 21
  IL_19D7  ldc.i4 0x1e
  IL_19DC  ldloc 6
  IL_19E0  stelem.i1
  IL_19E1  ldc.i4 0xf9
  IL_19E6  ldc.i4 0x53
  IL_19EB  sub
  IL_19EC  stloc 6
  IL_19F0  ldloc 21
  IL_19F4  ldc.i4 0x1e
  IL_19F9  ldloc 6
  IL_19FD  stelem.i1
  IL_19FE  ldloc 21
  IL_1A02  ldc.i4 0x1e
  IL_1A07  ldc.i4 0x46
  IL_1A0C  ldc.i4 0x3b
  IL_1A11  add
  IL_1A12  stelem.i1
  IL_1A13  ldc.i4 0x7a
  IL_1A18  ldc.i4 0x76
  IL_1A1D  add
  IL_1A1E  stloc 6
  IL_1A22  ldloc 21
  IL_1A26  ldc.i4 0x1f
  IL_1A2B  ldloc 6
  IL_1A2F  stelem.i1
  IL_1A30  ldc.i4 0x57
  IL_1A35  ldc.i4 0x6e
  IL_1A3A  add
  IL_1A3B  stloc 14
  IL_1A3F  ldloc 21
  IL_1A43  ldc.i4 0x1f
  IL_1A48  ldloc 14
  IL_1A4C  stelem.i1
  IL_1A4D  ldc.i4 0x7
  IL_1A52  ldc.i4 0x38
  IL_1A57  add
  IL_1A58  stloc 6
  IL_1A5C  ldloc 21
  IL_1A60  ldc.i4 0x1f
  IL_1A65  ldloc 6
  IL_1A69  stelem.i1
  IL_1A6A  ldloc 21
  IL_1A6E  ldc.i4 0x1f
  IL_1A73  ldc.i4 0x47
  IL_1A78  ldc.i4 0x6c
  IL_1A7D  add
  IL_1A7E  stelem.i1
  IL_1A7F  ldloc 21
  IL_1A83  ldc.i4 0x1f
  IL_1A88  ldc.i4 0xeb
  IL_1A8D  ldc.i4 0x4e
  IL_1A92  sub
  IL_1A93  stelem.i1
  IL_1A94  ldloc 21
  IL_1A98  ldc.i4 0x1f
  IL_1A9D  ldc.i4 0x66
  IL_1AA2  ldc.i4 0x58
  IL_1AA7  sub
  IL_1AA8  stelem.i1
  IL_1AA9  ldloc 21
  IL_1AAD  stloc.s 0x10
  IL_1AAF  ldc.i4 0x10
  IL_1AB4  newarr 0x100005b   ; TypeRef:System.Byte
  IL_1AB9  stloc 1
  IL_1ABD  ldloc 1
  IL_1AC1  ldc.i4 0x0
  IL_1AC6  ldc.i4 0x7
  IL_1ACB  ldc.i4 0x25
  IL_1AD0  add
  IL_1AD1  stelem.i1
  IL_1AD2  ldc.i4 0x6c
  IL_1AD7  ldc.i4 0x21
  IL_1ADC  add
  IL_1ADD  stloc 15
  IL_1AE1  ldloc 1
  IL_1AE5  ldc.i4 0x0
  IL_1AEA  ldloc 15
  IL_1AEE  stelem.i1
  IL_1AEF  ldc.i4 0x64
  IL_1AF4  ldc.i4 0x19
  IL_1AF9  add
  IL_1AFA  stloc 15
  IL_1AFE  ldloc 1
  IL_1B02  ldc.i4 0x0
  IL_1B07  ldloc 15
  IL_1B0B  stelem.i1
  IL_1B0C  ldloc 1
  IL_1B10  ldc.i4 0x0
  IL_1B15  ldc.i4 0x9e
  IL_1B1A  ldc.i4 0x34
  IL_1B1F  sub
  IL_1B20  stelem.i1
  IL_1B21  ldloc 1
  IL_1B25  ldc.i4 0x0
  IL_1B2A  ldc.i4 0x76
  IL_1B2F  ldc.i4 0x4c
  IL_1B34  add
  IL_1B35  stelem.i1
  IL_1B36  ldloc 1
  IL_1B3A  ldc.i4 0x0
  IL_1B3F  ldc.i4 0xb2
  IL_1B44  ldc.i4 0x4a
  IL_1B49  add
  IL_1B4A  stelem.i1
  IL_1B4B  ldc.i4 0x11
  IL_1B50  ldc.i4 0x37
  IL_1B55  add
  IL_1B56  stloc 15
  IL_1B5A  ldloc 1
  IL_1B5E  ldc.i4 0x1
  IL_1B63  ldloc 15
  IL_1B67  stelem.i1
  IL_1B68  ldc.i4 0xdf
  IL_1B6D  ldc.i4 0x4a
  IL_1B72  sub
  IL_1B73  stloc 15
  IL_1B77  ldloc 1
  IL_1B7B  ldc.i4 0x1
  IL_1B80  ldloc 15
  IL_1B84  stelem.i1
  IL_1B85  ldloc 1
  IL_1B89  ldc.i4 0x1
  IL_1B8E  ldc.i4 0x1a
  IL_1B93  ldc.i4 0x60
  IL_1B98  add
  IL_1B99  stelem.i1
  IL_1B9A  ldloc 1
  IL_1B9E  ldc.i4 0x1
  IL_1BA3  ldc.i4 0xbb
  IL_1BA8  ldc.i4 0x3e
  IL_1BAD  sub
  IL_1BAE  stelem.i1
  IL_1BAF  ldloc 1
  IL_1BB3  ldc.i4 0x1
  IL_1BB8  ldc.i4 0xb1
  IL_1BBD  ldc.i4 0x3b
  IL_1BC2  sub
  IL_1BC3  stelem.i1
  IL_1BC4  ldloc 1
  IL_1BC8  ldc.i4 0x1
  IL_1BCD  ldc.i4 0xaa
  IL_1BD2  ldc.i4 0x30
  IL_1BD7  sub
  IL_1BD8  stelem.i1
  IL_1BD9  ldc.i4 0xd5
  IL_1BDE  ldc.i4 0x47
  IL_1BE3  sub
  IL_1BE4  stloc 15
  IL_1BE8  ldloc 1
  IL_1BEC  ldc.i4 0x2
  IL_1BF1  ldloc 15
  IL_1BF5  stelem.i1
  IL_1BF6  ldloc 1
  IL_1BFA  ldc.i4 0x2
  IL_1BFF  ldc.i4 0x55
  IL_1C04  ldc.i4 0x65
  IL_1C09  add
  IL_1C0A  stelem.i1
  IL_1C0B  ldloc 1
  IL_1C0F  ldc.i4 0x2
  IL_1C14  ldc.i4 0xd8
  IL_1C19  ldc.i4 0x48
  IL_1C1E  sub
  IL_1C1F  stelem.i1
  IL_1C20  ldc.i4 0x18
  IL_1C25  ldc.i4 0x43
  IL_1C2A  add
  IL_1C2B  stloc 15
  IL_1C2F  ldloc 1
  IL_1C33  ldc.i4 0x2
  IL_1C38  ldloc 15
  IL_1C3C  stelem.i1
  IL_1C3D  ldloc 1
  IL_1C41  ldc.i4 0x2
  IL_1C46  ldc.i4 0xcb
  IL_1C4B  ldc.i4 0x17
  IL_1C50  add
  IL_1C51  stelem.i1
  IL_1C52  ldloc 1
  IL_1C56  ldc.i4 0x3
  IL_1C5B  ldc.i4 0x9d
  IL_1C60  ldc.i4 0x34
  IL_1C65  sub
  IL_1C66  stelem.i1
  IL_1C67  ldc.i4 0x3
  IL_1C6C  ldc.i4 0x79
  IL_1C71  add
  IL_1C72  stloc 15
  IL_1C76  ldloc 1
  IL_1C7A  ldc.i4 0x3
  IL_1C7F  ldloc 15
  IL_1C83  stelem.i1
  IL_1C84  ldloc 1
  IL_1C88  ldc.i4 0x3
  IL_1C8D  ldc.i4 0x3d
  IL_1C92  ldc.i4 0x46
  IL_1C97  add
  IL_1C98  stelem.i1
  IL_1C99  ldloc 1
  IL_1C9D  ldc.i4 0x3
  IL_1CA2  ldc.i4 0x60
  IL_1CA7  ldc.i4 0x69
  IL_1CAC  add
  IL_1CAD  stelem.i1
  IL_1CAE  ldloc 1
  IL_1CB2  ldc.i4 0x3
  IL_1CB7  ldc.i4 0xb8
  IL_1CBC  ldc.i4 0x2e
  IL_1CC1  add
  IL_1CC2  stelem.i1
  IL_1CC3  ldc.i4 0x22
  IL_1CC8  ldc.i4 0x18
  IL_1CCD  add
  IL_1CCE  stloc 15
  IL_1CD2  ldloc 1
  IL_1CD6  ldc.i4 0x4
  IL_1CDB  ldloc 15
  IL_1CDF  stelem.i1
  IL_1CE0  ldloc 1
  IL_1CE4  ldc.i4 0x4
  IL_1CE9  ldc.i4 0xaa
  IL_1CEE  ldc.i4 0x38
  IL_1CF3  sub
  IL_1CF4  stelem.i1
  IL_1CF5  ldc.i4 0x97
  IL_1CFA  ldc.i4 0x6c
  IL_1CFF  sub
  IL_1D00  stloc 15
  IL_1D04  ldloc 1
  IL_1D08  ldc.i4 0x4
  IL_1D0D  ldloc 15
  IL_1D11  stelem.i1
  IL_1D12  ldloc 1
  IL_1D16  ldc.i4 0x5
  IL_1D1B  ldc.i4 0x1d
  IL_1D20  ldc.i4 0x32
  IL_1D25  add
  IL_1D26  stelem.i1
  IL_1D27  ldc.i4 0xc1
  IL_1D2C  ldc.i4 0x40
  IL_1D31  sub
  IL_1D32  stloc 15
  IL_1D36  ldloc 1
  IL_1D3A  ldc.i4 0x5
  IL_1D3F  ldloc 15
  IL_1D43  stelem.i1
  IL_1D44  ldloc 1
  IL_1D48  ldc.i4 0x5
  IL_1D4D  ldc.i4 0x5a
  IL_1D52  ldc.i4 0x1a
  IL_1D57  add
  IL_1D58  stelem.i1
  IL_1D59  ldc.i4 0xb6
  IL_1D5E  ldc.i4 0x3c
  IL_1D63  sub
  IL_1D64  stloc 15
  IL_1D68  ldloc 1
  IL_1D6C  ldc.i4 0x5
  IL_1D71  ldloc 15
  IL_1D75  stelem.i1
  IL_1D76  ldloc 1
  IL_1D7A  ldc.i4 0x5
  IL_1D7F  ldc.i4 0x69
  IL_1D84  ldc.i4 0x5a
  IL_1D89  sub
  IL_1D8A  stelem.i1
  IL_1D8B  ldc.i4 0x36
  IL_1D90  ldc.i4 0x54
  IL_1D95  add
  IL_1D96  stloc 15
  IL_1D9A  ldloc 1
  IL_1D9E  ldc.i4 0x6
  IL_1DA3  ldloc 15
  IL_1DA7  stelem.i1
  IL_1DA8  ldloc 1
  IL_1DAC  ldc.i4 0x6
  IL_1DB1  ldc.i4 0x1f
  IL_1DB6  ldc.i4 0x55
  IL_1DBB  add
  IL_1DBC  stelem.i1
  IL_1DBD  ldloc 1
  IL_1DC1  ldc.i4 0x6
  IL_1DC6  ldc.i4 0x7a
  IL_1DCB  ldc.i4 0x65
  IL_1DD0  add
  IL_1DD1  stelem.i1
  IL_1DD2  ldloc 1
  IL_1DD6  ldc.i4 0x7
  IL_1DDB  ldc.i4 0x72
  IL_1DE0  ldc.i4 0x3d
  IL_1DE5  add
  IL_1DE6  stelem.i1
  IL_1DE7  ldloc 1
  IL_1DEB  ldc.i4 0x7
  IL_1DF0  ldc.i4 0x10
  IL_1DF5  ldc.i4 0x6
  IL_1DFA  add
  IL_1DFB  stelem.i1
  IL_1DFC  ldloc 1
  IL_1E00  ldc.i4 0x7
  IL_1E05  ldc.i4 0x9b
  IL_1E0A  ldc.i4 0x53
  IL_1E0F  sub
  IL_1E10  stelem.i1
  IL_1E11  ldloc 1
  IL_1E15  ldc.i4 0x8
  IL_1E1A  ldc.i4 0x3e
  IL_1E1F  ldc.i4 0x54
  IL_1E24  add
  IL_1E25  stelem.i1
  IL_1E26  ldc.i4 0x77
  IL_1E2B  ldc.i4 0x6a
  IL_1E30  add
  IL_1E31  stloc 15
  IL_1E35  ldloc 1
  IL_1E39  ldc.i4 0x8
  IL_1E3E  ldloc 15
  IL_1E42  stelem.i1
  IL_1E43  ldc.i4 0xb6
  IL_1E48  ldc.i4 0x3c
  IL_1E4D  sub
  IL_1E4E  stloc 15
  IL_1E52  ldloc 1
  IL_1E56  ldc.i4 0x8
  IL_1E5B  ldloc 15
  IL_1E5F  stelem.i1
  IL_1E60  ldloc 1
  IL_1E64  ldc.i4 0x8
  IL_1E69  ldc.i4 0x52
  IL_1E6E  ldc.i4 0x11
  IL_1E73  add
  IL_1E74  stelem.i1
  IL_1E75  ldloc 1
  IL_1E79  ldc.i4 0x8
  IL_1E7E  ldc.i4 0x87
  IL_1E83  ldc.i4 0x18
  IL_1E88  sub
  IL_1E89  stelem.i1
  IL_1E8A  ldloc 1
  IL_1E8E  ldc.i4 0x9
  IL_1E93  ldc.i4 0xf5
  IL_1E98  ldc.i4 0x51
  IL_1E9D  sub
  IL_1E9E  stelem.i1
  IL_1E9F  ldloc 1
  IL_1EA3  ldc.i4 0x9
  IL_1EA8  ldc.i4 0xa7
  IL_1EAD  ldc.i4 0x37
  IL_1EB2  sub
  IL_1EB3  stelem.i1
  IL_1EB4  ldc.i4 0x18
  IL_1EB9  ldc.i4 0x56
  IL_1EBE  add
  IL_1EBF  stloc 15
  IL_1EC3  ldloc 1
  IL_1EC7  ldc.i4 0x9
  IL_1ECC  ldloc 15
  IL_1ED0  stelem.i1
  IL_1ED1  ldloc 1
  IL_1ED5  ldc.i4 0x9
  IL_1EDA  ldc.i4 0xae
  IL_1EDF  ldc.i4 0x3a
  IL_1EE4  sub
  IL_1EE5  stelem.i1
  IL_1EE6  ldc.i4 0xa8
  IL_1EEB  ldc.i4 0x38
  IL_1EF0  sub
  IL_1EF1  stloc 15
  IL_1EF5  ldloc 1
  IL_1EF9  ldc.i4 0x9
  IL_1EFE  ldloc 15
  IL_1F02  stelem.i1
  IL_1F03  ldc.i4 0x80
  IL_1F08  ldc.i4 0x46
  IL_1F0D  add
  IL_1F0E  stloc 15
  IL_1F12  ldloc 1
  IL_1F16  ldc.i4 0x9
  IL_1F1B  ldloc 15
  IL_1F1F  stelem.i1
  IL_1F20  ldc.i4 0xc6
  IL_1F25  ldc.i4 0x42
  IL_1F2A  sub
  IL_1F2B  stloc 15
  IL_1F2F  ldloc 1
  IL_1F33  ldc.i4 0xa
  IL_1F38  ldloc 15
  IL_1F3C  stelem.i1
  IL_1F3D  ldc.i4 0x79
  IL_1F42  ldc.i4 0x45
  IL_1F47  add
  IL_1F48  stloc 15
  IL_1F4C  ldloc 1
  IL_1F50  ldc.i4 0xa
  IL_1F55  ldloc 15
  IL_1F59  stelem.i1
  IL_1F5A  ldc.i4 0x2c
  IL_1F5F  ldc.i4 0x4b
  IL_1F64  add
  IL_1F65  stloc 15
  IL_1F69  ldloc 1
  IL_1F6D  ldc.i4 0xa
  IL_1F72  ldloc 15
  IL_1F76  stelem.i1
  IL_1F77  ldloc 1
  IL_1F7B  ldc.i4 0xa
  IL_1F80  ldc.i4 0x7c
  IL_1F85  ldc.i4 0x59
  IL_1F8A  sub
  IL_1F8B  stelem.i1
  IL_1F8C  ldc.i4 0xd6
  IL_1F91  ldc.i4 0x47
  IL_1F96  sub
  IL_1F97  stloc 15
  IL_1F9B  ldloc 1
  IL_1F9F  ldc.i4 0xb
  IL_1FA4  ldloc 15
  IL_1FA8  stelem.i1
  IL_1FA9  ldloc 1
  IL_1FAD  ldc.i4 0xb
  IL_1FB2  ldc.i4 0x49
  IL_1FB7  ldc.i4 0x78
  IL_1FBC  add
  IL_1FBD  stelem.i1
  IL_1FBE  ldloc 1
  IL_1FC2  ldc.i4 0xb
  IL_1FC7  ldc.i4 0xc4
  IL_1FCC  ldc.i4 0x41
  IL_1FD1  sub
  IL_1FD2  stelem.i1
  IL_1FD3  ldc.i4 0x7d
  IL_1FD8  ldc.i4 0x29
  IL_1FDD  sub
  IL_1FDE  stloc 15
  IL_1FE2  ldloc 1
  IL_1FE6  ldc.i4 0xb
  IL_1FEB  ldloc 15
  IL_1FEF  stelem.i1
  IL_1FF0  ldloc 1
  IL_1FF4  ldc.i4 0xb
  IL_1FF9  ldc.i4 0x7c
  IL_1FFE  ldc.i4 0x78
  IL_2003  sub
  IL_2004  stelem.i1
  IL_2005  ldc.i4 0xeb
  IL_200A  ldc.i4 0x4e
  IL_200F  sub
  IL_2010  stloc 15
  IL_2014  ldloc 1
  IL_2018  ldc.i4 0xc
  IL_201D  ldloc 15
  IL_2021  stelem.i1
  IL_2022  ldc.i4 0xcc
  IL_2027  ldc.i4 0x44
  IL_202C  sub
  IL_202D  stloc 15
  IL_2031  ldloc 1
  IL_2035  ldc.i4 0xc
  IL_203A  ldloc 15
  IL_203E  stelem.i1
  IL_203F  ldloc 1
  IL_2043  ldc.i4 0xc
  IL_2048  ldc.i4 0x50
  IL_204D  ldc.i4 0x31
  IL_2052  add
  IL_2053  stelem.i1
  IL_2054  ldloc 1
  IL_2058  ldc.i4 0xc
  IL_205D  ldc.i4 0x1b
  IL_2062  ldc.i4 0x47
  IL_2067  add
  IL_2068  stelem.i1
  IL_2069  ldc.i4 0x45
  IL_206E  ldc.i4 0x35
  IL_2073  sub
  IL_2074  stloc 15
  IL_2078  ldloc 1
  IL_207C  ldc.i4 0xc
  IL_2081  ldloc 15
  IL_2085  stelem.i1
  IL_2086  ldc.i4 0x1d
  IL_208B  ldc.i4 0x0
  IL_2090  add
  IL_2091  stloc 15
  IL_2095  ldloc 1
  IL_2099  ldc.i4 0xd
  IL_209E  ldloc 15
  IL_20A2  stelem.i1
  IL_20A3  ldc.i4 0xf2
  IL_20A8  ldc.i4 0x50
  IL_20AD  sub
  IL_20AE  stloc 15
  IL_20B2  ldloc 1
  IL_20B6  ldc.i4 0xd
  IL_20BB  ldloc 15
  IL_20BF  stelem.i1
  IL_20C0  ldc.i4 0xc0
  IL_20C5  ldc.i4 0x40
  IL_20CA  sub
  IL_20CB  stloc 15
  IL_20CF  ldloc 1
  IL_20D3  ldc.i4 0xd
  IL_20D8  ldloc 15
  IL_20DC  stelem.i1
  IL_20DD  ldc.i4 0x7c
  IL_20E2  ldc.i4 0x2d
  IL_20E7  add
  IL_20E8  stloc 15
  IL_20EC  ldloc 1
  IL_20F0  ldc.i4 0xd
  IL_20F5  ldloc 15
  IL_20F9  stelem.i1
  IL_20FA  ldloc 1
  IL_20FE  ldc.i4 0xe
  IL_2103  ldc.i4 0x2a
  IL_2108  ldc.i4 0xd
  IL_210D  add
  IL_210E  stelem.i1
  IL_210F  ldc.i4 0x95
  IL_2114  ldc.i4 0x31
  IL_2119  sub
  IL_211A  stloc 15
  IL_211E  ldloc 1
  IL_2122  ldc.i4 0xe
  IL_2127  ldloc 15
  IL_212B  stelem.i1
  IL_212C  ldloc 1
  IL_2130  ldc.i4 0xe
  IL_2135  ldc.i4 0x38
  IL_213A  ldc.i4 0x6f
  IL_213F  add
  IL_2140  stelem.i1
  IL_2141  ldloc 1
  IL_2145  ldc.i4 0xe
  IL_214A  ldc.i4 0xee
  IL_214F  ldc.i4 0x4f
  IL_2154  sub
  IL_2155  stelem.i1
  IL_2156  ldc.i4 0x29
  IL_215B  ldc.i4 0x1e
  IL_2160  sub
  IL_2161  stloc 15
  IL_2165  ldloc 1
  IL_2169  ldc.i4 0xe
  IL_216E  ldloc 15
  IL_2172  stelem.i1
  IL_2173  ldc.i4 0x60
  IL_2178  ldc.i4 0x66
  IL_217D  add
  IL_217E  stloc 15
  IL_2182  ldloc 1
  IL_2186  ldc.i4 0xf
  IL_218B  ldloc 15
  IL_218F  stelem.i1
  IL_2190  ldloc 1
  IL_2194  ldc.i4 0xf
  IL_2199  ldc.i4 0x4a
  IL_219E  ldc.i4 0x34
  IL_21A3  add
  IL_21A4  stelem.i1
  IL_21A5  ldloc 1
  IL_21A9  ldc.i4 0xf
  IL_21AE  ldc.i4 0x6d
  IL_21B3  ldc.i4 0x25
  IL_21B8  add
  IL_21B9  stelem.i1
  IL_21BA  ldloc 1
  IL_21BE  ldc.i4 0xf
  IL_21C3  ldc.i4 0xdd
  IL_21C8  ldc.i4 0x49
  IL_21CD  sub
  IL_21CE  stelem.i1
  IL_21CF  ldloc 1
  IL_21D3  ldc.i4 0xf
  IL_21D8  ldc.i4 0xa
  IL_21DD  ldc.i4 0x69
  IL_21E2  add
  IL_21E3  stelem.i1
  IL_21E4  ldloc 1
  IL_21E8  ldc.i4 0xf
  IL_21ED  ldc.i4 0x93
  IL_21F2  ldc.i4 0x1b
  IL_21F7  sub
  IL_21F8  stelem.i1
  IL_21F9  ldloc 1
  IL_21FD  stloc.s 0x5
  IL_21FF  call 0x60041d6   ; MethodDef:VerifyIsolatedState
  IL_2204  dup
  IL_2205  ldc.i4.1
  IL_2206  call 0x60041d7   ; MethodDef:VerifyTransferableRequest
  IL_220B  ldloc.s 0x10
  IL_220D  ldloc.s 0x5
  IL_220F  call 0x60041d8   ; MethodDef:VerifyConnectedWorker
  IL_2214  stloc.s 0xb
  IL_2216  call 0x60041d9   ; MethodDef:CheckSegmentedResponder
  IL_221B  stloc.s 0x1d
  IL_221D  ldloc.s 0x1d
  IL_221F  ldloc.s 0xb
  IL_2221  ldc.i4.1
  IL_2222  newobj 0xa00033a   ; MemberRef:System.Security.Cryptography.CryptoStream::.ctor
  IL_2227  dup
  IL_2228  ldloc.s 0x16
  IL_222A  ldc.i4.0
  IL_222B  ldloc.s 0x16
  IL_222D  ldlen
  IL_222E  conv.i4
  IL_222F  call 0x60041da   ; MethodDef:PopReceiver
  IL_2234  dup
  IL_2235  call 0x60041db   ; MethodDef:VerifyAdaptableDriver
  IL_223A  ldsfld 0x4001fcd   ; Field:1FCD
  IL_223F  call 0x60041dc   ; MethodDef:VerifyLogicalHandler
  IL_2244  ldloc.s 0x1d
  IL_2246  call 0x60041dd   ; MethodDef:CheckEfficientFormatter
  IL_224B  call 0x60041de   ; MethodDef:AwakeProcessor
  IL_2250  call 0x60041df   ; MethodDef:CheckConfigurableDistributor
  IL_2255  ldloc.s 0x1d
  IL_2257  call 0x60041e0   ; MethodDef:VerifySetListener
  IL_225C  call 0x60041e0   ; MethodDef:VerifySetListener
  IL_2261  call 0x60041e1   ; MethodDef:VerifyGroupedTokenizer
  IL_2266  br IL_226b
  IL_226B  nop
  IL_226C  ldc.i4 0x9
  IL_2271  stloc 31
  IL_2275  ldc.i4 0x46f3ad78
  IL_227A  stloc 0
  IL_227E  leave IL_0012
  IL_2283  pop
  IL_2284  br IL_2289
  IL_2289  ldc.i4.1
  IL_228A  stloc.s 0xc
  IL_228C  br IL_2291
  IL_2291  nop
  IL_2292  ldc.i4 0x9
  IL_2297  stloc 31
  IL_229B  ldc.i4 0x46f3ad78
  IL_22A0  stloc 0
  IL_22A4  leave IL_0012
  IL_22A9  newobj 0xa0009a5   ; MemberRef:System.Security.Cryptography.RSACryptoServiceProvider::.ctor
  IL_22AE  stsfld 0x4001fcd   ; Field:1FCD
  IL_22B3  ldloc 0
  IL_22B7  ldc.i4 0xe650d77f
  IL_22BC  add
  IL_22BD  stloc 31
  IL_22C1  ldloc 0
  IL_22C5  ldc.i4 0x39ac45bd
  IL_22CA  add
  IL_22CB  stloc 0
  IL_22CF  br IL_0012
  IL_22D4  ldloc.s 0x2
  IL_22D6  call 0x60041cd   ; MethodDef:CustomizeMatcher
  IL_22DB  ldloc 0
  IL_22DF  ldc.i4 0xbcb9b2cf
  IL_22E4  add
  IL_22E5  stloc 31
  IL_22E9  ldloc 0
  IL_22ED  ldc.i4 0x1d355e59
  IL_22F2  add
  IL_22F3  stloc 0
  IL_22F7  brtrue IL_0012
  IL_22FC  br IL_0bdf
  IL_2301  ldnull
  IL_2302  stloc.s 0x1a
  IL_2304  br IL_00fb
  IL_2309  ret
