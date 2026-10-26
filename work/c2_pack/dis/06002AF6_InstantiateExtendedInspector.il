# token=06002AF6 rva=2410DC name=InstantiateExtendedInspector source=dump_full grp=gfp
# {'ilsize': 61, 'maxstack': 6, 'eh': 0}
  IL_0000  ldc.i4.s 0x1a
  IL_0002  call 0xa000159   ; MemberRef:System.Environment::GetFolderPath
  IL_0007  ldsfld 0xa000125   ; MemberRef:System.IO.Path::DirectorySeparatorChar
  IL_000C  stloc.s 0x1
  IL_000E  ldloca.s 0x1
  IL_0010  ldsfld 0x40021c6   ; Field:21C6
  IL_0015  call 0x60048b0   ; MethodDef:ExecuteExplorer
  IL_001A  call 0x6002f52   ; MethodDef:ControlStruct
  IL_001F  ldsfld 0xa000125   ; MemberRef:System.IO.Path::DirectorySeparatorChar
  IL_0024  stloc.s 0x1
  IL_0026  ldloca.s 0x1
  IL_0028  ldsfld 0x40021c6   ; Field:21C6
  IL_002D  call 0x60048b0   ; MethodDef:ExecuteExplorer
  IL_0032  ldsfld 0x40021c8   ; Field:21C8
  IL_0037  call 0x60048b8   ; MethodDef:ExecuteExplorer
  IL_003C  ret
