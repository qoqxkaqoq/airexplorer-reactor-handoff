# token=06004194 rva=3FDA24 name=DefineActiveEvent source=dump_full grp=debugger
# {'ilsize': 22, 'maxstack': 8, 'eh': 0}
  IL_0000  call 0xa0009cb   ; MemberRef:System.Diagnostics.Debugger::get_IsAttached
  IL_0005  brfalse IL_0015
  IL_000A  ldstr 0x70000adc   ; ".Properties.Resources"
  IL_000F  newobj 0xa000252   ; MemberRef:System.Exception::.ctor
  IL_0014  throw
  IL_0015  ret
