0000|br.s|->0007
0002|call|
0007|newobj|System.Void AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::.ctor()
000C|stloc.0|
000D|call|System.Text.Encoding System.Text.Encoding::get_UTF8()
0012|call|System.Void System.Console::set_OutputEncoding(System.Text.Encoding)
0017|ldloca.s|V_1
0019|ldloca.s|V_2
001B|call|System.Boolean AirExplorerCmd.Core.CompressorObject::DestroyConnectedObject(System.Boolean&,System.DateTime&)
0020|stloc.3|
0021|ldarg.0|
0022|ldlen|
0023|conv.i4|
0024|ldc.i4.1|
0025|bne.un|->0052
002A|ldarg.0|
002B|ldc.i4.0|
002C|ldelem.ref|
002D|ldc.i4|608630644
0032|ldc.i4|2008666151
0037|xor|
0038|ldsfld|<Module>{883c023e-01b0-4701-9cfa-c85338d8f612} <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_f8cdd8c7f4b34d93a64e229e3ac6fced
003D|ldfld|System.Int32 <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_85e7c858505740898ac417369bdb679a
0042|xor|
0043|call|System.String AirExplorerCmd.Reporting.PassiveReporter::SetupReporter(System.Int32)
0048|call|System.Boolean System.String::op_Equality(System.String,System.String)
004D|br|->0053
0052|ldc.i4.0|
0053|brtrue|->0085
0058|ldloc.3|
0059|ldc.i4.0|
005A|ceq|
005C|ldloc.1|
005D|or|
005E|brfalse|->0085
0063|ldc.i4|-1531160698
0068|ldc.i4|-165486685
006D|xor|
006E|ldsfld|<Module>{883c023e-01b0-4701-9cfa-c85338d8f612} <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_f8cdd8c7f4b34d93a64e229e3ac6fced
0073|ldfld|System.Int32 <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_5ba0d0c50afd4c2688f4d7835d20d5e4
0078|xor|
0079|call|System.String AirExplorerCmd.Reporting.PassiveReporter::SetupReporter(System.Int32)
007E|call|System.Void System.Console::WriteLine(System.String)
0083|ldc.i4.1|
0084|ret|
0085|call|System.Reflection.Assembly System.Reflection.Assembly::GetExecutingAssembly()
008A|callvirt|System.String System.Reflection.Assembly::get_Location()
008F|call|System.String System.IO.Path::GetDirectoryName(System.String)
0094|stloc.s|V_4
0096|ldloc.0|
0097|newobj|System.Void System.Diagnostics.Process::.ctor()
009C|stfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
00A1|ldloc.0|
00A2|ldftn|System.Void AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::DestroyHiddenObject(System.Object,System.ConsoleCancelEventArgs)
00A8|newobj|System.Void System.ConsoleCancelEventHandler::.ctor(System.Object,System.IntPtr)
00AD|call|System.Void System.Console::add_CancelKeyPress(System.ConsoleCancelEventHandler)
00B2|ldloc.0|
00B3|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
00B8|callvirt|System.Diagnostics.ProcessStartInfo System.Diagnostics.Process::get_StartInfo()
00BD|ldloc.s|V_4
00BF|ldc.i4|1653340668
00C4|ldc.i4|960052474
00C9|add|
00CA|ldc.i4|-1785825344
00CF|xor|
00D0|ldsfld|<Module>{883c023e-01b0-4701-9cfa-c85338d8f612} <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_f8cdd8c7f4b34d93a64e229e3ac6fced
00D5|ldfld|System.Int32 <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_88c8f72dff3c418dbad5e80e08fc0509
00DA|xor|
00DB|call|System.String AirExplorerCmd.Reporting.PassiveReporter::SetupReporter(System.Int32)
00E0|call|System.String System.IO.Path::Combine(System.String,System.String)
00E5|callvirt|System.Void System.Diagnostics.ProcessStartInfo::set_FileName(System.String)
00EA|ldstr|
00EF|stloc.s|V_5
00F1|ldarg.0|
00F2|stloc.s|V_8
00F4|ldc.i4.0|
00F5|stloc.s|V_9
00F7|br|->0150
00FC|ldloc.s|V_8
00FE|ldloc.s|V_9
0100|ldelem.ref|
0101|stloc.s|V_10
0103|ldloc.s|V_5
0105|ldc.i4|976850276
010A|ldc.i4|517444133
010F|xor|
0110|ldsfld|<Module>{883c023e-01b0-4701-9cfa-c85338d8f612} <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_f8cdd8c7f4b34d93a64e229e3ac6fced
0115|ldfld|System.Int32 <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_354f162f315f4532af80d87f7fda0604
011A|xor|
011B|call|System.String AirExplorerCmd.Reporting.PassiveReporter::SetupReporter(System.Int32)
0120|ldloc.s|V_10
0122|ldc.i4|-1893959786
0127|ldc.i4|-1576448438
012C|xor|
012D|ldc.i4|2103023878
0132|xor|
0133|ldsfld|<Module>{883c023e-01b0-4701-9cfa-c85338d8f612} <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_f8cdd8c7f4b34d93a64e229e3ac6fced
0138|ldfld|System.Int32 <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_2f241f045913452abc84e802dbb2755b
013D|xor|
013E|call|System.String AirExplorerCmd.Reporting.PassiveReporter::SetupReporter(System.Int32)
0143|call|System.String System.String::Concat(System.String,System.String,System.String,System.String)
0148|stloc.s|V_5
014A|ldloc.s|V_9
014C|ldc.i4.1|
014D|add|
014E|stloc.s|V_9
0150|ldloc.s|V_9
0152|ldloc.s|V_8
0154|ldlen|
0155|conv.i4|
0156|blt|->00FC
015B|ldloc.s|V_5
015D|callvirt|System.Int32 System.String::get_Length()
0162|brtrue|->0184
0167|ldc.i4|326838873
016C|ldc.i4|760967049
0171|xor|
0172|ldsfld|<Module>{883c023e-01b0-4701-9cfa-c85338d8f612} <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_f8cdd8c7f4b34d93a64e229e3ac6fced
0177|ldfld|System.Int32 <Module>{883c023e-01b0-4701-9cfa-c85338d8f612}::m_4b670619fdbd41cfb460da708970e697
017C|xor|
017D|call|System.String AirExplorerCmd.Reporting.PassiveReporter::SetupReporter(System.Int32)
0182|stloc.s|V_5
0184|ldloc.0|
0185|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
018A|callvirt|System.Diagnostics.ProcessStartInfo System.Diagnostics.Process::get_StartInfo()
018F|ldloc.s|V_5
0191|callvirt|System.Void System.Diagnostics.ProcessStartInfo::set_Arguments(System.String)
0196|ldloc.0|
0197|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
019C|ldc.i4.0|
019D|callvirt|System.Void System.Diagnostics.Process::set_EnableRaisingEvents(System.Boolean)
01A2|ldloc.0|
01A3|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
01A8|callvirt|System.Diagnostics.ProcessStartInfo System.Diagnostics.Process::get_StartInfo()
01AD|ldc.i4.0|
01AE|callvirt|System.Void System.Diagnostics.ProcessStartInfo::set_UseShellExecute(System.Boolean)
01B3|ldloc.0|
01B4|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
01B9|callvirt|System.Diagnostics.ProcessStartInfo System.Diagnostics.Process::get_StartInfo()
01BE|ldc.i4.1|
01BF|callvirt|System.Void System.Diagnostics.ProcessStartInfo::set_CreateNoWindow(System.Boolean)
01C4|ldloc.0|
01C5|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
01CA|callvirt|System.Diagnostics.ProcessStartInfo System.Diagnostics.Process::get_StartInfo()
01CF|ldc.i4.1|
01D0|callvirt|System.Void System.Diagnostics.ProcessStartInfo::set_RedirectStandardOutput(System.Boolean)
01D5|ldloc.0|
01D6|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
01DB|callvirt|System.Diagnostics.ProcessStartInfo System.Diagnostics.Process::get_StartInfo()
01E0|ldc.i4.1|
01E1|callvirt|System.Void System.Diagnostics.ProcessStartInfo::set_RedirectStandardError(System.Boolean)
01E6|ldloc.0|
01E7|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
01EC|callvirt|System.Diagnostics.ProcessStartInfo System.Diagnostics.Process::get_StartInfo()
01F1|ldc.i4.1|
01F2|callvirt|System.Void System.Diagnostics.ProcessStartInfo::set_RedirectStandardInput(System.Boolean)
01F7|ldloc.0|
01F8|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
01FD|callvirt|System.Diagnostics.ProcessStartInfo System.Diagnostics.Process::get_StartInfo()
0202|call|System.Text.Encoding System.Text.Encoding::get_UTF8()
0207|callvirt|System.Void System.Diagnostics.ProcessStartInfo::set_StandardOutputEncoding(System.Text.Encoding)
020C|ldloc.0|
020D|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
0212|callvirt|System.Boolean System.Diagnostics.Process::Start()
0217|pop|
0218|ldloc.0|
0219|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
021E|callvirt|System.IO.StreamReader System.Diagnostics.Process::get_StandardOutput()
0223|stloc.s|V_6
0225|ldloc.0|
0226|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
022B|callvirt|System.IO.StreamWriter System.Diagnostics.Process::get_StandardInput()
0230|pop|
0231|ldloc.s|V_6
0233|callvirt|System.String System.IO.TextReader::ReadLine()
0238|call|System.Void System.Console::WriteLine(System.String)
023D|ldloc.s|V_6
023F|callvirt|System.Boolean System.IO.StreamReader::get_EndOfStream()
0244|brfalse|->0231
0249|ldloc.0|
024A|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
024F|callvirt|System.Void System.Diagnostics.Process::WaitForExit()
0254|ldloc.0|
0255|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
025A|callvirt|System.Int32 System.Diagnostics.Process::get_ExitCode()
025F|stloc.s|V_7
0261|ldloc.0|
0262|ldfld|System.Diagnostics.Process AirExplorerCmd.Helpers.GenericEmitter/<>c__DisplayClass0_0::attachedObject
0267|callvirt|System.Void System.Diagnostics.Process::Close()
026C|ldloc.s|V_7
026E|ret|
