0000|ldnull|
0001|stloc.0|
0002|ldsfld|System.Object CloudClient.Templating.TemplateArgument::m_ProviderTemplateObj
0007|stloc.s|V_7
0009|ldc.i4.0|
000A|stloc.s|V_8
000C|ldloc.s|V_7
000E|ldloca.s|V_8
0010|call|System.Void System.Threading.Monitor::Enter(System.Object,System.Boolean&)
0015|ldsfld|System.Boolean CloudClient.Templating.TemplateArgument::isObserverTemplate
001A|brtrue.s|->0027
001C|ldc.i4.1|
001D|stsfld|System.Boolean CloudClient.Templating.TemplateArgument::isObserverTemplate
0022|call|System.Void CloudClient.Templating.TemplateArgument::GenerateJoinedOrder()
0027|ldsfld|CloudClient.Templating.TemplateArgument/DetachedCalculator[] CloudClient.Templating.TemplateArgument::_AdjustableTransformerElements
002C|ldarg.0|
002D|ldelem.ref|
002E|brfalse.s|->003D
0030|ldsfld|CloudClient.Templating.TemplateArgument/DetachedCalculator[] CloudClient.Templating.TemplateArgument::_AdjustableTransformerElements
0035|ldarg.0|
0036|ldelem.ref|
0037|stloc.0|
0038|leave|->05FD
003D|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0042|castclass|System.IO.BinaryReader
0047|callvirt|System.IO.Stream System.IO.BinaryReader::get_BaseStream()
004C|ldsfld|System.Int32[] CloudClient.Templating.TemplateArgument::templateStateArray
0051|ldarg.0|
0052|ldelem.i4|
0053|conv.i8|
0054|stloc|V_47
0058|castclass|System.IO.Stream
005D|ldloc|V_47
0061|callvirt|System.Void System.IO.Stream::set_Position(System.Int64)
0066|newobj|System.Void CloudClient.Templating.TemplateArgument/DetachedCalculator::.ctor()
006B|stloc.0|
006C|ldtoken|CloudClient.Templating.TemplateArgument
0071|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
0076|castclass|System.Type
007B|callvirt|System.Reflection.Module System.Type::get_Module()
0080|stloc.s|V_9
0082|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0087|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
008C|stloc.s|V_10
008E|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0093|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
0098|stloc.s|V_11
009A|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
009F|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
00A4|stloc.s|V_12
00A6|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
00AB|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
00B0|stloc.s|V_13
00B2|ldloc.0|
00B3|ldloc.s|V_9
00B5|ldloc.s|V_10
00B7|stloc|V_48
00BB|castclass|System.Reflection.Module
00C0|ldloc|V_48
00C4|callvirt|System.Reflection.MethodBase System.Reflection.Module::ResolveMethod(System.Int32)
00C9|stfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
00CE|ldloc.0|
00CF|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
00D4|castclass|System.Reflection.MethodBase
00D9|callvirt|System.Reflection.ParameterInfo[] System.Reflection.MethodBase::GetParameters()
00DE|stloc.s|V_14
00E0|ldloc.0|
00E1|ldloc.s|V_14
00E3|ldlen|
00E4|conv.i4|
00E5|newarr|CloudClient.Templating.TemplateArgument/AdjustableTreeAggregator
00EA|stfld|CloudClient.Templating.TemplateArgument/AdjustableTreeAggregator[] CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CustomContextItems
00EF|ldc.i4.0|
00F0|stloc.s|V_15
00F2|br|->02F4
00F7|ldloc.s|V_14
00F9|ldloc.s|V_15
00FB|ldelem.ref|
00FC|castclass|System.Reflection.ParameterInfo
0101|callvirt|System.Type System.Reflection.ParameterInfo::get_ParameterType()
0106|stloc.s|V_16
0108|newobj|System.Void CloudClient.Templating.TemplateArgument/AdjustableTreeAggregator::.ctor()
010D|stloc.s|V_17
010F|ldloc.s|V_17
0111|ldloc.s|V_16
0113|castclass|System.Type
0118|callvirt|System.Boolean System.Type::get_IsByRef()
011D|stfld|System.Boolean CloudClient.Templating.TemplateArgument/AdjustableTreeAggregator::_IsConfigurationTester
0122|ldloc.s|V_17
0124|ldloc.s|V_15
0126|stfld|System.Int32 CloudClient.Templating.TemplateArgument/AdjustableTreeAggregator::_IterableTransmitterVal
012B|ldloc.0|
012C|ldfld|CloudClient.Templating.TemplateArgument/AdjustableTreeAggregator[] CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CustomContextItems
0131|ldloc.s|V_15
0133|ldloc.s|V_17
0135|stelem.ref|
0136|ldloc.s|V_16
0138|castclass|System.Type
013D|callvirt|System.Boolean System.Type::get_IsByRef()
0142|brfalse.s|->0152
0144|ldloc.s|V_16
0146|castclass|System.Type
014B|callvirt|System.Type System.Type::GetElementType()
0150|stloc.s|V_16
0152|ldc.i4.0|
0153|stloc.s|V_18
0155|ldloc.s|V_16
0157|ldtoken|System.String
015C|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
0161|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
0166|brfalse.s|->0171
0168|ldc.i4.s|14
016A|stloc.s|V_18
016C|br|->02E5
0171|ldloc.s|V_16
0173|ldtoken|System.Byte
0178|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
017D|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
0182|brfalse.s|->018C
0184|ldc.i4.2|
0185|stloc.s|V_18
0187|br|->02E5
018C|ldloc.s|V_16
018E|ldtoken|System.SByte
0193|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
0198|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
019D|brfalse.s|->01A7
019F|ldc.i4.1|
01A0|stloc.s|V_18
01A2|br|->02E5
01A7|ldloc.s|V_16
01A9|ldtoken|System.Int16
01AE|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
01B3|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
01B8|brfalse.s|->01C2
01BA|ldc.i4.3|
01BB|stloc.s|V_18
01BD|br|->02E5
01C2|ldloc.s|V_16
01C4|ldtoken|System.UInt16
01C9|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
01CE|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
01D3|brfalse.s|->01DD
01D5|ldc.i4.4|
01D6|stloc.s|V_18
01D8|br|->02E5
01DD|ldloc.s|V_16
01DF|ldtoken|System.Int32
01E4|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
01E9|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
01EE|brfalse.s|->01F8
01F0|ldc.i4.5|
01F1|stloc.s|V_18
01F3|br|->02E5
01F8|ldloc.s|V_16
01FA|ldtoken|System.UInt32
01FF|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
0204|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
0209|brfalse.s|->0213
020B|ldc.i4.6|
020C|stloc.s|V_18
020E|br|->02E5
0213|ldloc.s|V_16
0215|ldtoken|System.Int64
021A|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
021F|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
0224|brfalse.s|->022E
0226|ldc.i4.7|
0227|stloc.s|V_18
0229|br|->02E5
022E|ldloc.s|V_16
0230|ldtoken|System.UInt64
0235|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
023A|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
023F|brfalse.s|->0249
0241|ldc.i4.8|
0242|stloc.s|V_18
0244|br|->02E5
0249|ldloc.s|V_16
024B|ldtoken|System.Single
0250|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
0255|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
025A|brfalse.s|->0265
025C|ldc.i4.s|9
025E|stloc.s|V_18
0260|br|->02E5
0265|ldloc.s|V_16
0267|ldtoken|System.Double
026C|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
0271|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
0276|brfalse.s|->027E
0278|ldc.i4.s|10
027A|stloc.s|V_18
027C|br.s|->02E5
027E|ldloc.s|V_16
0280|ldtoken|System.Boolean
0285|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
028A|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
028F|brfalse.s|->0297
0291|ldc.i4.s|11
0293|stloc.s|V_18
0295|br.s|->02E5
0297|ldloc.s|V_16
0299|ldtoken|System.IntPtr
029E|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
02A3|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
02A8|brfalse.s|->02B0
02AA|ldc.i4.s|12
02AC|stloc.s|V_18
02AE|br.s|->02E5
02B0|ldloc.s|V_16
02B2|ldtoken|System.UIntPtr
02B7|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
02BC|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
02C1|brfalse.s|->02C9
02C3|ldc.i4.s|13
02C5|stloc.s|V_18
02C7|br.s|->02E5
02C9|ldloc.s|V_16
02CB|ldtoken|System.Char
02D0|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
02D5|call|System.Boolean System.Type::op_Equality(System.Type,System.Type)
02DA|brfalse.s|->02E2
02DC|ldc.i4.s|15
02DE|stloc.s|V_18
02E0|br.s|->02E5
02E2|ldc.i4.0|
02E3|stloc.s|V_18
02E5|ldloc.s|V_17
02E7|ldloc.s|V_18
02E9|stfld|CloudClient.Templating.TemplateArgument/m4iNrp3uTHM9viOH5bc CloudClient.Templating.TemplateArgument/AdjustableTreeAggregator::responderDecorator
02EE|ldloc.s|V_15
02F0|ldc.i4.1|
02F1|add|
02F2|stloc.s|V_15
02F4|ldloc.s|V_15
02F6|ldloc.s|V_14
02F8|ldlen|
02F9|conv.i4|
02FA|blt|->00F7
02FF|ldloc.0|
0300|ldloc.s|V_11
0302|newobj|System.Void System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener>::.ctor(System.Int32)
0307|stfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener> CloudClient.Templating.TemplateArgument/DetachedCalculator::flexibleCalculatorList
030C|ldc.i4.0|
030D|stloc.s|V_19
030F|br.s|->036F
0311|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0316|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
031B|stloc.s|V_20
031D|newobj|System.Void CloudClient.Templating.TemplateArgument/CalculatorListener::.ctor()
0322|stloc.s|V_21
0324|ldloc.s|V_21
0326|ldnull|
0327|stfld|System.Type CloudClient.Templating.TemplateArgument/CalculatorListener::calculatorTransaction
032C|ldloc.s|V_20
032E|ldc.i4.0|
032F|blt.s|->0353
0331|ldloc.s|V_20
0333|ldc.i4.s|50
0335|bge.s|->0353
0337|ldloc.s|V_21
0339|ldloc.s|V_20
033B|ldc.i4.s|31
033D|and|
033E|conv.u1|
033F|stfld|CloudClient.Templating.TemplateArgument/m4iNrp3uTHM9viOH5bc CloudClient.Templating.TemplateArgument/CalculatorListener::statelessCalculator
0344|ldloc.s|V_21
0346|ldloc.s|V_20
0348|ldc.i4.s|32
034A|and|
034B|ldc.i4.0|
034C|cgt|
034E|stfld|System.Boolean CloudClient.Templating.TemplateArgument/CalculatorListener::isConnectedFactory
0353|ldloc.s|V_21
0355|ldloc.s|V_19
0357|stfld|System.Int32 CloudClient.Templating.TemplateArgument/CalculatorListener::_AlphabeticCalculatorIdx
035C|ldloc.0|
035D|ldfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener> CloudClient.Templating.TemplateArgument/DetachedCalculator::flexibleCalculatorList
0362|ldloc.s|V_21
0364|callvirt|System.Void System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener>::Add(CloudClient.Templating.TemplateArgument/CalculatorListener)
0369|ldloc.s|V_19
036B|ldc.i4.1|
036C|add|
036D|stloc.s|V_19
036F|ldloc.s|V_19
0371|ldloc.s|V_11
0373|blt.s|->0311
0375|ldloc.0|
0376|ldloc.s|V_12
0378|newobj|System.Void System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/DistributorProfile>::.ctor(System.Int32)
037D|stfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/DistributorProfile> CloudClient.Templating.TemplateArgument/DetachedCalculator::m_ProjectDecorators
0382|ldc.i4.0|
0383|stloc.s|V_22
0385|br|->046B
038A|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
038F|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
0394|stloc.s|V_23
0396|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
039B|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
03A0|stloc.s|V_24
03A2|newobj|System.Void CloudClient.Templating.TemplateArgument/DistributorProfile::.ctor()
03A7|stloc.s|V_25
03A9|ldloc.s|V_25
03AB|ldloc.s|V_23
03AD|stfld|System.Int32 CloudClient.Templating.TemplateArgument/DistributorProfile::_SegmentedFilterId
03B2|ldloc.s|V_25
03B4|ldloc.s|V_24
03B6|stfld|System.Int32 CloudClient.Templating.TemplateArgument/DistributorProfile::m_InterruptibleListCounter
03BB|newobj|System.Void CloudClient.Templating.TemplateArgument/WrapperConfiguration::.ctor()
03C0|stloc.s|V_26
03C2|ldloc.s|V_25
03C4|ldloc.s|V_26
03C6|stfld|CloudClient.Templating.TemplateArgument/WrapperConfiguration CloudClient.Templating.TemplateArgument/DistributorProfile::m_AdjustableDistributor
03CB|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
03D0|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
03D5|stloc.s|V_23
03D7|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
03DC|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
03E1|stloc.s|V_24
03E3|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
03E8|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
03ED|stloc.s|V_27
03EF|ldloc.s|V_26
03F1|ldloc.s|V_23
03F3|stfld|System.Int32 CloudClient.Templating.TemplateArgument/WrapperConfiguration::filterSetSize
03F8|ldloc.s|V_26
03FA|ldloc.s|V_24
03FC|stfld|System.Int32 CloudClient.Templating.TemplateArgument/WrapperConfiguration::m_WrapperProxyErrorCode
0401|ldloc.s|V_26
0403|ldloc.s|V_27
0405|stfld|System.Int32 CloudClient.Templating.TemplateArgument/WrapperConfiguration::m_WrapperContextScore
040A|ldloc.s|V_27
040C|brtrue.s|->0435
040E|ldloc.s|V_26
0410|ldloc.s|V_9
0412|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0417|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
041C|stloc|V_49
0420|castclass|System.Reflection.Module
0425|ldloc|V_49
0429|callvirt|System.Type System.Reflection.Module::ResolveType(System.Int32)
042E|stfld|System.Type CloudClient.Templating.TemplateArgument/WrapperConfiguration::advancedServer
0433|br.s|->0458
0435|ldloc.s|V_27
0437|ldc.i4.1|
0438|bne.un.s|->044D
043A|ldloc.s|V_26
043C|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0441|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
0446|stfld|System.Int32 CloudClient.Templating.TemplateArgument/WrapperConfiguration::m_DividedChainFreq
044B|br.s|->0458
044D|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0452|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
0457|pop|
0458|ldloc.0|
0459|ldfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/DistributorProfile> CloudClient.Templating.TemplateArgument/DetachedCalculator::m_ProjectDecorators
045E|ldloc.s|V_25
0460|callvirt|System.Void System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/DistributorProfile>::Add(CloudClient.Templating.TemplateArgument/DistributorProfile)
0465|ldloc.s|V_22
0467|ldc.i4.1|
0468|add|
0469|stloc.s|V_22
046B|ldloc.s|V_22
046D|ldloc.s|V_12
046F|blt|->038A
0474|ldloc.0|
0475|ldfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/DistributorProfile> CloudClient.Templating.TemplateArgument/DetachedCalculator::m_ProjectDecorators
047A|ldsfld|System.Comparison`1<CloudClient.Templating.TemplateArgument/DistributorProfile> CloudClient.Templating.TemplateArgument/GeneratedType_0431<T>::<>9__47_0
047F|dup|
0480|brtrue.s|->0499
0482|pop|
0483|ldsfld|CloudClient.Templating.TemplateArgument/GeneratedType_0431<T> CloudClient.Templating.TemplateArgument/GeneratedType_0431<T>::<>9
0488|ldftn|System.Int32 CloudClient.Templating.TemplateArgument/GeneratedType_0431<T>::generatedMethod_0290(CloudClient.Templating.TemplateArgument/DistributorProfile,CloudClient.Templating.TemplateArgument/DistributorProfile)
048E|newobj|System.Void System.Comparison`1<CloudClient.Templating.TemplateArgument/DistributorProfile>::.ctor(System.Object,System.IntPtr)
0493|dup|
0494|stsfld|System.Comparison`1<CloudClient.Templating.TemplateArgument/DistributorProfile> CloudClient.Templating.TemplateArgument/GeneratedType_0431<T>::<>9__47_0
0499|callvirt|System.Void System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/DistributorProfile>::Sort(System.Comparison`1<CloudClient.Templating.TemplateArgument/DistributorProfile>)
049E|ldloc.0|
049F|ldloc.s|V_13
04A1|newobj|System.Void System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/HandlerPublisher>::.ctor(System.Int32)
04A6|stfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/HandlerPublisher> CloudClient.Templating.TemplateArgument/DetachedCalculator::m_SequentialCalculators
04AB|ldc.i4.0|
04AC|stloc.s|V_28
04AE|br|->05DE
04B3|newobj|System.Void CloudClient.Templating.TemplateArgument/HandlerPublisher::.ctor()
04B8|stloc.s|V_29
04BA|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
04BF|castclass|System.IO.BinaryReader
04C4|callvirt|System.Byte System.IO.BinaryReader::ReadByte()
04C9|stloc.s|V_30
04CB|ldloc.s|V_29
04CD|ldloc.s|V_30
04CF|stfld|CloudClient.Templating.TemplateArgument/AItOeB3UZns1qY0NkiI CloudClient.Templating.TemplateArgument/HandlerPublisher::m_CalculatorPredicate
04D4|ldloc.s|V_30
04D6|ldc.i4|176
04DB|blt.s|->04E3
04DD|newobj|System.Void System.Exception::.ctor()
04E2|throw|
04E3|ldsfld|System.Byte[] CloudClient.Templating.TemplateArgument::templatePolicyElements
04E8|ldloc.s|V_30
04EA|ldelem.u1|
04EB|stloc.s|V_31
04ED|ldloc.s|V_31
04EF|brtrue.s|->04FE
04F1|ldloc.s|V_29
04F3|ldnull|
04F4|stfld|System.Object CloudClient.Templating.TemplateArgument/HandlerPublisher::_CommonBuilderObj
04F9|br|->05CB
04FE|ldnull|
04FF|stloc.s|V_32
0501|ldloc.s|V_31
0503|ldc.i4.1|
0504|sub|
0505|switch|[5目标]
051E|br|->05BC
0523|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0528|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
052D|box|System.Int32
0532|stloc.s|V_32
0534|br|->05C2
0539|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
053E|castclass|System.IO.BinaryReader
0543|callvirt|System.Int64 System.IO.BinaryReader::ReadInt64()
0548|box|System.Int64
054D|stloc.s|V_32
054F|br.s|->05C2
0551|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0556|castclass|System.IO.BinaryReader
055B|callvirt|System.Single System.IO.BinaryReader::ReadSingle()
0560|box|System.Single
0565|stloc.s|V_32
0567|br.s|->05C2
0569|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
056E|castclass|System.IO.BinaryReader
0573|callvirt|System.Double System.IO.BinaryReader::ReadDouble()
0578|box|System.Double
057D|stloc.s|V_32
057F|br.s|->05C2
0581|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
0586|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
058B|stloc.s|V_33
058D|ldloc.s|V_33
058F|newarr|System.Int32
0594|stloc.s|V_34
0596|ldc.i4.0|
0597|stloc.s|V_35
0599|br.s|->05B0
059B|ldloc.s|V_34
059D|ldloc.s|V_35
059F|ldsfld|System.IO.BinaryReader CloudClient.Templating.TemplateArgument::_TemplateController
05A4|call|System.Int32 CloudClient.Templating.TemplateArgument::EnableAuthorizer(System.IO.BinaryReader)
05A9|stelem.i4|
05AA|ldloc.s|V_35
05AC|ldc.i4.1|
05AD|add|
05AE|stloc.s|V_35
05B0|ldloc.s|V_35
05B2|ldloc.s|V_33
05B4|blt.s|->059B
05B6|ldloc.s|V_34
05B8|stloc.s|V_32
05BA|br.s|->05C2
05BC|newobj|System.Void System.Exception::.ctor()
05C1|throw|
05C2|ldloc.s|V_29
05C4|ldloc.s|V_32
05C6|stfld|System.Object CloudClient.Templating.TemplateArgument/HandlerPublisher::_CommonBuilderObj
05CB|ldloc.0|
05CC|ldfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/HandlerPublisher> CloudClient.Templating.TemplateArgument/DetachedCalculator::m_SequentialCalculators
05D1|ldloc.s|V_29
05D3|callvirt|System.Void System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/HandlerPublisher>::Add(CloudClient.Templating.TemplateArgument/HandlerPublisher)
05D8|ldloc.s|V_28
05DA|ldc.i4.1|
05DB|add|
05DC|stloc.s|V_28
05DE|ldloc.s|V_28
05E0|ldloc.s|V_13
05E2|blt|->04B3
05E7|ldsfld|CloudClient.Templating.TemplateArgument/DetachedCalculator[] CloudClient.Templating.TemplateArgument::_AdjustableTransformerElements
05EC|ldarg.0|
05ED|ldloc.0|
05EE|stelem.ref|
05EF|leave.s|->05FD
05F1|ldloc.s|V_8
05F3|brfalse.s|->05FC
05F5|ldloc.s|V_7
05F7|call|System.Void System.Threading.Monitor::Exit(System.Object)
05FC|endfinally|
05FD|newobj|System.Void CloudClient.Templating.TemplateArgument/TemplateThread::.ctor()
0602|stloc.1|
0603|ldloc.1|
0604|ldloc.0|
0605|stfld|CloudClient.Templating.TemplateArgument/DetachedCalculator CloudClient.Templating.TemplateArgument/TemplateThread::_TemplateConfig
060A|ldloc.0|
060B|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
0610|castclass|System.Reflection.MethodBase
0615|callvirt|System.Reflection.ParameterInfo[] System.Reflection.MethodBase::GetParameters()
061A|stloc.2|
061B|ldc.i4.0|
061C|stloc.3|
061D|ldc.i4.0|
061E|stloc.s|V_4
0620|ldloc.0|
0621|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
0626|isinst|System.Reflection.MethodInfo
062B|brfalse.s|->0655
062D|ldloc.0|
062E|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
0633|castclass|System.Reflection.MethodInfo
0638|castclass|System.Reflection.MethodInfo
063D|callvirt|System.Type System.Reflection.MethodInfo::get_ReturnType()
0642|ldtoken|System.Void
0647|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
064C|call|System.Boolean System.Type::op_Inequality(System.Type,System.Type)
0651|brfalse.s|->0655
0653|ldc.i4.1|
0654|stloc.3|
0655|ldloc.0|
0656|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
065B|castclass|System.Reflection.MethodBase
0660|callvirt|System.Boolean System.Reflection.MethodBase::get_IsStatic()
0665|brfalse.s|->06C4
0667|ldloc.1|
0668|ldloc.2|
0669|ldlen|
066A|conv.i4|
066B|newarr|CloudClient.Templating.TemplateArgument/ConnectedObserver
0670|stfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
0675|ldc.i4.0|
0676|stloc.s|V_36
0678|br.s|->06B8
067A|ldloc.2|
067B|ldloc.s|V_36
067D|ldelem.ref|
067E|castclass|System.Reflection.ParameterInfo
0683|callvirt|System.Type System.Reflection.ParameterInfo::get_ParameterType()
0688|stloc.s|V_37
068A|ldloc.1|
068B|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
0690|ldloc.s|V_36
0692|ldloc.s|V_37
0694|ldarg.1|
0695|ldloc.s|V_36
0697|ldelem.ref|
0698|call|CloudClient.Templating.TemplateArgument/ConnectedObserver CloudClient.Templating.TemplateArgument/ConnectedObserver::MonitorConcreteUser(System.Type,System.Object)
069D|stelem.ref|
069E|ldloc.s|V_37
06A0|castclass|System.Type
06A5|callvirt|System.Boolean System.Type::get_IsByRef()
06AA|brfalse.s|->06B2
06AC|ldloc.s|V_4
06AE|ldc.i4.1|
06AF|add|
06B0|stloc.s|V_4
06B2|ldloc.s|V_36
06B4|ldc.i4.1|
06B5|add|
06B6|stloc.s|V_36
06B8|ldloc.s|V_36
06BA|ldloc.2|
06BB|ldlen|
06BC|conv.i4|
06BD|blt.s|->067A
06BF|br|->0787
06C4|ldloc.1|
06C5|ldloc.2|
06C6|ldlen|
06C7|conv.i4|
06C8|ldc.i4.1|
06C9|add|
06CA|newarr|CloudClient.Templating.TemplateArgument/ConnectedObserver
06CF|stfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
06D4|ldloc.0|
06D5|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
06DA|castclass|System.Reflection.MemberInfo
06DF|callvirt|System.Type System.Reflection.MemberInfo::get_DeclaringType()
06E4|castclass|System.Type
06E9|callvirt|System.Boolean System.Type::get_IsValueType()
06EE|brfalse.s|->0715
06F0|ldloc.1|
06F1|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
06F6|ldc.i4.0|
06F7|ldarg.2|
06F8|newobj|System.Void CloudClient.Templating.TemplateArgument/ProgramFinder::.ctor(System.Object)
06FD|ldloc.0|
06FE|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
0703|castclass|System.Reflection.MemberInfo
0708|callvirt|System.Type System.Reflection.MemberInfo::get_DeclaringType()
070D|newobj|System.Void CloudClient.Templating.TemplateArgument/TagToken::.ctor(CloudClient.Templating.TemplateArgument/ConnectedObserver,System.Type)
0712|stelem.ref|
0713|br.s|->0723
0715|ldloc.1|
0716|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
071B|ldc.i4.0|
071C|ldarg.2|
071D|newobj|System.Void CloudClient.Templating.TemplateArgument/ProgramFinder::.ctor(System.Object)
0722|stelem.ref|
0723|ldc.i4.0|
0724|stloc.s|V_38
0726|br.s|->0780
0728|ldloc.2|
0729|ldloc.s|V_38
072B|ldelem.ref|
072C|castclass|System.Reflection.ParameterInfo
0731|callvirt|System.Type System.Reflection.ParameterInfo::get_ParameterType()
0736|stloc.s|V_39
0738|ldloc.s|V_39
073A|castclass|System.Type
073F|callvirt|System.Boolean System.Type::get_IsByRef()
0744|brfalse.s|->0764
0746|ldloc.1|
0747|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
074C|ldloc.s|V_38
074E|ldc.i4.1|
074F|add|
0750|ldloc.s|V_39
0752|ldarg.1|
0753|ldloc.s|V_38
0755|ldelem.ref|
0756|call|CloudClient.Templating.TemplateArgument/ConnectedObserver CloudClient.Templating.TemplateArgument/ConnectedObserver::MonitorConcreteUser(System.Type,System.Object)
075B|stelem.ref|
075C|ldloc.s|V_4
075E|ldc.i4.1|
075F|add|
0760|stloc.s|V_4
0762|br.s|->077A
0764|ldloc.1|
0765|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
076A|ldloc.s|V_38
076C|ldc.i4.1|
076D|add|
076E|ldloc.s|V_39
0770|ldarg.1|
0771|ldloc.s|V_38
0773|ldelem.ref|
0774|call|CloudClient.Templating.TemplateArgument/ConnectedObserver CloudClient.Templating.TemplateArgument/ConnectedObserver::MonitorConcreteUser(System.Type,System.Object)
0779|stelem.ref|
077A|ldloc.s|V_38
077C|ldc.i4.1|
077D|add|
077E|stloc.s|V_38
0780|ldloc.s|V_38
0782|ldloc.2|
0783|ldlen|
0784|conv.i4|
0785|blt.s|->0728
0787|ldloc.1|
0788|ldloc.0|
0789|ldfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener> CloudClient.Templating.TemplateArgument/DetachedCalculator::flexibleCalculatorList
078E|callvirt|System.Int32 System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener>::get_Count()
0793|newarr|CloudClient.Templating.TemplateArgument/ConnectedObserver
0798|stfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::dynamicTransactionTemplateArray
079D|ldc.i4.0|
079E|stloc.s|V_40
07A0|br|->08B8
07A5|ldloc.0|
07A6|ldfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener> CloudClient.Templating.TemplateArgument/DetachedCalculator::flexibleCalculatorList
07AB|ldloc.s|V_40
07AD|callvirt|CloudClient.Templating.TemplateArgument/CalculatorListener System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener>::get_Item(System.Int32)
07B2|stloc.s|V_41
07B4|ldloc.s|V_41
07B6|ldfld|CloudClient.Templating.TemplateArgument/m4iNrp3uTHM9viOH5bc CloudClient.Templating.TemplateArgument/CalculatorListener::statelessCalculator
07BB|stloc.s|V_42
07BD|ldloc.s|V_42
07BF|switch|[17目标]
0808|br|->08B2
080D|ldloc.1|
080E|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::dynamicTransactionTemplateArray
0813|ldloc.s|V_40
0815|ldnull|
0816|stelem.ref|
0817|br|->08B2
081C|ldloc.1|
081D|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::dynamicTransactionTemplateArray
0822|ldloc.s|V_40
0824|ldc.i4.0|
0825|ldloc.s|V_41
0827|ldfld|CloudClient.Templating.TemplateArgument/m4iNrp3uTHM9viOH5bc CloudClient.Templating.TemplateArgument/CalculatorListener::statelessCalculator
082C|newobj|System.Void CloudClient.Templating.TemplateArgument/VirtualInitializer::.ctor(System.Int32,CloudClient.Templating.TemplateArgument/m4iNrp3uTHM9viOH5bc)
0831|stelem.ref|
0832|br.s|->08B2
0834|ldloc.1|
0835|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::dynamicTransactionTemplateArray
083A|ldloc.s|V_40
083C|ldc.i4.0|
083D|conv.i8|
083E|ldloc.s|V_41
0840|ldfld|CloudClient.Templating.TemplateArgument/m4iNrp3uTHM9viOH5bc CloudClient.Templating.TemplateArgument/CalculatorListener::statelessCalculator
0845|newobj|System.Void CloudClient.Templating.TemplateArgument/WrapperQueue::.ctor(System.Int64,CloudClient.Templating.TemplateArgument/m4iNrp3uTHM9viOH5bc)
084A|stelem.ref|
084B|br.s|->08B2
084D|ldloc.1|
084E|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::dynamicTransactionTemplateArray
0853|ldloc.s|V_40
0855|ldc.r8|0
085E|ldloc.s|V_41
0860|ldfld|CloudClient.Templating.TemplateArgument/m4iNrp3uTHM9viOH5bc CloudClient.Templating.TemplateArgument/CalculatorListener::statelessCalculator
0865|newobj|System.Void CloudClient.Templating.TemplateArgument/DecryptorWriter::.ctor(System.Double,CloudClient.Templating.TemplateArgument/m4iNrp3uTHM9viOH5bc)
086A|stelem.ref|
086B|br.s|->08B2
086D|ldloc.1|
086E|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::dynamicTransactionTemplateArray
0873|ldloc.s|V_40
0875|ldsfld|System.IntPtr System.IntPtr::Zero
087A|newobj|System.Void CloudClient.Templating.TemplateArgument/ExtendedCalculator::.ctor(System.IntPtr)
087F|stelem.ref|
0880|br.s|->08B2
0882|ldloc.1|
0883|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::dynamicTransactionTemplateArray
0888|ldloc.s|V_40
088A|ldsfld|System.UIntPtr System.UIntPtr::Zero
088F|newobj|System.Void CloudClient.Templating.TemplateArgument/ExtendedCalculator::.ctor(System.UIntPtr)
0894|stelem.ref|
0895|br.s|->08B2
0897|ldloc.1|
0898|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::dynamicTransactionTemplateArray
089D|ldloc.s|V_40
089F|ldnull|
08A0|stelem.ref|
08A1|br.s|->08B2
08A3|ldloc.1|
08A4|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::dynamicTransactionTemplateArray
08A9|ldloc.s|V_40
08AB|ldnull|
08AC|newobj|System.Void CloudClient.Templating.TemplateArgument/ProgramFinder::.ctor(System.Object)
08B1|stelem.ref|
08B2|ldloc.s|V_40
08B4|ldc.i4.1|
08B5|add|
08B6|stloc.s|V_40
08B8|ldloc.s|V_40
08BA|ldloc.0|
08BB|ldfld|System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener> CloudClient.Templating.TemplateArgument/DetachedCalculator::flexibleCalculatorList
08C0|callvirt|System.Int32 System.Collections.Generic.List`1<CloudClient.Templating.TemplateArgument/CalculatorListener>::get_Count()
08C5|blt|->07A5
08CA|nop|
08CB|ldloc.1|
08CC|callvirt|System.Void CloudClient.Templating.TemplateArgument/TemplateThread::PlanRunner()
08D1|leave.s|->08DA
08D3|ldloc.1|
08D4|callvirt|System.Void CloudClient.Templating.TemplateArgument/TemplateThread::DefineIntegratedCollection()
08D9|endfinally|
08DA|ldc.i4.0|
08DB|stloc.s|V_5
08DD|ldloc.3|
08DE|brfalse.s|->08E3
08E0|ldc.i4.1|
08E1|stloc.s|V_5
08E3|ldloc.s|V_5
08E5|ldloc.s|V_4
08E7|add|
08E8|stloc.s|V_5
08EA|ldloc.s|V_5
08EC|newarr|System.Object
08F1|stloc.s|V_6
08F3|ldloc.3|
08F4|brfalse.s|->08FB
08F6|ldloc.s|V_6
08F8|ldc.i4.0|
08F9|ldnull|
08FA|stelem.ref|
08FB|ldloc.0|
08FC|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
0901|isinst|System.Reflection.MethodInfo
0906|brfalse.s|->094B
0908|ldloc.0|
0909|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
090E|castclass|System.Reflection.MethodInfo
0913|stloc.s|V_43
0915|ldloc.s|V_43
0917|callvirt|System.Type System.Reflection.MethodInfo::get_ReturnType()
091C|ldtoken|System.Void
0921|call|System.Type System.Type::GetTypeFromHandle(System.RuntimeTypeHandle)
0926|call|System.Boolean System.Type::op_Inequality(System.Type,System.Type)
092B|brfalse.s|->094B
092D|ldloc.1|
092E|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver CloudClient.Templating.TemplateArgument/TemplateThread::templateEditor
0933|brfalse.s|->094B
0935|ldloc.s|V_6
0937|ldc.i4.0|
0938|ldloc.1|
0939|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver CloudClient.Templating.TemplateArgument/TemplateThread::templateEditor
093E|ldloc.s|V_43
0940|callvirt|System.Type System.Reflection.MethodInfo::get_ReturnType()
0945|callvirt|System.Object CloudClient.Templating.TemplateArgument/ConnectedObserver::HandleAutomatableConnection(System.Type)
094A|stelem.ref|
094B|ldloc.s|V_4
094D|ldc.i4.0|
094E|ble|->09FD
0953|ldc.i4.0|
0954|stloc.s|V_44
0956|ldloc.3|
0957|brfalse.s|->0960
0959|ldc.i4|1
095E|stloc.s|V_44
0960|ldc.i4.0|
0961|stloc.s|V_45
0963|br|->09F3
0968|ldloc.2|
0969|ldloc.s|V_45
096B|ldelem.ref|
096C|castclass|System.Reflection.ParameterInfo
0971|callvirt|System.Type System.Reflection.ParameterInfo::get_ParameterType()
0976|stloc.s|V_46
0978|ldloc.s|V_46
097A|castclass|System.Type
097F|callvirt|System.Boolean System.Type::get_IsByRef()
0984|brfalse.s|->09ED
0986|ldloc.s|V_46
0988|castclass|System.Type
098D|callvirt|System.Type System.Type::GetElementType()
0992|stloc.s|V_46
0994|ldloc.1|
0995|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
099A|ldloc.s|V_45
099C|ldelem.ref|
099D|brfalse.s|->09E1
099F|ldloc.0|
09A0|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
09A5|castclass|System.Reflection.MethodBase
09AA|callvirt|System.Boolean System.Reflection.MethodBase::get_IsStatic()
09AF|brfalse.s|->09C8
09B1|ldloc.s|V_6
09B3|ldloc.s|V_44
09B5|ldloc.1|
09B6|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
09BB|ldloc.s|V_45
09BD|ldelem.ref|
09BE|ldloc.s|V_46
09C0|callvirt|System.Object CloudClient.Templating.TemplateArgument/ConnectedObserver::HandleAutomatableConnection(System.Type)
09C5|stelem.ref|
09C6|br.s|->09E7
09C8|ldloc.s|V_6
09CA|ldloc.s|V_44
09CC|ldloc.1|
09CD|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
09D2|ldloc.s|V_45
09D4|ldc.i4.1|
09D5|add|
09D6|ldelem.ref|
09D7|ldloc.s|V_46
09D9|callvirt|System.Object CloudClient.Templating.TemplateArgument/ConnectedObserver::HandleAutomatableConnection(System.Type)
09DE|stelem.ref|
09DF|br.s|->09E7
09E1|ldloc.s|V_6
09E3|ldloc.s|V_44
09E5|ldnull|
09E6|stelem.ref|
09E7|ldloc.s|V_44
09E9|ldc.i4.1|
09EA|add|
09EB|stloc.s|V_44
09ED|ldloc.s|V_45
09EF|ldc.i4.1|
09F0|add|
09F1|stloc.s|V_45
09F3|ldloc.s|V_45
09F5|ldloc.2|
09F6|ldlen|
09F7|conv.i4|
09F8|blt|->0968
09FD|ldloc.0|
09FE|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
0A03|castclass|System.Reflection.MethodBase
0A08|callvirt|System.Boolean System.Reflection.MethodBase::get_IsStatic()
0A0D|brtrue.s|->0A53
0A0F|ldloc.0|
0A10|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
0A15|castclass|System.Reflection.MemberInfo
0A1A|callvirt|System.Type System.Reflection.MemberInfo::get_DeclaringType()
0A1F|castclass|System.Type
0A24|callvirt|System.Boolean System.Type::get_IsValueType()
0A29|brfalse.s|->0A53
0A2B|ldarg.3|
0A2C|ldloc.1|
0A2D|ldfld|CloudClient.Templating.TemplateArgument/ConnectedObserver[] CloudClient.Templating.TemplateArgument/TemplateThread::activeFinderTemplateArray
0A32|ldc.i4.0|
0A33|ldelem.ref|
0A34|ldloc.0|
0A35|ldfld|System.Reflection.MethodBase CloudClient.Templating.TemplateArgument/DetachedCalculator::m_CalculatorArgument
0A3A|castclass|System.Reflection.MemberInfo
0A3F|callvirt|System.Type System.Reflection.MemberInfo::get_DeclaringType()
0A44|callvirt|System.Object CloudClient.Templating.TemplateArgument/ConnectedObserver::HandleAutomatableConnection(System.Type)
0A49|unbox.any|T
0A4E|stobj|T
0A53|ldloc.s|V_6
0A55|ret|
SWITCH@0505|0523,0539,0551,0569,0581
SWITCH@07BF|080D,081C,081C,081C,081C,081C,081C,0834,0834,084D,084D,081C,086D,0882,0897,081C,08A3
EH|try=000C-05F1 handler=05F1-05FD filter=- type=Finally
EH|try=08CB-08D3 handler=08D3-08DA filter=- type=Finally
