using System.Reflection;

var exe = Path.GetFullPath(args[0]);
var coreDir = args.Length > 1 ? args[1] : "/usr/lib/mono/4.5";
var paths = Directory.GetFiles(coreDir, "*.dll").ToHashSet();
paths.Add(exe);
var mlc = new MetadataLoadContext(new PathAssemblyResolver(paths));
var asm = mlc.LoadFromAssemblyPath(exe);
Type[] types;
try
{
    types = asm.GetTypes();
    Console.WriteLine("[ok] GetTypes: {0} types", types.Length);
}
catch (ReflectionTypeLoadException ex)
{
    types = ex.Types;
    Console.WriteLine("[FAIL] GetTypes: {0} of {1} loaded, loader exceptions: {2}",
        ex.Types.Count(t => t != null), ex.Types.Length, ex.LoaderExceptions.Length);
    foreach (var le in ex.LoaderExceptions.Take(30))
        Console.WriteLine("  LOADER: {0}", le.Message);
}
int nBad = 0;
foreach (var t in types)
{
    if (t == null) continue;
    try
    {
        foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
        {
            var _ = m.ReturnType; foreach (var p in m.GetParameters()) { var __ = p.ParameterType; }
        }
        foreach (var f in t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
        { var _ = f.FieldType; }
    }
    catch (Exception ex2)
    {
        nBad++;
        if (nBad <= 30) Console.WriteLine("  MEMBER-FAIL: {0} :: {1}", t.FullName, ex2.Message);
    }
}
Console.WriteLine("[done] bad members: {0}", nBad);
