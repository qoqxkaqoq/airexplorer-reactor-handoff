using System;
using System.Linq;
using dnlib.DotNet;

// nestedchk: 检查某个嵌套类型的 NestedClass 元数据行是否存在
// （dnlib 内存对象 DeclaringType 非空 ≠ 写盘时一定有 NestedClass 行）
// 用法: nestedchk <file> <nameSubstr>
class NestedChk {
    static void Main(string[] a) {
        var mod = ModuleDefMD.Load(a[0]);
        var nc = mod.TablesStream.NestedClassTable;
        Console.WriteLine("[table] NestedClass rows=" + nc.Rows);
        foreach (var t in mod.GetTypes()) {
            if (t.Name.String.IndexOf(a[1], StringComparison.Ordinal) < 0) continue;
            bool inTable = false;
            uint enclosing = 0;
            for (uint rid = 1; rid <= nc.Rows; rid++) {
                var row = nc.Read(rid);
                if (row.NestedClass == t.RID) { inTable = true; enclosing = row.EnclosingClass; break; }
            }
            string encName = enclosing == 0 ? "-" : (mod.ResolveTypeDef(enclosing)?.FullName ?? "?");
            bool inParentList = t.DeclaringType != null && t.DeclaringType.NestedTypes.Contains(t);
            Console.WriteLine(t.FullName + "  rid=" + t.RID
                + "  decl=" + (t.DeclaringType == null ? "null" : t.DeclaringType.FullName)
                + "  inParentNestedTypes=" + inParentList
                + "  nestedClassRow=" + inTable + (inTable ? (" enclosingRid=" + enclosing + " (" + encName + ")") : ""));
        }
    }
}
