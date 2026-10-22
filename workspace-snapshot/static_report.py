import sys, math, hashlib
from datetime import datetime, timezone
try:
    import pefile
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "pefile", "--quiet", "--disable-pip-version-check"], check=True)
    import pefile

def entropy(data):
    if not data: return 0.0
    counts = [0] * 256
    for b in data: counts[b] += 1
    e, n = 0.0, len(data)
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e

def describe(path, label, report, imp_lines):
    report.append(f"===== {label} =====")
    report.append(f"文件: {path}")
    raw = open(path, "rb").read()
    report.append(f"大小: {len(raw)} 字节")
    report.append(f"SHA256: {hashlib.sha256(raw).hexdigest().upper()}")
    pe = pefile.PE(path, fast_load=True)
    report.append(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
    ts = pe.FILE_HEADER.TimeDateStamp
    report.append(f"TimeDateStamp: {ts} ({datetime.fromtimestamp(ts, timezone.utc)} UTC)")
    rows = []
    for s in pe.sections:
        name = s.Name.decode(errors="replace").rstrip("\x00")
        try: ent = entropy(s.get_data())
        except Exception: ent = -1.0
        rows.append((name, s.Misc_VirtualSize, s.SizeOfRawData, ent))
    report.append(f"节数量: {len(rows)}")
    report.append("节名          虚拟大小      原始大小      熵值")
    for name, vs, rs, ent in rows:
        report.append(f"{name:<12}  {vs:>10}  {rs:>10}  {ent:>8.3f}")
    clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
    report.append(".NET CLR 头: " + (f"存在 (托管程序集, 数据目录14 RVA=0x{clr.VirtualAddress:X} Size={clr.Size})" if clr.VirtualAddress else "未发现"))
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        pass
    imps = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    imp_lines.append(f"===== {label} 导入表 =====")
    if imps:
        dlls = []
        for entry in imps:
            dll = entry.dll.decode(errors="replace")
            dlls.append(dll)
            for imp in entry.imports:
                n = imp.name.decode(errors="replace") if imp.name else f"ord#{imp.ordinal}"
                imp_lines.append(f"{dll}!{n}")
        report.append(f"导入表: {len(dlls)} 个 DLL ({', '.join(dlls)}) — 明细见 import_table.txt")
    else:
        report.append("导入表: 无标准导入目录 (.NET 程序集, 入口由 mscoree!_CorExeMain 引导)")
        imp_lines.append("(无标准导入目录 — .NET 程序集, 延迟绑定, 入口 mscoree!_CorExeMain)")
    report.append("")

report, imp_lines = [], []
describe(sys.argv[1], "原始 (加壳, .NET Reactor)", report, imp_lines)
describe(sys.argv[2], "脱壳后 (内存脱壳 + 定向补丁)", report, imp_lines)
open(sys.argv[3], "w", encoding="utf-8").write("\n".join(report) + "\n")
open(sys.argv[4], "w", encoding="utf-8").write("\n".join(imp_lines) + "\n")
print(f"STATIC REPORT OK: {sys.argv[3]}")
print(f"IMPORT TABLE OK: {sys.argv[4]}")
