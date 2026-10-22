// JitScan.js — Windbg TTD 时间旅行扫描 (x86 WoW64 / x64 自适应)
// 在 TTD 录制(.run)上运行: 枚举每次 clrjit!CILJit::compileMethod,
// 从 CORINFO_METHOD_INFO 提取: ILCode 快照 + locals.tok + 官方 LocalVarSig blob
// 目标是 x86(Framework 4.8 WoW64): stdcall, info = [esp+C]
// 输出 C:\out\jitscan.json

const log = x => host.diagnostics.debugLog(x + "\n");
const sys = x => host.namespace.Debugger.Utility.Control.ExecuteCommand(x);
const read1 = (addr, n) => host.memory.readMemoryValues(addr, n, 1).map(v => Number(v));
function u32(a, i) { return (a[i] | (a[i+1]<<8) | (a[i+2]<<16) | (a[i+3]<<24)) >>> 0; }
function u64(a, i) { let v = 0n; for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(a[i+k] & 0xff); return Number(v); }

log("[JitScan] sympath...");
sys("sympath srv*C:\\symbols*https://msdl.microsoft.com/download/symbols");
sys(".reload /f clrjit.dll");

var regs0 = host.currentThread.Registers.User;
var isX86 = regs0.esp !== undefined;
log("[JitScan] arch = " + (isX86 ? "x86 (WoW64)" : "x64"));

var session = host.currentSession;
var calls = session.TTD.Calls("clrjit!CILJit::compileMethod");
var n = Number(calls.Count());
log("[JitScan] compileMethod 次数 = " + n);

var out = { arch: isX86 ? "x86" : "x64", count: n, methods: [] };
var MAXIL = 100000;

for (var i = 0; i < n && out.methods.length < 30000; i++) {
    try {
        calls[i].TimeStart.SeekTo();
        var regs = host.currentThread.Registers.User;
        var infoAddr;
        if (isX86) {
            var esp = Number(regs.esp);
            var stack = read1(esp, 16);            // [ret][this][comp][info]
            infoAddr = u32(stack, 12);
        } else {
            infoAddr = Number(regs.r8);
        }
        if (!infoAddr) continue;
        var raw = read1(infoAddr, 0xC0);
        if (raw.length < 0x40) continue;
        var ilAddr = isX86 ? u32(raw, 8) : u64(raw, 16);
        var ilSize = u32(raw, isX86 ? 12 : 24);
        var maxStack = u32(raw, isX86 ? 16 : 28);
        var ehCount = u32(raw, isX86 ? 20 : 32);
        if (!ilAddr || !ilSize || ilSize > 200000) continue;

        // 扫 0xC0 窗口找唯一 0x11xxxxxx (StandAloneSig locals.tok)
        var tokOff = -1, localsTok = 0;
        var start = isX86 ? 0x20 : 0x28;           // args/locals 内嵌区起点
        for (var off = start; off < 0xC0 - 3; off++) {
            var v = u32(raw, off);
            if ((v & 0xFF000000) === 0x11000000 && (v & 0x00FFFFFF) !== 0) { tokOff = off; localsTok = v; break; }
        }
        var rec = { idx: i, ilSize: ilSize, maxStack: maxStack, ehCount: ehCount,
                    localsTok: "0x" + localsTok.toString(16) };
        // tok 在 CORINFO_SIG_INFO 内偏移 0x34(x86)/0x68(x64) -> 反推 pSig/cbSig
        if (tokOff > 0) {
            var sigBase = tokOff - (isX86 ? 0x34 : 0x68);
            if (sigBase >= 0) {
                var pSig = isX86 ? u32(raw, sigBase + 8) : u64(raw, sigBase + 16);
                var cbSig = u32(raw, sigBase + (isX86 ? 12 : 24));
                if (pSig && cbSig > 0 && cbSig < 4096) {
                    var blob = read1(pSig, cbSig);
                    rec.localsSig = blob.map(b => b.toString(16).padStart(2, "0")).join("");
                }
            }
        }
        if (out.methods.length < 30000) {
            var il = read1(ilAddr, Math.min(ilSize, MAXIL));
            rec.il = il.map(b => b.toString(16).padStart(2, "0")).join("");
        }
        out.methods.push(rec);
        if (i % 500 === 0) log("[JitScan] " + i + "/" + n + " il=" + ilSize + " localsTok=" + rec.localsTok);
    } catch (e) { }
}

log("[JitScan] 完成 " + out.methods.length + " 条, withLocalsSig=" +
    out.methods.filter(m => m.localsSig).length);
var txt = JSON.stringify(out);
host.namespace.Debugger.Utility.FileSystem.CreateFile("C:\\out\\jitscan.json").Write(txt);
log("[JitScan] C:\\out\\jitscan.json size=" + txt.length);
