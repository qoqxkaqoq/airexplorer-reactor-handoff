// JitScan.js — Windbg TTD 时间旅行扫描 (x64)
// 在 TTD 录制(.run)上运行: 枚举每次 clrjit!CILJit::compileMethod,
// 读 CORINFO_METHOD_INFO (r8): ILCode/ILCodeSize/EHcount/locals.tok/locals.pSig+cbSig
// 输出 C:\out\jitscan.json — 官方 locals 签名 blob + IL 快照。
// 用法: windbgx -c ".scriptload JitScan.js; q" trace.run   (先 .sympath+)

const log = x => host.diagnostics.debugLog(x + "\n");
const sys = x => host.namespace.Debugger.Utility.Control.ExecuteCommand(x);
const read1 = (addr, n) => host.memory.readMemoryValues(addr, n, 1).map(v => Number(v));

function u32(arr, i) { return (arr[i] | (arr[i+1]<<8) | (arr[i+2]<<16) | (arr[i+3]<<24)) >>> 0; }
function u64(arr, i) { let v = 0n; for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(arr[i+k] & 0xff); return v; }

log("[JitScan] sympath...");
sys("sympath srv*C:\\symbols*https://msdl.microsoft.com/download/symbols");
sys(".reload");

var session = host.currentSession;
var calls = session.TTD.Calls("clrjit!CILJit::compileMethod");
var n = Number(calls.Count());
log("[JitScan] compileMethod 次数 = " + n);

var out = { count: n, methods: [] };
var MAXDUMP = 40000;            // 每方法最多 dump 字节数
var dumped = 0;

for (var i = 0; i < n && dumped < 60000; i++) {
    try {
        calls[i].TimeStart.SeekTo();
        var regs = host.currentThread.Registers.User;
        // x64 fastcall: rcx=this, rdx=comp, r8=info, r9=flags
        var infoAddr = Number(regs.r8);
        if (!infoAddr) continue;
        var raw = read1(infoAddr, 0xC0);
        if (raw.length < 0x40) continue;
        var ilAddr = Number(u64(raw, 16));
        var ilSize = u32(raw, 24);
        var maxStack = u32(raw, 28);
        var ehCount = u32(raw, 32);
        if (ilAddr === 0 || ilSize === 0 || ilSize > 200000) continue;
        // locals CORINFO_SIG_INFO: args 之后。x64: 头 40B + args(0x50) + locals
        // 定位: 扫 0x40..0xC0 找 0x11xxxxxx StandAloneSig token (locals.tok)
        var localsTok = 0;
        for (var off = 16; off < 0xC0 / 4; off++) {
            var v = u32(raw, off * 4);
            if ((v & 0xFF000000) === 0x11000000 && (v & 0x00FFFFFF) !== 0) { localsTok = v; break; }
        }
        // MethodToken: 用 SOS !DumpMD 拿 tok 太慢, 直接记 ftn 句柄, 离线用 ilSize+il 特征对齐
        var rec = {
            idx: i, ilSize: ilSize, maxStack: maxStack, ehCount: ehCount,
            localsTok: "0x" + localsTok.toString(16), ftn: "0x" + regs.r8.toString(16)
        };
        if (dumped < 30000) {
            var il = read1(ilAddr, Math.min(ilSize, MAXDUMP));
            rec.il = il.map(b => b.toString(16).padStart(2, "0")).join("");
            dumped += il.length;
        }
        out.methods.push(rec);
        if (i % 500 === 0) log("[JitScan] " + i + "/" + n + " il=" + ilSize + " tok=" + rec.localsTok);
    } catch (e) { /* 单方法失败继续 */ }
}

log("[JitScan] 完成, 写出 " + out.methods.length + " 条");
var fso = host.namespace.Debugger.Utility.FileSystem;
var txt = JSON.stringify(out);
fso.CreateFile("C:\\out\\jitscan.json").Write(txt);
log("[JitScan] C:\\out\\jitscan.json size=" + txt.length);
