// JitScan.js — Windbg TTD 时间旅行扫描 (x86 WoW64 / x64 自适应) v2
// 在 TTD 录制(.run)上运行: 枚举 clrjit!CILJit::compileMethod,
// 提取目标方法的: IL 快照 + locals.tok + 官方 LocalVarSig blob
// v2: 不依赖 host.namespace.Debugger(新版 cdb 下 undefined);
//     目标过滤(TARGET_ILSIZES)避免 16 万次 SeekTo 超时。
// 输出 C:\out\jitscan.json

const log = x => host.diagnostics.debugLog(x + "\n");
const read1 = (addr, n) => host.memory.readMemoryValues(addr, n, 1).map(v => Number(v));
function u32(a, i) { return (a[i] | (a[i+1]<<8) | (a[i+2]<<16) | (a[i+3]<<24)) >>> 0; }
function u64(a, i) { let v = 0n; for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(a[i+k] & 0xff); return Number(v); }

// ★ API 版本协商: 新版 WinDbg(1.2610) 默认移除了 host.namespace/currentSession/
//   currentThread/memory 等 legacy 全局, 必须显式请求 1.7 才恢复
function initializeScript() {
    return [new host.apiVersionSupport(1, 7)];
}

// 目标方法 IL 大小 (RequestVerifierTransformer..ctor = 2283 等, forcedump failed 名单)
const TARGET_ILSIZES = [2283];
const MAX_CALLS = 200000;

log("[JitScan] start, targets=" + JSON.stringify(TARGET_ILSIZES));

// ---- API 面探测 (新版 WinDbg JS host 兼容) ----
log("[JitScan] probe: host keys=" + Object.keys(host).join(","));
try { log("[JitScan] probe: currentSession=" + (typeof host.currentSession)); } catch(e) { log("[JitScan] probe: currentSession threw " + e); }
try { log("[JitScan] probe: currentThread=" + (typeof host.currentThread)); } catch(e) { log("[JitScan] probe: currentThread threw " + e); }
try { log("[JitScan] probe: namespace.Debugger=" + (typeof host.namespace.Debugger)); } catch(e) { log("[JitScan] probe: namespace.Debugger threw " + e); }

function getRegsUser() {
    try { if (typeof host.currentThread !== "undefined" && host.currentThread) return host.currentThread.Registers.User; } catch (e) { }
    try {
        var t = host.namespace.Debugger.Sessions.First().Processes.First().Threads.First();
        return t.Registers.User;
    } catch (e) { log("[JitScan] getRegsUser fallback failed: " + e); }
    return null;
}
function getSession() {
    try { if (typeof host.currentSession !== "undefined" && host.currentSession) return host.currentSession; } catch (e) { }
    try { return host.namespace.Debugger.Sessions.First(); } catch (e) { log("[JitScan] getSession fallback failed: " + e); }
    return null;
}

var regsObj = getRegsUser();
var isX86 = false;
try { isX86 = regsObj !== null && regsObj.esp !== undefined; } catch (e) { }
log("[JitScan] arch = " + (isX86 ? "x86 (WoW64)" : "x64/unknown"));

var session = getSession();
var calls = session.TTD.Calls("clrjit!CILJit::compileMethod");
var out = { arch: isX86 ? "x86" : "x64", targets: TARGET_ILSIZES, methods: [], sizeHistogram: {} };
var scanned = 0;

var it = calls.GetEnumerator();
while (it.MoveNext() && scanned < MAX_CALLS && out.methods.length < 50) {
    scanned++;
    var call = it.Current;
    var infoAddr;
    try {
        if (isX86) infoAddr = Number(call.Parameters[2]) >>> 0;
        else infoAddr = Number(call.Parameters[2]);
    } catch (e) { continue; }
    if (!infoAddr || infoAddr < 4096) continue;

    try {
        call.TimeStart.SeekTo();
        var regs = host.currentThread.Registers.User;
        if (isX86) {
            var esp = Number(regs.esp);
            var stack = read1(esp, 16);
            infoAddr = u32(stack, 12);
        } else {
            infoAddr = Number(regs.r8);
        }
        if (!infoAddr || infoAddr < 4096) continue;
        var head = read1(infoAddr, 0x28);
        if (head.length < 0x28) continue;
        var ilAddr = isX86 ? u32(head, 8) : u64(head, 16);
        var ilSize = u32(head, isX86 ? 12 : 24);
        if (!ilAddr || !ilSize || ilSize > 200000) continue;

        var key = String(ilSize);
        out.sizeHistogram[key] = (out.sizeHistogram[key] || 0) + 1;

        if (TARGET_ILSIZES.indexOf(ilSize) < 0) continue;

        // 命中目标: 读全量 info 窗口
        var raw = read1(infoAddr, 0xC0);
        if (raw.length < 0x40) continue;
        var maxStack = u32(raw, isX86 ? 16 : 28);
        var ehCount = u32(raw, isX86 ? 20 : 32);
        var tokOff = -1, localsTok = 0;
        var start = isX86 ? 0x20 : 0x28;
        for (var off = start; off < 0xC0 - 3; off++) {
            var v = u32(raw, off);
            if ((v & 0xFF000000) === 0x11000000 && (v & 0x00FFFFFF) !== 0) { tokOff = off; localsTok = v; break; }
        }
        var rec = { callIndex: scanned, ilSize: ilSize, maxStack: maxStack, ehCount: ehCount,
                    localsTok: "0x" + localsTok.toString(16) };
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
        var il = read1(ilAddr, ilSize);
        rec.il = il.map(b => b.toString(16).padStart(2, "0")).join("");
        out.methods.push(rec);
        log("[JitScan] TARGET HIT call#" + scanned + " ilSize=" + ilSize + " localsTok=" + rec.localsTok + " sig=" + (rec.localsSig ? rec.localsSig.length/2 + "B" : "none"));
    } catch (e) { }
}

log("[JitScan] scanned=" + scanned + " hits=" + out.methods.length);
var topSizes = Object.keys(out.sizeHistogram).sort(function(a,b){ return out.sizeHistogram[b]-out.sizeHistogram[a]; }).slice(0, 30);
out.topSizes = topSizes.map(function(k){ return { ilSize: Number(k), count: out.sizeHistogram[k] }; });
var txt = JSON.stringify(out);
host.namespace.Debugger.Utility.FileSystem.CreateFile("C:\\out\\jitscan.json").Write(txt);
log("[JitScan] C:\\out\\jitscan.json size=" + txt.length);
