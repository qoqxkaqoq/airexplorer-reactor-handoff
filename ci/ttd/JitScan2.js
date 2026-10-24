// JitScan2.js — Windbg TTD compileMethod 扫描 v2 (标记夹逼版)
// 逻辑: 扫描全部 clrjit!CILJit::compileMethod 调用; prep.cs 用唯一 ilSize 的 DynamicMethod
// 标记夹住每次 PrepareMethod / 自然调用; 标记窗口内的所有 JIT = 目标方法真体。
// 输出 C:\out\jitscan2.json: markers + windows + 全量 sizeHistogram。
"use strict";
function initializeScript() {
    return [new host.apiVersionSupport(1, 7)];
}
function invokeScript() {
mainImpl();
}
function mainImpl() {
const log = x => host.diagnostics.debugLog(x + "\n");
const read1 = (addr, n) => host.memory.readMemoryValues(addr, n, 1).map(v => Number(v));
function u32(a, i) { return (a[i] | (a[i+1]<<8) | (a[i+2]<<16) | (a[i+3]<<24)) >>> 0; }
function u64(a, i) { let v = 0n; for (let k = 7; k >= 0; k--) v = (v << 8n) | BigInt(a[i+k] & 0xff); return Number(v); }

// prep.cs 的标记 ilSize: 50000+i*2 系列 (prep 模式) / 60000-60002 (agcall 模式) / 99999 (收尾)
const MARKER_SIZES = [];
for (let i = 0; i < 20; i++) MARKER_SIZES.push(50000 + i);
for (let i = 0; i < 10; i++) MARKER_SIZES.push(60000 + i);
MARKER_SIZES.push(99999);
const MAX_PER_WINDOW = 40;
const MAX_CALLS = 400000;

log("[JS2] start, markers=" + MARKER_SIZES.length);

function getRegsUser() {
    try { if (typeof host.currentThread !== "undefined" && host.currentThread) return host.currentThread.Registers.User; } catch (e) { }
    try { return host.namespace.Debugger.Sessions.First().Processes.First().Threads.First().Registers.User; } catch (e) { log("[JS2] regs fallback failed: " + e); }
    return null;
}
function getSession() {
    try { if (typeof host.currentSession !== "undefined" && host.currentSession) return host.currentSession; } catch (e) { }
    try { return host.namespace.Debugger.Sessions.First(); } catch (e) { log("[JS2] session fallback failed: " + e); }
    return null;
}
var regsObj = getRegsUser();
var isX86 = true;
try {
    // x64 优先: rax/rcx/rdx 存在即为 x64 (esp 在 x64 上是 rsp 的别名, 不能用它判定)
    isX86 = !(regsObj !== null && regsObj.rax !== undefined);
} catch (e) { }
log("[JS2] arch = " + (isX86 ? "x86 (WoW64)" : "x64"));

var session = getSession();
var calls = session.TTD.Calls("clrjit!CILJit::compileMethod");
var out = { arch: isX86 ? "x86" : "x64", markers: [], windows: [], sizeHistogram: {}, total: 0, scanned: 0 };
try { out.total = Number(calls.Count()); } catch (e) { log("[JS2] Count() failed: " + e); }
log("[JS2] total compileMethod calls=" + out.total);

var markerIdx = -1;
var windowCalls = [];

function flushWindow() {
    if (markerIdx < 0) return;
    if (windowCalls.length > 0) {
        out.windows.push({ afterMarker: markerIdx, calls: windowCalls });
        log("[JS2] window after marker#" + markerIdx + ": " + windowCalls.length + " calls");
    }
    windowCalls = [];
}

var scanned = 0;
for (var call of calls) {
    scanned++;
    if (scanned > MAX_CALLS) { log("[JS2] MAX_CALLS cap"); break; }
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
        if (!ilAddr || ilSize > 200000) continue;

        var key = String(ilSize);
        out.sizeHistogram[key] = (out.sizeHistogram[key] || 0) + 1;

        if (MARKER_SIZES.indexOf(ilSize) >= 0) {
            flushWindow();
            markerIdx = ilSize;
            out.markers.push({ ilSize: ilSize, callIndex: scanned });
            log("[JS2] MARKER ilSize=" + ilSize + " callIndex=" + scanned);
            continue;
        }
        // 窗口内: 记录(小方法跳过, cap 限流)
        if (markerIdx >= 0 && windowCalls.length < MAX_PER_WINDOW) {
            var rec = { callIndex: scanned, ilSize: ilSize };
            if (ilSize > 8) {
                var raw = read1(infoAddr, 0xC0);
                if (raw.length >= 0x40) {
                    var maxStack = u32(raw, isX86 ? 16 : 28);
                    var ehCount = u32(raw, isX86 ? 20 : 32);
                    var localsTok = 0, tokOff = -1;
                    var start = isX86 ? 0x20 : 0x28;
                    for (var off = start; off < 0xC0 - 3; off++) {
                        var v = u32(raw, off);
                        if ((v & 0xFF000000) === 0x11000000 && (v & 0x00FFFFFF) !== 0) { tokOff = off; localsTok = v; break; }
                    }
                    rec.maxStack = maxStack; rec.ehCount = ehCount;
                    rec.localsTok = "0x" + localsTok.toString(16);
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
                }
            }
            windowCalls.push(rec);
        }
    } catch (e) { }
}
flushWindow();
out.scanned = scanned;
log("[JS2] done scanned=" + scanned + "/" + out.total + " markers=" + out.markers.length + " windows=" + out.windows.length);
var topSizes = Object.keys(out.sizeHistogram).sort(function(a,b){ return out.sizeHistogram[b]-out.sizeHistogram[a]; }).slice(0, 40);
out.topSizes = topSizes.map(function(k){ return { ilSize: Number(k), count: out.sizeHistogram[k] }; });

// 输出策略: ① 行式 JS2DATA 打到 debugLog (cdb.log 兜底, 文件写失败也能解析)
//           ② 同时尝试写 jitscan2.json
log("===JITSCAN2_META===" + JSON.stringify({arch: out.arch, total: out.total, scanned: scanned, markers: out.markers, topSizes: out.topSizes}));
for (var wi = 0; wi < out.windows.length; wi++) {
    var w = out.windows[wi];
    log("===JITSCAN2_WINDOW===" + w.afterMarker + "|" + w.calls.length);
    for (var ci = 0; ci < w.calls.length; ci++) {
        var c = w.calls[ci];
        log("JS2DATA|" + w.afterMarker + "|" + c.callIndex + "|" + c.ilSize + "|" + (c.maxStack||0) + "|" + (c.ehCount||0) + "|" + (c.localsTok||"0") + "|" + (c.localsSig||"") + "|" + (c.il||""));
    }
}
log("===JITSCAN2_END===");
var txt = JSON.stringify(out);
var written = false;
try {
    var f = host.namespace.Debugger.Utility.FileSystem.CreateFile("C:\\out\\jitscan2.json");
    try { f.Write(txt); written = true; } catch (e1) { try { f.WriteLine(txt); written = true; } catch (e2) { } }
} catch (e0) { log("[JS2] createfile err " + e0); }
log("[JS2] jitscan2.json bytes=" + txt.length + " written=" + written + " (行式输出已打到 cdb.log, 可兜底解析)");
}
