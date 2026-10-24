// PayloadScan v7 — v6 P3 int32 位运算截断修复 + 驱动器内存真体全量提取
// v6 战果:
//   P1 实锤: 每方法回填 = fat hdr(12B)+体前8B 写入 exe 槽位(5 dword), 完整 IL 在驱动器内存
//   寄存器: rbx=负载条目偏移(Viewer资源) r10=rbx+0xA 读游标(+4/dword) r9=0x56FE8(资源大小) rsi=0x6e51d6f8
//   06003909 窗口实为 9 方法族 06003909..06003911 (0F/10/11 新发现: codesize 0x480/0x5AE/0x684)
//   P3 败因: JS 位运算 int32 截断(0x7ffba50b7000 & mask → 0xa50b0000) → 基址变负数
//   驱动器 = 无模块映射动态可执行内存(0x7ffba50b7000 区), k 栈 retaddr 0x7ffba50bb1ae
// v7 阶段:
//   P1 同 v6(照旧)
//   P2 !tt 首事件 → k → 算术页对齐 → 驱动器区边界探测(上下 64 页) → !address/lm 区间
//   P3 bp writerIP 命中#1 → regs + P6(ct 缓冲区定位: r13/r14/栈候选 base + r10/rbx 读内存对照)
//      → TTD "e" 执行查询(1MB 区) → IP 直方图 top30 → 最热 IP !tt → regs + u 反汇编(解密循环!)
//   P5 s -d 在 exe 全区 + r13/r14 邻域搜已知 fat hdr(1b300700 等) → db 提取 06003909 等完整真体
//   P4 !tt ladder 到后段 → SOS name2ee(改 late pos 解决 "Failed to request module list")
"use strict";

function initializeScript() {
    return [new host.apiVersionSupport(1, 7)];
}
function invokeScript() {
    mainImpl();
}
function mainImpl() {

function log(s) { host.diagnostics.debugLog(s + "\n"); }
function hexB(b) { return (b < 16 ? "0" : "") + b.toString(16); }

var session = null;
try { if (host.currentSession) session = host.currentSession; } catch (e) { }
if (!session) session = host.namespace.Debugger.Sessions.First();
var proc = session.Processes.First();

var mod = null;
var modList = [];
for (var m of proc.Modules) {
    var nm = String(m.Name);
    try {
        var b = Number(m.BaseAddress);
        modList.push({ name: nm, base: b, end: b + Number(m.Size) });
        if (nm.toLowerCase().indexOf("airexplorer") >= 0 && !mod) mod = m;
    } catch (e) { }
}
var BASE = mod ? Number(mod.BaseAddress) : 0;
log("[V7] module AirExplorer base=0x" + BASE.toString(16) + " modules=" + modList.length);
if (!BASE) { log("[V7] FATAL no AirExplorer module"); return; }
function modOf(a) { for (var x of modList) if (a >= x.base && a < x.end) return x.name; return "?"; }
function ExecuteCommand2(cmd) {
    var out = "";
    try { out = host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd); }
    catch (e) { return "ERR: " + e; }
    return ecStr(out);
}
function ecStr(r) {
    if (r === null || r === undefined) return "";
    if (typeof r === "string") return r;
    try { var s = r.toString(); if (s !== "[object Object]") return s; } catch (e) { }
    try {
        var lines = [];
        for (var line of r) lines.push(String(line));
        return lines.join("\n");
    } catch (e2) { }
    try { return JSON.stringify(r); } catch (e3) { return "[unprintable]"; }
}
function EC(cmd) { var out = ExecuteCommand2(cmd); log("[V7|CMD] " + cmd + "\n" + out); return out; }
function memReadable(a) {
    try { host.memory.readMemoryValues(a, 1, 1); return true; } catch (e) { return false; }
}
function readBytesSafe(a, n) {
    try {
        var vals = host.memory.readMemoryValues(a, n, 1);
        var h = "";
        for (var v of vals) h += hexB(Number(v) & 0xFF);
        return h;
    } catch (e) { return null; }
}
function evPos(w) {
    try { if (w.TimeStart !== undefined && w.TimeStart !== null) return (String(w.TimeStart.Sequence) + ":" + String(w.TimeStart.Steps)).replace(/0x/g, ""); } catch (e) { }
    try { if (w.Position !== undefined && w.Position !== null) return String(w.Position).replace(/0x/g, ""); } catch (e) { }
    return "undef";
}
function dumpRegs() {
    var regs;
    try { regs = host.currentThread.Registers.User; } catch (e2) { log("[V7] no regs"); return null; }
    var names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
    var rd = {};
    for (var rn of names) {
        try { var v = Number(regs[rn]); rd[rn] = isFinite(v) ? v : 0; } catch (e) { }
    }
    var s = "";
    for (var k in rd) s += k + "=0x" + rd[k].toString(16) + " ";
    log("[V7] REGS " + s);
    return rd;
}
// 整数安全: JS 位运算 int32 截断 — 一律算术
function pageDown(a) { return Math.floor(a / 0x10000) * 0x10000; }
function parseHexTok(s) {
    var t = String(s).replace(/`/g, "").replace(/^0x/, "");
    if (!/^[0-9a-f]+$/i.test(t) || t.length < 8) return 0;
    return parseInt(t, 16);
}

var TARGETS = [
    { tok: "06003909", rva: 0x00334EB0, win: 0x2000 },
    { tok: "06002BD1", rva: 0x0024EA40, win: 0x800 },
    { tok: "060042B0", rva: 0x0040EE88, win: 8 },
    { tok: "060042B1", rva: 0x0040F2A4, win: 8 },
    { tok: "0600212A", rva: 0x00195D18, win: 16 },
];

// ---------------- P1 ----------------
log("[V7] PHASE1 TTD.Memory");
var allEvents = [];
var writerIPs = [];
var firstPos = {};
for (var t of TARGETS) {
    var va = BASE + t.rva;
    var cnt = 0;
    var evs = null;
    try { evs = session.TTD.Memory(va, va + t.win, "w"); } catch (e) { log("[V7] query fail " + t.tok + ": " + e); continue; }
    for (var w of evs) {
        cnt++;
        try {
            var a = Number(w.Address);
            var v = Number(w.Value) & 0xFFFFFFFF;
            var ip = Number(w.IP);
            allEvents.push({ tok: t.tok, addr: a, val: v, ip: ip });
            if (writerIPs.indexOf(ip) < 0) writerIPs.push(ip);
            if (firstPos[t.tok] === undefined) firstPos[t.tok] = evPos(w);
            if (cnt <= 60) log("[V7] EVT " + t.tok + " i=" + cnt + " addr=0x" + a.toString(16) + " val=" + hexW(v) + " ip=0x" + ip.toString(16) + " pos=" + evPos(w));
        } catch (e) { }
        if (cnt > 400) break;
    }
    log("[V7] " + t.tok + " events=" + cnt);
}
function hexW(v) { return ("00000000" + (v >>> 0).toString(16)).slice(-8); }

// 重建(同 v6)
for (var t3 of TARGETS) {
    if (t3.tok !== "06003909" && t3.tok !== "06002BD1") continue;
    var tw3 = t3.win;
    var bytes = {};
    for (var ev2 of allEvents) {
        if (ev2.tok !== t3.tok) continue;
        var off = ev2.addr - (BASE + t3.rva);
        if (off < 0 || off >= tw3) continue;
        var v = ev2.val >>> 0;
        for (var b = 0; b < 4 && (off + b) < tw3; b++) bytes[off + b] = (v >>> (8 * b)) & 0xFF;
    }
    var known3 = 0;
    for (var k3 in bytes) known3++;
    log("[V7] IL " + t3.tok + " reconstructed=" + known3 + "/" + tw3);
    for (var row = 0; row < tw3; row += 256) {
        var has = false;
        for (var j3 = row; j3 < row + 256 && j3 < tw3; j3++) if (bytes[j3] !== undefined) { has = true; break; }
        if (!has) continue;
        var hexr = "";
        for (var j4 = row; j4 < row + 256 && j4 < tw3; j4++) hexr += (bytes[j4] === undefined ? "??" : hexB(bytes[j4]));
        log("[V7] IL " + t3.tok + " @" + row.toString(16) + " " + hexr);
    }
}

// ---------------- P2: 首事件 → 驱动器区边界 ----------------
log("[V7] PHASE2 driver region discovery");
var pos0909 = firstPos["06003909"];
var natBase = 0, natEnd = 0;
if (pos0909 && pos0909 !== "undef") {
    EC("!tt " + pos0909);
    var rd = dumpRegs();
    var kOut = ExecuteCommand2("k 15");
    log("[V7|CMD] k 15\n" + kOut);
    var cands = [];
    var lkArr = kOut.split("\n");
    for (var lk of lkArr) {
        var cols = lk.trim().split(/\s+/);
        for (var ci = 1; ci < cols.length && ci <= 3; ci++) {
            var vv = parseHexTok(cols[ci]);
            if (vv > 0x7ff000000000 && modOf(vv) === "?") cands.push(vv);
        }
    }
    cands.sort(function (a, b) { return a - b; });
    log("[V7] P2 driver addrs from k: " + cands.map(function (x) { return "0x" + x.toString(16); }).join(", "));
    if (cands.length > 0) {
        var lo = pageDown(cands[0]);
        natBase = lo;
        for (var down = 1; down <= 64; down++) {
            var probe = lo - down * 0x10000;
            if (!memReadable(probe)) { natBase = probe + 0x10000; break; }
            natBase = probe;
        }
        var hi = pageDown(cands[cands.length - 1]) + 0x10000;
        natEnd = hi;
        for (var up = 1; up <= 64; up++) {
            var probe2 = hi + up * 0x10000;
            if (!memReadable(probe2)) { natEnd = probe2; break; }
            natEnd = probe2;
        }
    }
    log("[V7] P2 driver region = 0x" + natBase.toString(16) + " - 0x" + natEnd.toString(16) + " (0x" + (natEnd - natBase).toString(16) + " bytes)");
    if (natBase) {
        EC("ln 0x" + natBase.toString(16));
        EC("!address 0x" + Math.floor((natBase + natEnd) / 2).toString(16));
        var mz2 = readBytesSafe(natBase, 16);
        log("[V7] P2 first16 = " + (mz2 ? mz2 : "<unreadable>"));
    }
}

// ---------------- P6 helper: ct 缓冲区定位 ----------------
function probeBuffers(rd, tag) {
    if (!rd) return;
    var bases = [];
    var rnames = ["r13", "r14", "r12", "r15", "rsi", "rdi"];
    for (var rn of rnames) {
        var v = rd[rn];
        if (v > 0x10000 && v < 0x7ff000000000) bases.push({ n: rn, b: v });
    }
    // 栈上 qword 候选 (rsp..rsp+0x100)
    var spStr = ExecuteCommand2("dqs @rsp L40");
    var sl = spStr.split("\n");
    for (var ln of sl) {
        var mm = ln.match(/^\w+`(\w+)\s+([0-9a-f`]+)/i);
        if (mm) {
            var pv = parseHexTok(mm[2]);
            if (pv > 0x10000 && pv < 0x7ff000000000 && modOf(pv) === "?") bases.push({ n: "stk", b: pv });
        }
    }
    var seen = {};
    for (var cand of bases) {
        if (seen[cand.b]) continue;
        seen[cand.b] = 1;
        // 读 base+r10 与 base+rbx 的内存
        var h1 = readBytesSafe(cand.b + rd.r10, 16);
        var h2 = readBytesSafe(cand.b + rd.rbx, 16);
        if (h1 || h2) {
            log("[V7] P6 " + tag + " base=" + cand.n + ":0x" + cand.b.toString(16) +
                " +r10(0x" + rd.r10.toString(16) + ")=" + (h1 || "<unread>") +
                " +rbx(0x" + rd.rbx.toString(16) + ")=" + (h2 || "<unread>"));
        }
    }
    // rbx/r10 直接当地址试
    var h3 = readBytesSafe(rd.r10, 16), h4 = readBytesSafe(rd.rbx, 16);
    log("[V7] P6 " + tag + " direct r10=0x" + rd.r10.toString(16) + "->" + (h3 || "<unread>") + " rbx->" + (h4 || "<unread>"));
}

// ---------------- P3: bp writerIP → 执行热图 + 反汇编 ----------------
log("[V7] PHASE3 native execute heatmap");
var heapBufs = [];
function collectBufs(rd) {
    if (!rd) return;
    var rnames = ["r13", "r14", "r12", "r15"];
    for (var rn of rnames) {
        var v = rd[rn];
        if (v > 0x10000 && v < 0x7ff000000000 && heapBufs.indexOf(v) < 0) heapBufs.push(v);
    }
}
if (writerIPs.length > 0) {
    var wip = writerIPs[0];
    ExecuteCommand2("bp 0x" + wip.toString(16));
    try { ExecuteCommand2("g"); } catch (e) { log("[V7] P3 g#1 threw: " + e); }
    log("[V7] P3 ---- HIT#1 ----");
    var rd3 = dumpRegs();
    collectBufs(rd3);
    if (rd3) probeBuffers(rd3, "hit1");
    // 执行查询
    if (natBase && natEnd > natBase) {
        var hist = {};
        var eCnt = 0;
        try {
            var es = session.TTD.Memory(natBase, natEnd, "e");
            for (var ee of es) {
                eCnt++;
                var ipE = Number(ee.IP);
                if (hist[ipE] === undefined) hist[ipE] = 0;
                hist[ipE]++;
                if (eCnt > 300000) break;
            }
        } catch (e) { log("[V7] TTD exec query failed: " + e); }
        log("[V7] P3 exec events=" + eCnt + " uniqueIPs=" + Object.keys(hist).length);
        var pairs = [];
        for (var ipH in hist) pairs.push({ ip: Number(ipH), c: hist[ipH] });
        pairs.sort(function (a, b) { return b.c - a.c; });
        for (var pi = 0; pi < Math.min(40, pairs.length); pi++)
            log("[V7] HOT 0x" + pairs[pi].ip.toString(16) + " (drv+0x" + (pairs[pi].ip - natBase).toString(16) + ") count=" + pairs[pi].c);
        if (pairs.length > 0) {
            var hot = pairs[0].ip;
            try {
                var es2 = session.TTD.Memory(hot, hot + 1, "e");
                var firstE = null, lastE = null, nE = 0;
                for (var e2 of es2) {
                    nE++;
                    if (!firstE) firstE = evPos(e2);
                    lastE = evPos(e2);
                    if (nE >= 150000) break;
                }
                log("[V7] P3 hotIP 0x" + hot.toString(16) + " execCount=" + nE + " firstPos=" + firstE + " lastPos=" + lastE);
                if (lastE) {
                    EC("!tt " + lastE);
                    var rd4 = dumpRegs();
                    collectBufs(rd4);
                    if (rd4) probeBuffers(rd4, "hot");
                    EC("u @rip-0x100 L80");
                    EC("u @rip L20");
                    EC("k 15");
                }
            } catch (e) { log("[V7] hotIP pos query failed: " + e); }
            // 热区全反汇编
            if (pairs.length > 3) {
                var lo2 = pairs[0].ip, hi2 = pairs[0].ip;
                for (var p6 of pairs) { if (p6.c < 10) continue; if (p6.ip < lo2) lo2 = p6.ip; if (p6.ip > hi2) hi2 = p6.ip; }
                log("[V7] P3 hot range 0x" + lo2.toString(16) + " - 0x" + hi2.toString(16) + " span=0x" + (hi2 - lo2).toString(16));
                EC("u 0x" + (lo2 - 0x40).toString(16) + " L" + Math.min(300, Math.floor((hi2 - lo2) / 4) + 120));
            }
        }
        ExecuteCommand2("bc *");
    } else {
        log("[V7] P3 no driver region, skip exec query");
    }
}

// ---------------- P5: 驱动器内存搜已知 fat hdr → 全量真体提取 ----------------
log("[V7] PHASE5 memory search for decrypted bodies");
// 已知 fat hdr word1 (LE bytes): 06003909=1b300700 06002BD1=1b300600 0600390F=1b300700(同)
// 搜索值用 dword (s -d 按调试器 hex): 0x0007301b / 0x0006301b
var searches = [];
if (natBase && natEnd > natBase) searches.push({ n: "drv", s: natBase, c: natEnd - natBase });
searches.push({ n: "exe", s: BASE, c: 0x93A000 });
// 堆缓冲区: r13/r14 等 ±0x400000, 按可读 64KB 页分块搜
var bufChunks = [];
for (var hb of heapBufs) {
    var plo = Math.floor((hb - 0x400000) / 0x10000) * 0x10000;
    var phi = hb + 0x400000;
    var run = 0, start = 0;
    for (var pg = plo; pg <= phi; pg += 0x10000) {
        var rdok = memReadable(pg);
        if (rdok) { if (run === 0) start = pg; run++; }
        else { if (run > 0) bufChunks.push({ n: "buf@0x" + hb.toString(16), s: start, c: run * 0x10000 }); run = 0; }
    }
    if (run > 0) bufChunks.push({ n: "buf@0x" + hb.toString(16), s: start, c: run * 0x10000 });
}
for (var bc of bufChunks) { bc.n += "+0x" + (bc.s - 0).toString(16); searches.push(bc); log("[V7] P5 buf chunk " + bc.n + " len=0x" + bc.c.toString(16)); }
for (var sc of searches) {
    log("[V7] P5 search " + sc.n + " 0x" + sc.s.toString(16) + " L0x" + sc.c.toString(16));
    var out1 = ExecuteCommand2("s -d 0x" + sc.s.toString(16) + " L0x" + sc.c.toString(16) + " 0007301b");
    log("[V7] P5 hits(0007301b) " + sc.n + ":\n" + out1);
    var hits1 = [];
    var ol = out1.split("\n");
    for (var o1 of ol) {
        var a1 = parseHexTok(o1.split(" ")[0]);
        if (a1 > 0x10000) hits1.push(a1);
    }
    for (var hh of hits1.slice(0, 6)) {
        EC("db 0x" + hh.toString(16) + " L900");
    }
    var out2 = ExecuteCommand2("s -d 0x" + sc.s.toString(16) + " L0x" + sc.c.toString(16) + " 0006301b");
    log("[V7] P5 hits(0006301b) " + sc.n + ":\n" + out2);
    var hits2 = [];
    for (var o2 of out2.split("\n")) {
        var a2 = parseHexTok(o2.split(" ")[0]);
        if (a2 > 0x10000) hits2.push(a2);
    }
    for (var h5 of hits2.slice(0, 4)) {
        EC("db 0x" + h5.toString(16) + " L800");
    }
}

// ---------------- P4: ladder 到后段 → SOS ----------------
log("[V7] PHASE4 sos at late position");
var ladder = ["c0000", "80000", "60000", "50000", "40000", "38000", "30000", "28000", "24000", "20000", "1c000"];
var lateSet = false;
for (var ld of ladder) {
    var r4 = ExecuteCommand2("!tt " + ld);
    if (r4.indexOf("Setting position") >= 0) { log("[V7] P4 late pos = " + ld); lateSet = true; break; }
    else log("[V7] P4 !tt " + ld + " failed");
}
EC(".loadby sos clr");
if (lateSet) {
    var n2e = EC("!name2ee AirExplorer.exe CloudClient.Templating.DispatcherInitializer.VerifyCustomIteratorRunner");
    var mdm = n2e.match(/MethodDesc:\s*([0-9a-f`]+)/i);
    if (mdm) {
        var md = mdm[1].replace(/`/g, "");
        EC("!dumpil 0x" + md);
    }
    EC("!dumpmodule 0x" + BASE.toString(16));
} else {
    log("[V7] P4 no late position available");
}
log("[V7] done");
}
