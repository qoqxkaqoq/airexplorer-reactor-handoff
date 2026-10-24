// PayloadScan v6 — native 驱动器决定性一击
// v5 实锤: 060041FA 的调用方在 0x7fff914c7000 区域, !ip2md 说 "not in JIT code range"
//          → 驱动器是 native 代码(内存加载的 Reactor 运行时), 不是托管 JIT
// v5 实锤: 06003909 桩窗口 = 多方法族回填区(6 方法: codesize 0x89D/0x11/0xB2/0xE2/0x121/0x752)
// v6 阶段:
//   P1 TTD.Memory 写查询(同 v5, 06003909 窗口 0x2000)
//   P2 !tt 首事件 → lm / !address / u native 区 / MZ 检查
//   P3 bp writerIP 命中#1 → TTD "e"(执行)查询 native 模块区 → 执行 IP 直方图 →
//      热点 top → !tt 热点 → u 反汇编(解密循环 native 代码!)
//   P4 !name2ee → 060041FA 的 MD → !dumpil
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
function hexW(v) { return ("00000000" + (v >>> 0).toString(16)).slice(-8); }

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
log("[V6] module AirExplorer base=0x" + BASE.toString(16) + " modules=" + modList.length);
for (var ml of modList) log("[V6]   mod " + ml.name + " base=0x" + ml.base.toString(16) + " size=0x" + (ml.end - ml.base).toString(16));
if (!BASE) { log("[V6] FATAL no AirExplorer module"); return; }
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
function EC(cmd) { var out = ExecuteCommand2(cmd); log("[V6|CMD] " + cmd + "\n" + out); return out; }
function memReadable(a) {
    try { host.memory.readMemoryValues(a, 1, 1); return true; } catch (e) { return false; }
}
function evPos(w) {
    try { if (w.TimeStart !== undefined && w.TimeStart !== null) return (String(w.TimeStart.Sequence) + ":" + String(w.TimeStart.Steps)).replace(/0x/g, ""); } catch (e) { }
    try { if (w.Position !== undefined && w.Position !== null) return String(w.Position).replace(/0x/g, ""); } catch (e) { }
    return "undef";
}
function dumpRegs() {
    var regs;
    try { regs = host.currentThread.Registers.User; } catch (e2) { log("[V6] no regs"); return null; }
    var names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
    var rd = {};
    for (var rn of names) {
        try { var v = Number(regs[rn]); rd[rn] = isFinite(v) ? v : 0; } catch (e) { }
    }
    var s = "";
    for (var k in rd) s += k + "=0x" + rd[k].toString(16) + " ";
    log("[V6] REGS " + s);
    return rd;
}

var TARGETS = [
    { tok: "06003909", rva: 0x00334EB0, win: 0x2000 },
    { tok: "06002BD1", rva: 0x0024EA40, win: 0x800 },
    { tok: "060042B0", rva: 0x0040EE88, win: 8 },
    { tok: "060042B1", rva: 0x0040F2A4, win: 8 },
    { tok: "0600212A", rva: 0x00195D18, win: 16 },
];

// ---------------- P1 ----------------
log("[V6] PHASE1 TTD.Memory");
var allEvents = [];
var writerIPs = [];
var firstPos = {};
for (var t of TARGETS) {
    var va = BASE + t.rva;
    var tw = t.win;
    var cnt = 0;
    try {
        var ws = session.TTD.Memory(va, va + tw, "w");
        for (var w of ws) {
            cnt++;
            var addr = (w.Address !== undefined && w.Address !== null) ? Number(w.Address) : (va + (cnt - 1) * 4);
            var ev = { tok: t.tok, addr: addr, size: Number(w.Size), ip: Number(w.IP), val: Number(w.Value), pos: evPos(w) };
            allEvents.push(ev);
            if (firstPos[t.tok] === undefined) firstPos[t.tok] = ev.pos;
            var known = false;
            for (var ip2 of writerIPs) if (ip2 === ev.ip) known = true;
            if (!known) writerIPs.push(ev.ip);
            if (cnt <= 64)
                log("[V6] EVT " + ev.tok + " i=" + cnt + " addr=0x" + ev.addr.toString(16) + " size=" + ev.size
                    + " val=" + hexW(ev.val) + " ip=0x" + ev.ip.toString(16) + " pos=" + ev.pos);
            if (cnt > 2000) break;
        }
    } catch (e) { log("[V6] TTD.Memory failed for " + t.tok + ": " + e); }
    log("[V6] " + t.tok + " events=" + cnt);
}

// reconstruction for 06003909 / 06002BD1
for (var t3 of TARGETS) {
    if (t3.tok !== "06003909" && t3.tok !== "06002BD1") continue;
    var tw3 = t3.win;
    var bytes = {};
    for (var ev2 of allEvents) {
        if (ev2.tok !== t3.tok) continue;
        var off = ev2.addr - (BASE + t3.rva);
        if (off < 0 || off >= tw3) continue;
        var v = ev2.val >>> 0;
        for (var b = 0; b < ev2.size && (off + b) < tw3; b++) bytes[off + b] = (v >>> (8 * b)) & 0xFF;
    }
    var known3 = 0;
    for (var k3 in bytes) known3++;
    log("[V6] IL " + t3.tok + " reconstructed=" + known3 + "/" + tw3 + " bytes");
    // 只 log 有数据的 256B 行
    for (var row = 0; row < tw3; row += 256) {
        var has = false;
        for (var j3 = row; j3 < row + 256 && j3 < tw3; j3++) if (bytes[j3] !== undefined) { has = true; break; }
        if (!has) continue;
        var hexr = "";
        for (var j4 = row; j4 < row + 256 && j4 < tw3; j4++) hexr += (bytes[j4] === undefined ? "??" : hexB(bytes[j4]));
        log("[V6] IL " + t3.tok + " @" + row.toString(16) + " " + hexr);
    }
}

// ---------------- P2: !tt first backfill → native module discovery ----------------
log("[V6] PHASE2 tt + native module discovery");
var pos0909 = firstPos["06003909"];
if (pos0909 && pos0909 !== "undef") {
    EC("!tt " + pos0909);
    var rd = dumpRegs();
    EC("lm");
    // writerIP 之外, k 里应该有 native 基址。直接看 v5 已知形态: 栈上 0x7fff914c7000
    EC("k 15");
    // 从寄存器/栈找 native 基址: 取所有 0x7ff 开头且 modOf='?' 的地址, 对齐 0x1000
    var natBase = 0;
    if (rd) {
        // 先试 rsp 附近 dps 已在 k 中; 用 r13/r14? v5 显示 0x7fff914c7000 出现在 k 第 7 行 RetAddr
        // 动态解析 k
        var kOut = ExecuteCommand2("k 15");
        var cands = [];
        var lkArr = kOut.split("\n");
        for (var lk of lkArr) {
            var cols = lk.trim().split(/\s+/);
            for (var ci = 1; ci < cols.length && ci <= 2; ci++) {
                var cc = cols[ci].replace(/`/g, "").replace(/^0x/, "");
                if (cc.length >= 12 && /^[0-9a-f]+$/i.test(cc)) {
                    var vv = parseInt(cc, 16);
                    if (isFinite(vv) && vv > 0x7ff000000000 && modOf(vv) === "?") cands.push(vv);
                }
            }
        }
        cands.sort(function (a, b) { return a - b; });
        log("[V6] P2 native addrs from k: " + cands.map(function (x) { return "0x" + x.toString(16); }).join(", "));
        if (cands.length > 0) {
            var lo = cands[0] & 0xFFFFFFFFFFFF0000;
            // 向下找直到不可读(基址)
            natBase = lo;
            for (var down = 0; down < 16; down++) {
                var probe = lo - down * 0x10000;
                if (!memReadable(probe)) { natBase = probe + 0x10000; break; }
                natBase = probe;
            }
        }
    }
    if (natBase) {
        log("[V6] P2 native base candidate = 0x" + natBase.toString(16));
        EC("ln 0x" + natBase.toString(16));
        EC("!address 0x" + natBase.toString(16));
        EC("dps 0x" + natBase.toString(16) + " L4");
        EC("u 0x" + natBase.toString(16) + " L60");
        // 头部 MZ?
        var mz = readBytesSafe(natBase, 2);
        log("[V6] P2 first bytes = " + (mz ? mz : "<unreadable>"));
        // 记下供 P3
        session.__natBase = natBase;
    }
}
function readBytesSafe(a, n) {
    try {
        var vals = host.memory.readMemoryValues(a, n, 1);
        var h = "";
        for (var v of vals) h += hexB(Number(v) & 0xFF);
        return h;
    } catch (e) { return null; }
}

// ---------------- P3: writerIP bp → native execute heatmap ----------------
log("[V6] PHASE3 native execute heatmap");
if (writerIPs.length > 0) {
    var wip = writerIPs[0];
    var ipHex = "0x" + wip.toString(16);
    var set = memReadable(wip);
    var tries = 0;
    while (!set && tries < 60) { tries++; ExecuteCommand2("sxe ld"); ExecuteCommand2("g"); set = memReadable(wip); if (set) break; }
    if (set) {
        ExecuteCommand2("bp " + ipHex);
        try { ExecuteCommand2("g"); } catch (e) { log("[V6] P3 g#1 threw: " + e); }
        log("[V6] P3 ---- HIT#1 ----");
        var rd3 = dumpRegs();
        // native 基址: 重新从 k 解析 (此刻在 WriteInt32, 栈上有 native 帧信息)
        var k3 = ExecuteCommand2("k 12");
        var natB = 0;
        var arr = [];
        var lks = k3.split("\n");
        for (var l2 of lks) {
            var cs = l2.trim().split(/\s+/);
            for (var c4 = 1; c4 < cs.length && c4 <= 2; c4++) {
                var c5 = cs[c4].replace(/`/g, "").replace(/^0x/, "");
                if (c5.length >= 12 && /^[0-9a-f]+$/i.test(c5)) {
                    var v5 = parseInt(c5, 16);
                    if (isFinite(v5) && v5 > 0x7ff000000000 && modOf(v5) === "?") arr.push(v5);
                }
            }
        }
        if (arr.length > 0) {
            arr.sort(function (a, b) { return a - b; });
            natB = arr[0] & 0xFFFFFFFFFFFF0000;
            for (var d2 = 0; d2 < 16; d2++) {
                var p2 = (arr[0] & 0xFFFFFFFFFFFF0000) - d2 * 0x10000;
                if (!memReadable(p2)) { natB = p2 + 0x10000; break; }
                natB = p2;
            }
        }
        log("[V6] P3 native base = 0x" + natB.toString(16));
        if (natB) {
            EC("ln 0x" + natB.toString(16));
            // 执行查询: native 模块 64KB 窗口
            var nbEnd = natB + 0x10000;
            var hist = {};
            var eCnt = 0;
            try {
                var es = session.TTD.Memory(natB, nbEnd, "e");
                for (var ee of es) {
                    eCnt++;
                    var ipE = Number(ee.IP);
                    if (hist[ipE] === undefined) hist[ipE] = 0;
                    hist[ipE]++;
                    if (eCnt > 200000) break;
                }
            } catch (e) { log("[V6] TTD exec query failed: " + e); }
            log("[V6] P3 exec events=" + eCnt + " uniqueIPs=" + Object.keys(hist).length);
            // top 30 热点
            var pairs = [];
            for (var ipH in hist) pairs.push({ ip: Number(ipH), c: hist[ipH] });
            pairs.sort(function (a, b) { return b.c - a.c; });
            for (var pi = 0; pi < Math.min(30, pairs.length); pi++)
                log("[V6] HOT 0x" + pairs[pi].ip.toString(16) + " (base+0x" + (pairs[pi].ip - natB).toString(16) + ") count=" + pairs[pi].c);
            // 最热 IP 处反汇编 + !tt
            if (pairs.length > 0) {
                var hot = pairs[0].ip;
                // 找一个它的执行 pos: 重新查询该 IP 附近窗口的执行事件拿 pos
                try {
                    var es2 = session.TTD.Memory(hot, hot + 1, "e");
                    var firstE = null, lastE = null, nE = 0;
                    for (var e2 of es2) {
                        nE++;
                        if (!firstE) firstE = evPos(e2);
                        lastE = evPos(e2);
                        if (nE >= 100000) break;
                    }
                    log("[V6] P3 hotIP 0x" + hot.toString(16) + " execCount=" + nE + " firstPos=" + firstE + " lastPos=" + lastE);
                    if (lastE) {
                        EC("!tt " + lastE);
                        dumpRegs();
                        EC("u @rip-0x80 L40");
                        EC("u @rip L10");
                        EC("k 12");
                    }
                } catch (e) { log("[V6] hotIP pos query failed: " + e); }
                // 全区反汇编: 解密循环区域
                if (pairs.length > 3) {
                    var lo2 = pairs[0].ip, hi2 = pairs[0].ip;
                    for (var p6 of pairs) { if (p6.c < 10) continue; if (p6.ip < lo2) lo2 = p6.ip; if (p6.ip > hi2) hi2 = p6.ip; }
                    log("[V6] P3 hot range 0x" + lo2.toString(16) + " - 0x" + hi2.toString(16) + " span=0x" + (hi2 - lo2).toString(16));
                    EC("u 0x" + (lo2 - 0x20).toString(16) + " L" + Math.min(200, (hi2 - lo2) / 4 + 80));
                }
            }
        }
        ExecuteCommand2("bc *");
    } else {
        log("[V6] bp never readable");
    }
}

// ---------------- P4: name2ee → dumpil 060041FA ----------------
log("[V6] PHASE4 name2ee dumpil");
EC(".loadby sos clr");
var n2e = EC("!name2ee AirExplorer.exe CloudClient.Templating.DispatcherInitializer.VerifyCustomIteratorRunner");
var mdm = n2e.match(/MethodDesc:\s*([0-9a-f`]+)/i);
if (mdm) {
    var md = mdm[1].replace(/`/g, "");
    EC("!dumpil 0x" + md);
}
// 驱动器若为 native, 060041FA 的 MD 无用; 但 06003909 族方法的 IL 已由 P1 重建。
// 额外: dumpmodule 看有没有 token->IL 接口
EC("!dumpmodule 0x" + BASE.toString(16));
log("[V6] done");
}
