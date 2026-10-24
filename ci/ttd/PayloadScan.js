// PayloadScan v5 — 决定性一击: TTD 回放态用 SOS 直接读回填后的解密 IL
// 已知(2026-10-25 v4c):
//   - 回填写入方 = Marshal.WriteInt32 的 NGEN 体(mscorlib_ni+0x570801)
//   - 调用链: 驱动器(0x7ff9ecea3ab9 JIT 帧) -> 060041FA VerifyCustomIteratorRunner(19B 壳) -> Marshal.WriteInt32
//   - dump MISSING 方法: 06003909 RequestVerifierTransformer::.ctor / 06002BD1(未知名)
//   - TTD 回放态 dumpheap/clrstack 不可用(GC in plan), 但 !ip2md/!dumpil 不需要 GC heap
// v5 阶段:
//   P1 TTD.Memory 写查询(目标表) → 事件/明文 IL/位置   (同 v4)
//   P2 !tt 到关键回填时刻 → 寄存器/栈/反汇编           (同 v4)
//   P3 writerIP bp + g, 命中#1 即 .loadby sos clr:
//      dps @rsp → retaddr → !ip2md → !dumpmd+!dumpil (060041FA 壳)
//      k 15 解析全部裸 JIT 帧地址 → 逐个 !ip2md → !dumpil (驱动器方法!)
//   P4 !dumpil <BASE> <token> 对全部 TARGETS(MISSING 方法真体直接到手)
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
log("[V5] module AirExplorer base=0x" + BASE.toString(16) + " modules=" + modList.length);
if (!BASE) { log("[V5] FATAL no AirExplorer module"); return; }
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
function EC(cmd) { var out = ExecuteCommand2(cmd); log("[V5|CMD] " + cmd + "\n" + out); return out; }
function readBytes(addr, n) {
    var out = [];
    try {
        var vals = host.memory.readMemoryValues(addr, n, 1);
        for (var v of vals) out.push(Number(v) & 0xFF);
    } catch (e) { }
    return out;
}
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
    try { regs = host.currentThread.Registers.User; } catch (e2) { log("[V5] no regs"); return null; }
    var names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
    var rd = {};
    for (var rn of names) {
        try { var v = Number(regs[rn]); rd[rn] = isFinite(v) ? v : 0; } catch (e) { }
    }
    var s = "";
    for (var k in rd) s += k + "=0x" + rd[k].toString(16) + " ";
    log("[V5] REGS " + s);
    return rd;
}

var TARGETS = [
    { tok: "0600212A", rva: 0x00195D18, win: 16 },
    { tok: "06003909", rva: 0x00334EB0, win: 0x1000 },
    { tok: "06002BD1", rva: 0x0024EA40, win: 0x400 },
    { tok: "06004282", rva: 0x00407F38, win: 8 },
    { tok: "0600418B", rva: 0x003FAA64, win: 8 },
    { tok: "06004196", rva: 0x003FDA7C, win: 8 },
    { tok: "060042B0", rva: 0x0040EE88, win: 8 },
    { tok: "060042B1", rva: 0x0040F2A4, win: 8 },
];
// 注: win 收紧 — 060042B0/060042B1/06004282/0600418B/06004196 真体已在 dump,
//     只需确认是否回填(events>0); 06003909(win 0x1000) / 06002BD1(0x400) MISSING,
//     尽量多抓字节做已知明文 + 验证 !dumpil。

// ---------------- P1: TTD.Memory write queries ----------------
log("[V5] PHASE1 TTD.Memory");
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
            if (tw <= 64 || cnt <= 40)
                log("[V5] EVT " + ev.tok + " i=" + cnt + " addr=0x" + ev.addr.toString(16) + " size=" + ev.size
                    + " val=" + hexW(ev.val) + " ip=0x" + ev.ip.toString(16) + " pos=" + ev.pos);
            if (cnt > 8 + tw / 4) break;
        }
    } catch (e) { log("[V5] TTD.Memory failed for " + t.tok + ": " + e); }
    log("[V5] " + t.tok + " events=" + cnt);
}

// IL reconstruction (only for MISSING: 06003909 / 06002BD1)
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
    log("[V5] IL " + t3.tok + " reconstructed=" + known3 + "/" + tw3 + " bytes");
    for (var row = 0; row < tw3; row += 256) {
        var hexr = "";
        for (var j3 = row; j3 < row + 256 && j3 < tw3; j3++) hexr += (bytes[j3] === undefined ? "??" : hexB(bytes[j3]));
        if (hexr.indexOf("??") < 0 || hexr.indexOf(hexB(0)) >= 0) log("[V5] IL " + t3.tok + " @" + row.toString(16) + " " + hexr);
    }
}

// ---------------- P2: !tt to first backfill ----------------
log("[V5] PHASE2 tt-to-backfill");
var ttTargets = ["06003909", "06002BD1"];
for (var tk of ttTargets) {
    var pos = firstPos[tk];
    if (!pos || pos === "undef") { log("[V5] P2 " + tk + " no pos"); continue; }
    log("[V5] P2 ---- " + tk + " pos=" + pos + " ----");
    try { EC("!tt " + pos); } catch (e) { log("[V5] !tt " + tk + " failed: " + e); }
    var rd = dumpRegs();
    if (rd) { EC("k 15"); EC("dps @rsp L40"); }
}

// ---------------- P3: writerIP bp + g → SOS dumpil ----------------
log("[V5] PHASE3 writerIP + SOS");
if (writerIPs.length > 0) {
    var wip = writerIPs[0];
    log("[V5] writerIPs all: " + writerIPs.map(function (x) { return "0x" + x.toString(16); }).join(","));
    var ipHex = "0x" + wip.toString(16);
    EC("ln " + ipHex);
    var set = memReadable(wip);
    var tries = 0;
    while (!set && tries < 60) {
        tries++;
        ExecuteCommand2("sxe ld");
        ExecuteCommand2("g");
        set = memReadable(wip);
        if (set) break;
    }
    if (set) {
        ExecuteCommand2("bp " + ipHex);
        log("[V5] bp set on " + ipHex + " (tries=" + tries + ")");
        // HIT#1: 进入 SOS
        try { ExecuteCommand2("g"); } catch (e) { log("[V5] P3 g#1 threw: " + e); }
        log("[V5] P3 ---- HIT#1 ----");
        EC("ln @rip");
        var rd3 = dumpRegs();
        EC("k 15");
        EC("dps @rsp L10");
        // SOS 加载
        EC(".loadby sos clr");
        EC("!EEVersion");
        // retaddr (rsp+8) = 060041FA JIT 内
        var rsp = rd3 ? rd3.rsp : 0;
        // 解析 k 输出的全部 JIT 裸地址
        var kOut = ExecuteCommand2("k 15");
        var jitAddrs = [];
        var lineRe = /(?:^|\s)0{0,8}([0-9a-f]{6,16})`([0-9a-f]{4,16})\s{2,}/g;
        var altRe = /\s0{0,2}([0-9a-f]{8,16})\s{2,}0x0000([0-9a-f`]{8,16})/g;
        // k 行格式: <childsp> <retaddr> <callsite>. retaddr 列在第二列。
        var linesK = kOut.split("\n");
        for (var lk of linesK) {
            // 取第二列
            var cols = lk.trim().split(/\s+/);
            if (cols.length >= 2) {
                var c2 = cols[1].replace(/`/g, "").replace(/^0+/, "");
                if (c2.length >= 12) {
                    var v2 = parseInt(c2, 16);
                    if (isFinite(v2) && v2 > 0x7ff000000000 && modOf(v2) === "?") jitAddrs.push(v2);
                }
                // callsite 列也可能裸 (0x00007ff9`eceab1ae 形式)
                var c3 = (cols[2] || "").replace(/`/g, "").replace(/^0x0000/, "0x");
                if (/^0x[0-9a-f]{12,16}$/i.test(c3)) {
                    var v3 = parseInt(c3.slice(2), 16);
                    if (isFinite(v3) && v3 > 0x7ff000000000 && modOf(v3) === "?") jitAddrs.push(v3);
                }
            }
        }
        var uniq = [];
        for (var ja of jitAddrs) { var dup = false; for (var u of uniq) if (u === ja) dup = true; if (!dup) uniq.push(ja); }
        log("[V5] P3 JIT frame addrs: " + uniq.map(function (x) { return "0x" + x.toString(16); }).join(", "));
        var mdSeen = {};
        for (var fa of uniq) {
            var ip = EC("!ip2md 0x" + fa.toString(16));
            var mdm = ip.match(/MethodDesc:\s*([0-9a-f`]+)/i);
            if (mdm) {
                var md = mdm[1].replace(/`/g, "");
                if (!mdSeen[md]) {
                    mdSeen[md] = true;
                    log("[V5] P3 ---- md " + md + " (from 0x" + fa.toString(16) + ") ----");
                    EC("!dumpmd 0x" + md);
                    EC("!dumpil 0x" + md);
                }
            }
        }
        ExecuteCommand2("bc *");
        log("[V5] P3 done (1 hit only; SOS extracted)");
    } else {
        log("[V5] bp never readable after 60 tries");
    }
} else {
    log("[V5] no writerIPs found");
}

// ---------------- P4: !dumpil <BASE> <token> — 直接读回填后真体 ----------------
log("[V5] PHASE4 dumpil tokens");
var toks = ["06003909", "06002BD1", "060042B0", "060042B1", "0600418B", "06004196", "060041FA", "0600212A"];
for (var tk2 of toks) {
    log("[V5] P4 ---- dumpil " + tk2 + " ----");
    EC("!dumpil 0x" + BASE.toString(16) + " 0x" + tk2);
}
log("[V5] done");
}
