// PayloadScan v4 — TTD 战役：抓回填例程反汇编 + 负载明文 + SOS 直接读池/门控
// v3 教训: ExecuteCommand 输出不进 debugLog → v4 全部 log(ExecuteCommand(...))
// 阶段:
//   P1 TTD.Memory 写查询(目标表) → 事件/明文 IL/位置
//   P2 !tt 到关键回填时刻 → 寄存器/栈/反汇编
//   P3 writerIP bp + g 重放 → 解密循环反汇编(ln/u/k/dps 全 log)
//   P4 SOS: .loadby sos clr + !bpmd 三个关键方法 → g 抓 key/ct 参数(dumparray)
//   P5 trace 末尾: dumpheap 门控实例 + 模板类 → 静态字段 → 解密池 byte[] 全量 db
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
log("[V4] module AirExplorer base=0x" + BASE.toString(16) + " modules=" + modList.length);
if (!BASE) { log("[V4] FATAL no AirExplorer module"); return; }
function modOf(a) { for (var x of modList) if (a >= x.base && a < x.end) return x.name; return "?"; }
function memReadable(a) {
    try {
        var out = ExecuteCommand2("db 0x" + a.toString(16) + " L1");
        return out.indexOf("??") < 0;
    } catch (e) { return false; }
}
function ExecuteCommand2(cmd) {
    var out = "";
    try { out = host.namespace.Debugger.Utility.Control.ExecuteCommand(cmd); }
    catch (e) { return "ERR: " + e; }
    return out;
}
function EC(cmd) { var out = ExecuteCommand2(cmd); log("[V4|CMD] " + cmd + "\n" + out); return out; }
function readBytes(addr, n) {
    var out = [];
    try {
        var vals = host.memory.readMemoryValues(addr, n, 1);
        for (var v of vals) out.push(Number(v) & 0xFF);
    } catch (e) { }
    return out;
}
function dumpMem(tag, addr, n) {
    var bs = readBytes(addr, n);
    if (bs.length === 0) { log("[V4] " + tag + "@0x" + addr.toString(16) + " <unreadable>"); return; }
    var hex = "";
    for (var b of bs) hex += hexB(b);
    log("[V4] " + tag + "@0x" + addr.toString(16) + " " + hex);
}
function evPos(w) {
    try { if (w.TimeStart !== undefined && w.TimeStart !== null) return (String(w.TimeStart.Sequence) + ":" + String(w.TimeStart.Steps)).replace(/0x/g, ""); } catch (e) { }
    try { if (w.Position !== undefined && w.Position !== null) return String(w.Position).replace(/0x/g, ""); } catch (e) { }
    return "undef";
}
function dumpRegs() {
    var regs;
    try { regs = host.currentThread.Registers.User; } catch (e2) { log("[V4] no regs"); return null; }
    var names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
    var rd = {};
    for (var rn of names) {
        try { var v = Number(regs[rn]); rd[rn] = isFinite(v) ? v : 0; } catch (e) { }
    }
    var s = "";
    for (var k in rd) s += k + "=0x" + rd[k].toString(16) + " ";
    log("[V4] REGS " + s);
    return rd;
}
function dumpNonStackMem(rd) {
    var rsp = rd.rsp, dumped = 0;
    for (var rn of ["rsi", "rdi", "rdx", "rcx", "r8", "r9", "rax", "rbx", "r10", "r11", "r12", "r13", "r14", "r15"]) {
        if (dumped >= 8) break;
        var a = rd[rn];
        if (!isFinite(a) || a < 0x10000 || a >= 0x7ff000000000) continue;
        if (modOf(a) !== "?") continue;
        if (rsp && Math.abs(a - rsp) < 0x10000) continue;
        dumpMem("mem[" + rn + "]", a - 0x10, 0x60);
        dumped++;
    }
}

var TARGETS = [
    { tok: "0600212A", rva: 0x00195D18, win: 16 },
    { tok: "06003909", rva: 0x00334EB0, win: 16 },
    { tok: "06002BD1", rva: 0x0024EA40, win: 16 },
    { tok: "06004282", rva: 0x00407F38, win: 0x2000 },
    { tok: "0600418B", rva: 0x003FAA64, win: 0x400 },
    { tok: "06004196", rva: 0x003FDA7C, win: 0x800 },
    { tok: "060042B0", rva: 0x0040EE88, win: 0x600 },
    { tok: "060042B1", rva: 0x0040F2A4, win: 0x200 },
];

// ---------------- P1: TTD.Memory write queries ----------------
log("[V4] PHASE1 TTD.Memory");
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
            if (tw <= 64 || cnt <= 24)
                log("[V4] EVT " + ev.tok + " i=" + cnt + " addr=0x" + ev.addr.toString(16) + " size=" + ev.size
                    + " val=" + hexW(ev.val) + " ip=0x" + ev.ip.toString(16) + " pos=" + ev.pos);
            if (cnt > 8 + tw / 4) break;
        }
    } catch (e) { log("[V4] TTD.Memory failed for " + t.tok + ": " + e); }
    log("[V4] " + t.tok + " events=" + cnt);
}

// IL reconstruction
for (var t3 of TARGETS) {
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
    log("[V4] IL " + t3.tok + " reconstructed=" + known3 + "/" + tw3 + " bytes");
    for (var row = 0; row < tw3; row += 256) {
        var hexr = "";
        for (var j3 = row; j3 < row + 256 && j3 < tw3; j3++) hexr += (bytes[j3] === undefined ? "??" : hexB(bytes[j3]));
        log("[V4] IL " + t3.tok + " @" + row.toString(16) + " " + hexr);
    }
}

// ---------------- P2: !tt to first backfill of key targets ----------------
log("[V4] PHASE2 tt-to-backfill");
var ttTargets = ["06003909", "06004282", "0600418B", "060042B1"];
for (var tk of ttTargets) {
    var pos = firstPos[tk];
    if (!pos || pos === "undef") { log("[V4] P2 " + tk + " no pos"); continue; }
    log("[V4] P2 ---- " + tk + " pos=" + pos + " ----");
    try { EC("!tt " + pos); } catch (e) { log("[V4] !tt " + tk + " failed: " + e); }
    var rd = dumpRegs();
    if (rd) {
        dumpNonStackMem(rd);
        EC("k 15");
        EC("dps @rsp L30");
        EC("u @rip-0x80 L34");
        EC("u @rip L20");
    }
}

// ---------------- P3: writerIP bp + g replay ----------------
log("[V4] PHASE3 writerIP");
if (writerIPs.length > 0) {
    var wip = writerIPs[0];
    log("[V4] writerIPs all: " + writerIPs.map(function (x) { return "0x" + x.toString(16); }).join(","));
    var ipHex = "0x" + wip.toString(16);
    EC("ln " + ipHex);
    EC("u " + ipHex + "-0x80 L48");
    // advance module loads until ip readable
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
        log("[V4] bp set on " + ipHex + " (tries=" + tries + ")");
        for (var hit = 1; hit <= 6; hit++) {
            try { ExecuteCommand2("g"); } catch (e) { log("[V4] P3 g#" + hit + " threw: " + e); break; }
            log("[V4] P3 ---- HIT#" + hit + " ----");
            EC("ln @rip");
            EC("u @rip-0xA0 L60");
            EC("u @rip L10");
            var rd3 = dumpRegs();
            if (rd3) { dumpNonStackMem(rd3); EC("k 15"); EC("dps @rsp L30"); }
        }
        ExecuteCommand2("bc *");
    } else {
        log("[V4] bp never readable after 60 tries");
    }
} else {
    log("[V4] no writerIPs found");
}

// ---------------- P4: SOS bpmd key methods ----------------
log("[V4] PHASE4 sos");
EC(".loadby sos clr");
EC("!EEVersion");
var bpmds = [
    "!bpmd AirExplorer.exe CloudClient.Templating.DispatcherInitializer.GenerateAlphabeticVerifier",
    "!bpmd AirExplorer.exe CloudClient.Templating.TemplateArgument.GenerateModularInitializer",
    "!bpmd AirExplorer.exe AirExplorer.Search.FinderMap.DirectDefinition",
];
for (var bm of bpmds) EC(bm);
var sosHits = 0;
for (var gi = 0; gi < 60; gi++) {
    try {
        var r = ExecuteCommand2("g");
        if (r.indexOf("reached end") >= 0 || r.indexOf("Running the trace to completion") >= 0) { log("[V4] P4 trace end at gi=" + gi); break; }
    } catch (e) { log("[V4] P4 g#" + gi + " threw: " + e); break; }
    sosHits++;
    log("[V4] P4 ---- SOS-BREAK gi=" + gi + " ----");
    var rd4 = dumpRegs();
    if (rd4) {
        for (var an of ["rcx", "rdx", "r8"]) {
            var a = rd4[an];
            if (a > 0x10000 && a < 0x7ff000000000 && modOf(a) === "?") EC("!dumparray 0x" + a.toString(16));
        }
        EC("!clrstack -a");
        EC("k 8");
    }
}
ExecuteCommand2("bc *");

// ---------------- P5: end of trace → managed state ----------------
log("[V4] PHASE5 end-state");
EC("g");
EC("!clrstack");
var am = EC("!dumpheap -type CloudClient.Models.AlphabeticModel");
var amAddr = null;
var lines = am.split("\n");
for (var ln of lines) {
    var mm = ln.match(/^\s*([0-9a-f`]+)\s+/i);
    if (mm && !amAddr) {
        var cand = mm[1].replace(/`/g, "");
        if (cand.length >= 12) amAddr = cand;
    }
}
log("[V4] P5 AlphabeticModel first instance = " + amAddr);
if (amAddr) {
    var dobj = EC("!dumpobj 0x" + amAddr);
    // MT of the class for statics
    var mtm = dobj.match(/MethodTable:\s*([0-9a-f`]+)/i);
    if (mtm) {
        var mt = mtm[1].replace(/`/g, "");
        EC("!dumpclass 0x" + mt);
    }
}
var ta = EC("!dumpheap -type CloudClient.Templating.TemplateArgument");
var taLines = ta.split("\n");
var taAddr = null, taMT = null;
for (var ln2 of taLines) {
    var m2 = ln2.match(/^\s*([0-9a-f`]+)\s+([0-9a-f`]+)\s+/i);
    if (m2 && !taAddr && m2[1].replace(/`/g, "").length >= 12) {
        taAddr = m2[1].replace(/`/g, "");
        taMT = m2[2].replace(/`/g, "");
    }
}
log("[V4] P5 TemplateArgument first instance=" + taAddr + " MT=" + taMT);
if (taMT) {
    var dc = EC("!dumpclass 0x" + taMT);
    log("[V4] P5 dumpclass full:\n" + dc);
    // find _ExtractorVisitors static value (byte[] ptr)
    var stfm = dc.match(/_ExtractorVisitors[^\n]*/i);
    log("[V4] P5 _ExtractorVisitors line: " + (stfm ? stfm[0] : "<none>"));
    var ptrm = dc.match(/_ExtractorVisitors[^0-9a-f]*([0-9a-f`]{12,})/i);
    if (ptrm) {
        var poolPtr = ptrm[1].replace(/`/g, "");
        log("[V4] P5 pool byte[] obj @ 0x" + poolPtr);
        var arr = EC("!dumpobj 0x" + poolPtr);
        log("[V4] P5 pool dumpobj:\n" + arr);
        var dm = arr.match(/Data:\s*([0-9a-f`]+)/i);
        var szm = arr.match(/Size:\s*(\d+)/i) || arr.match(/(\d+) items/i);
        if (dm) {
            var dataPtr = dm[1].replace(/`/g, "");
            var poolSize = szm ? parseInt(szm[1]) : 0x20000;
            if (poolSize > 0x100000) poolSize = 0x100000;
            log("[V4] P5 pool data @ 0x" + dataPtr + " size=" + poolSize + " dumping...");
            for (var off = 0; off < poolSize; off += 64) {
                var bs2 = readBytes(Number("0x" + dataPtr) + off, Math.min(64, poolSize - off));
                if (bs2.length === 0) { log("[V4] P5 pool unreadable at +" + off.toString(16)); break; }
                var hx = "";
                for (var b2 of bs2) hx += hexB(b2);
                log("[V4] POOL +" + off.toString(16) + " " + hx);
            }
        }
    } else {
        log("[V4] P5 pool static not parsed; raw dumpclass logged above");
    }
}
// gate booleans via instance if available
if (amAddr) {
    var vals = EC("!dumpobj 0x" + amAddr);
    log("[V4] P5 AlphabeticModel fields:\n" + vals);
}
log("[V4] done");

}
