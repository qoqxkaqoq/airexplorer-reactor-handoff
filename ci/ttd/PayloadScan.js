// PayloadScan v8 — A1 两字节补丁数据收集: 五桩 RVA 回填事件 → rbx(条目偏移) + ct 缓冲全读
// v6/v7 已证:
//   回填 = fat hdr(12B)+体前8B 写 exe 槽位(5 dword); rbx=条目偏移(Viewer资源) r10=rbx+0xA 游标(+4/dword)
//   r9=0x56FE8=Viewer资源大小; rsi=0x6e51d6f8 恒定; 写循环每 dword 一次(读ct→解密→写)
//   dump 库 = 纯 body 明文(0600390C 双向吻合); res 原文 @0x3E698 指纹:
//     b0ee75fc6be38b411b56 314bb1c35e624c7258b088e75ce40606 (hdr10B + ct16B)
// v8 目标:
//   P2 校准: 06003909 首事件枚举候选基址, 比对 res 原文指纹 → 确认 CTBASE(驱动器 ct 缓冲基址)
//   P3: 五目标(06002133/45/2A/57/27)首事件 → regs(rbx/r9/r10) → 读 CTBASE+rbx 全量(0x400B)
//       → [V8] ENT tok rbx=0x.. ct=<hex> → 离线 ks=ct^dump明文 → A1 两字节重加密
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
log("[V8] module AirExplorer base=0x" + BASE.toString(16) + " modules=" + modList.length);
if (!BASE) { log("[V8] FATAL no AirExplorer module"); return; }
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
function EC(cmd) { var out = ExecuteCommand2(cmd); log("[V8|CMD] " + cmd + "\n" + out); return out; }
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
    try { regs = host.currentThread.Registers.User; } catch (e2) { log("[V8] no regs"); return null; }
    var names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
    var rd = {};
    for (var rn of names) {
        try { var v = Number(regs[rn]); rd[rn] = isFinite(v) ? v : 0; } catch (e) { }
    }
    var s = "";
    for (var k in rd) s += k + "=0x" + rd[k].toString(16) + " ";
    log("[V8] REGS " + s);
    return rd;
}
function parseHexTok(s) {
    var t = String(s).replace(/`/g, "").replace(/^0x/, "");
    if (!/^[0-9a-f]+$/i.test(t) || t.length < 8) return 0;
    return parseInt(t, 16);
}

// res_ErrorReceiver.ValidatorViewer.bin 指纹: @0x3E698 (10B hdr) + @0x3E6A2 (16B ct)
var FPRINT = "b0ee75fc6be38b411b56" + "314bb1c35e624c7258b088e75ce40606";

var TARGETS = [
    { tok: "06003909", rva: 0x00334EB0, win: 0x2000, read: 0x400 },  // 对照(已知 rbx=0x3E698)
    { tok: "06002133", rva: 0x00196088, win: 0x400, read: 0x400 },   // P1: body[0x290] 16→17
    { tok: "06002145", rva: 0x001997C4, win: 0x400, read: 0x400 },   // P2: body[0x120] 16→17
    { tok: "0600212A", rva: 0x00195D18, win: 0x400, read: 0x100 },
    { tok: "06002157", rva: 0x0019A510, win: 0x400, read: 0x100 },
    { tok: "06002127", rva: 0x00195CD4, win: 0x400, read: 0x100 },
];

// ---------------- P1: 回填写事件 ----------------
log("[V8] PHASE1 TTD.Memory write events");
var allEvents = [];
var firstPos = {};
for (var t of TARGETS) {
    var va = BASE + t.rva;
    var cnt = 0;
    var evs = null;
    try { evs = session.TTD.Memory(va, va + t.win, "w"); } catch (e) { log("[V8] query fail " + t.tok + ": " + e); continue; }
    for (var w of evs) {
        cnt++;
        try {
            var a = Number(w.Address);
            var v = Number(w.Value) & 0xFFFFFFFF;
            var ip = Number(w.IP);
            allEvents.push({ tok: t.tok, addr: a, val: v, ip: ip });
            if (firstPos[t.tok] === undefined) firstPos[t.tok] = evPos(w);
            if (cnt <= 60) log("[V8] EVT " + t.tok + " i=" + cnt + " addr=0x" + a.toString(16) + " val=" + ("00000000" + (v >>> 0).toString(16)).slice(-8) + " ip=0x" + ip.toString(16) + " pos=" + evPos(w));
        } catch (e) { }
        if (cnt > 400) break;
    }
    log("[V8] " + t.tok + " events=" + cnt);
}

// 候选基址枚举
function collectCands(rd) {
    var cands = [];
    var names = ["r13", "r14", "r12", "r15", "rbp", "rsi", "rdi", "r8", "r9"];
    for (var rn of names) {
        var v = rd[rn];
        if (v > 0x10000 && v < 0x7ff000000000 && modOf(v) === "?") cands.push({ n: rn, b: v });
    }
    var spStr = ExecuteCommand2("dqs @rsp L40");
    var sl = spStr.split("\n");
    for (var ln of sl) {
        var mm = ln.match(/^\w+`(\w+)\s+([0-9a-f`]+)/i);
        if (mm) {
            var pv = parseHexTok(mm[2]);
            if (pv > 0x10000 && pv < 0x7ff000000000 && modOf(pv) === "?") cands.push({ n: "stk", b: pv });
        }
    }
    return cands;
}

// ---------------- P2: 06003909 校准 → CTBASE ----------------
log("[V8] PHASE2 calibrate ct buffer base via 06003909");
var CTBASE = 0;
var pos0909 = firstPos["06003909"];
if (pos0909 && pos0909 !== "undef") {
    EC("!tt " + pos0909);
    var rd = dumpRegs();
    if (rd) {
        log("[V8] P2 expected rbx=0x3e698 r10=0x3e6a2 r9=0x56fe8");
        var cands = collectCands(rd);
        var seen = {};
        for (var cand of cands) {
            if (seen[cand.b]) continue;
            seen[cand.b] = 1;
            // 读 base+0x3E698 L32 比对 res 原文指纹
            var h = readBytesSafe(cand.b + 0x3E698, 32);
            if (!h) continue;
            var hit = h.toLowerCase().indexOf(FPRINT) >= 0;
            log("[V8] P2 cand " + cand.n + ":0x" + cand.b.toString(16) + " @+0x3e698=" + h + (hit ? "  <<< FPRINT MATCH" : ""));
            if (hit && !CTBASE) CTBASE = cand.b;
        }
        // 兜底: res 原文可能在别处 — 用 ct16B 片段短指纹在候选±0x400000 范围 s 搜
        if (!CTBASE) {
            log("[V8] P2 no direct fingerprint match, fallback: search 8B fragment near cands");
            var frag = FPRINT.substr(20, 16); // ct[0:8] = 314bb1c35e624c72
            for (var cand2 of cands) {
                var plo = Math.floor((cand2.b - 0x400000) / 0x10000) * 0x10000;
                var out = ExecuteCommand2("s -b 0x" + plo.toString(16) + " L0x800000 " + frag.match(/../g).join(" "));
                var ol = out.split("\n");
                for (var o of ol) {
                    var aa = parseHexTok(o.split(" ")[0]);
                    if (aa > 0x10000) { log("[V8] P2 fragment hit: 0x" + aa.toString(16) + " (" + cand2.n + " +0x" + (aa - cand2.b).toString(16) + ")"); if (!CTBASE) CTBASE = aa - 0x3E6A2; }
                }
                if (CTBASE) break;
            }
        }
        log("[V8] P2 CTBASE = " + (CTBASE ? "0x" + CTBASE.toString(16) : "<not found>"));
    }
}

// ---------------- P3: 五目标条目数据 ----------------
log("[V8] PHASE3 five targets entry dump");
for (var t2 of TARGETS) {
    if (t2.tok === "06003909") continue;
    var p2 = firstPos[t2.tok];
    if (!p2 || p2 === "undef") { log("[V8] " + t2.tok + " no events, skip"); continue; }
    EC("!tt " + p2);
    var rd2 = dumpRegs();
    if (!rd2) continue;
    var rbx2 = rd2.rbx, r92 = rd2.r9;
    log("[V8] " + t2.tok + " rbx=0x" + rbx2.toString(16) + " r9=0x" + r92.toString(16) + " r10=0x" + rd2.r10.toString(16) + " rsi=0x" + rd2.rsi.toString(16));
    if (rbx2 < 0x1000 || rbx2 > 0x10000000) { log("[V8] " + t2.tok + " rbx implausible, skip"); continue; }
    var got = false;
    // 首选: CTBASE(若同资源 r9==0x56FE8)
    if (CTBASE && r92 === 0x56FE8) {
        var h1 = readBytesSafe(CTBASE + rbx2, t2.read);
        if (h1) { log("[V8] ENT " + t2.tok + " rbx=0x" + rbx2.toString(16) + " base=CTBASE ct=" + h1); got = true; }
    }
    if (!got) {
        // 兜底: 本事件候选基址枚举
        var cands2 = collectCands(rd2);
        var seen2 = {};
        for (var cd of cands2) {
            if (seen2[cd.b]) continue;
            seen2[cd.b] = 1;
            var h2 = readBytesSafe(cd.b + rbx2, t2.read);
            if (h2 && /[^0]/.test(h2)) {
                log("[V8] ENT " + t2.tok + " rbx=0x" + rbx2.toString(16) + " base=" + cd.n + ":0x" + cd.b.toString(16) + " ct=" + h2);
                got = true;
                break;
            }
        }
    }
    if (!got) log("[V8] ENT " + t2.tok + " <no buffer found>");
}

// ---------------- P4: 06003909 附近族条目(0600390A..06003911 槽位差已知) ----------------
// 供离线交叉验证条目连续性: CTBASE + 0x3E698 起 L0x1000 (06003909..0600390A 区)
if (CTBASE) {
    var h3 = readBytesSafe(CTBASE + 0x3E698, 0x400);
    log("[V8] CTBASE+0x3e698 L0x400 = " + (h3 || "<unread>"));
    // 资源头(0x0)与资源尾(0x56FD0)抽查
    log("[V8] CTBASE+0x0 L0x40 = " + (readBytesSafe(CTBASE, 0x40) || "<unread>"));
    log("[V8] CTBASE+0x56fb0 L0x38 = " + (readBytesSafe(CTBASE + 0x56FB0, 0x38) || "<unread>"));
}
log("[V8] done");
}
