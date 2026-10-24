// PayloadScan.js v3 — TTD: capture the in-place backfill of protected method bodies.
// v2 lessons (run 40123180425):
//  - TTD.Memory WRITE events DO hit the stub VAs; writer IP is a single fixed address.
//  - Written values are PLAINTEXT IL (tiny-header getters decoding to ldfld 04000C3B/C3D + ret).
//  - w.Position was undefined (trace unindexed) => !tt <undefined> broke all deep dumps.
//  - x64 process (AnyCPU ILONLY PE32 runs as native x64) => use rax/rsp/rip names.
// v3 strategy (index-free):
//  1) TTD.Memory 16B windows on 4 targets => writer IP + first 16B plaintext IL per body.
//  2) Identify writer IP statically: module, ln, u (disasm) — works even at B:0.
//  3) Set bp/bu on writer IP and replay FORWARD with g — at each hit dump full x64 regs,
//     stack trace (k), stack pointers (dps), and memory around candidate data registers.
//  Everything goes to cdb.log (debugLog) — no file writes needed.
"use strict";
function initializeScript() {
    return [new host.apiVersionSupport(1, 7)];
}
function invokeScript() {
    mainImpl();
}
function mainImpl() {
    const log = x => host.diagnostics.debugLog(x + "\n");
    const hexByte = b => ("0" + b.toString(16)).slice(-2);
    const readBytes = (addr, n) => host.memory.readMemoryValues(addr, n, 1).map(v => Number(v));

    // target stub RVAs (tokrva on exes/AirExplorer_baseline_verified.exe)
    // 0600212A: known plaintext (validation); 06003909/06002BD1/06004204: forcedump-failed bodies (new intel)
    // 06004282 DirectDefinition (win 0x2000): FULL body backfill capture = string-pool key source (0600418B caller)
    const TARGETS = [
        { tok: "0600212A", rva: 0x00195D18, win: 16 },
        { tok: "06003909", rva: 0x00334EB0, win: 16 },
        { tok: "06002BD1", rva: 0x0024EA40, win: 16 },
        { tok: "06004204", rva: 0x00407A00, win: 16 },
        { tok: "06004282", rva: 0x00407F38, win: 0x2000 },
    ];
    const WIN = 16;

    function getSession() {
        try { if (host.currentSession) return host.currentSession; } catch (e) { }
        return host.namespace.Debugger.Sessions.First();
    }
    var session = getSession();
    var proc = session.Processes.First();

    var base = 0;
    var modList = [];
    for (var m of proc.Modules) {
        var nm = String(m.Name);
        try { modList.push({ name: nm, base: Number(m.BaseAddress), end: Number(m.BaseAddress) + Number(m.Size) }); } catch (e) { }
        if (nm.toLowerCase().indexOf("airexplorer") >= 0 && !base) base = Number(m.BaseAddress);
    }
    log("[PS] module AirExplorer base=0x" + base.toString(16) + " modules=" + modList.length);
    if (!base) { log("[PS] FATAL: AirExplorer module not found"); return; }

    function modOf(addr) {
        for (var mm of modList) if (addr >= mm.base && addr < mm.end) return mm.name;
        return "?";
    }
    function memReadable(addr) {
        try { host.memory.readMemoryValues(addr, 1, 1); return true; } catch (e) { return false; }
    }
    function evPos(w) {
        try { if (w.Position) return String(w.Position); } catch (e) { }
        try { if (w.TimeStart) return String(w.TimeStart.Sequence) + ":" + String(w.TimeStart.Steps); } catch (e2) { }
        return null;
    }

    // ---- 1) write events per target (per-target window) ----
    var allEvents = [];
    var writerIPs = [];
    for (var t of TARGETS) {
        var va = base + t.rva;
        var tw = t.win || WIN;
        var cap = 8 + tw / 4;
        var cnt = 0;
        try {
            var ws = session.TTD.Memory(va, va + tw, "w");
            for (var w of ws) {
                cnt++;
                if (cnt === 1) {
                    var keys = "";
                    try { for (var kk in w) keys += kk + ","; } catch (e0) { }
                    log("[PS] EVT0 keys=" + keys + " typeofPos=" + (typeof w.Position) + " typeofTimeStart=" + (typeof w.TimeStart));
                }
                var addr = (w.Address !== undefined && w.Address !== null) ? Number(w.Address) : (va + (cnt - 1) * 4);
                var ev = { tok: t.tok, addr: addr, size: Number(w.Size), ip: Number(w.IP), val: Number(w.Value), pos: evPos(w) };
                allEvents.push(ev);
                if (tw <= 64)
                    log("[PS] EVT tok=" + ev.tok + " i=" + cnt + " addr=0x" + ev.addr.toString(16) + " size=" + ev.size
                        + " val=0x" + (ev.val >>> 0).toString(16) + " ip=0x" + ev.ip.toString(16) + " pos=" + ev.pos);
                var known = false;
                for (var ip2 of writerIPs) if (ip2 === ev.ip) known = true;
                if (!known) writerIPs.push(ev.ip);
                if (cnt > cap) break;
            }
        } catch (e) { log("[PS] TTD.Memory failed for " + t.tok + ": " + e); }
        log("[PS] " + t.tok + " events=" + cnt);
    }

    // ---- 2) reconstruct first N bytes per target from events (chronological, LE dwords) ----
    for (var t3 of TARGETS) {
        var tw3 = t3.win || WIN;
        var bytes = {};
        for (var ev2 of allEvents) {
            if (ev2.tok !== t3.tok) continue;
            var off = ev2.addr - (base + t3.rva);
            if (off < 0 || off >= tw3) continue;
            var v = ev2.val >>> 0;
            for (var b = 0; b < ev2.size && (off + b) < tw3; b++) bytes[off + b] = (v >>> (8 * b)) & 0xFF;
        }
        var known3 = 0;
        for (var k3 in bytes) known3++;
        log("[PS] IL " + t3.tok + " reconstructed=" + known3 + "/" + tw3 + " bytes");
        if (tw3 <= 64) {
            var hex = "";
            for (var i3 = 0; i3 < tw3; i3++) hex += (bytes[i3] === undefined ? "??" : hexByte(bytes[i3]));
            log("[PS] IL " + t3.tok + " first" + tw3 + "=" + hex);
        } else {
            for (var row = 0; row < tw3; row += 256) {
                var hexr = "";
                for (var j3 = row; j3 < row + 256 && j3 < tw3; j3++) hexr += (bytes[j3] === undefined ? "??" : hexByte(bytes[j3]));
                log("[PS] IL " + t3.tok + " @" + row.toString(16) + " " + hexr);
            }
        }
    }

    // ---- 3) static identification of writer IPs ----
    log("[PS] writerIPs: " + writerIPs.map(x => "0x" + x.toString(16)).join(" "));
    for (var wip of writerIPs.slice(0, 3)) {
        log("[PS] writerIP 0x" + wip.toString(16) + " module=" + modOf(wip) + " readable=" + memReadable(wip));
        try { host.namespace.Debugger.Utility.Control.ExecuteCommand("ln 0x" + wip.toString(16)); } catch (e) { }
        try { host.namespace.Debugger.Utility.Control.ExecuteCommand("u 0x" + (wip - 0x30).toString(16) + " L24"); } catch (e) { }
    }

    // ---- 4) bp on writer IP + forward replay: live regs/stack at each backfill write ----
    if (writerIPs.length > 0) {
        var bip = writerIPs[0];
        var ipHex = "0x" + bip.toString(16);
        var set = false;
        try { host.namespace.Debugger.Utility.Control.ExecuteCommand("bp " + ipHex); set = memReadable(bip); } catch (e) { }
        var tries = 0;
        while (!set && tries < 60) {
            tries++;
            try {
                host.namespace.Debugger.Utility.Control.ExecuteCommand("sxe ld");
                host.namespace.Debugger.Utility.Control.ExecuteCommand("g");
                set = memReadable(bip);
                if (set) {
                    host.namespace.Debugger.Utility.Control.ExecuteCommand("bp " + ipHex);
                    host.namespace.Debugger.Utility.Control.ExecuteCommand("sxd ld");
                    break;
                }
            } catch (e) { log("[PS] sxe-ld advance " + tries + " failed: " + e); break; }
        }
        if (!set) { try { host.namespace.Debugger.Utility.Control.ExecuteCommand("bu " + ipHex); } catch (e) { } log("[PS] bp direct failed; bu fallback set"); }
        log("[PS] bp set=" + set + " on " + ipHex + " (tries=" + tries + ")");

        for (var hit = 1; hit <= 14; hit++) {
            try {
                host.namespace.Debugger.Utility.Control.ExecuteCommand("g");
            } catch (e) { log("[PS] g#" + hit + " threw: " + e); break; }
            try { host.namespace.Debugger.Utility.Control.ExecuteCommand("!tt"); } catch (e) { }
            var regs;
            try { regs = host.currentThread.Registers.User; } catch (e2) { log("[PS] hit#" + hit + " no regs"); break; }
            var rd = {};
            var names = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
            for (var rn of names) {
                try { var v4 = Number(regs[rn]); rd[rn] = isFinite(v4) ? ("0x" + v4.toString(16)) : String(regs[rn]); } catch (e) { }
            }
            log("[PS] HIT#" + hit + " regs " + JSON.stringify(rd));
            try { host.namespace.Debugger.Utility.Control.ExecuteCommand("k 12"); } catch (e) { }
            try { host.namespace.Debugger.Utility.Control.ExecuteCommand("dps @rsp L30"); } catch (e) { }
            // memory around candidate data pointers (skip module/stack addresses)
            var dumped = 0;
            var rsp = 0;
            try { rsp = Number(regs.rsp); } catch (e) { }
            for (var rn2 of ["rsi", "rdi", "rdx", "rcx", "r8", "r9", "rax", "rbx", "r10", "r11", "r12", "r13", "r14", "r15"]) {
                if (dumped >= 6) break;
                try {
                    var a = Number(regs[rn2]);
                    if (!isFinite(a) || a < 0x10000 || a >= 0x7ff000000000) continue;
                    var inMod = false;
                    for (var mm2 of modList) if (a >= mm2.base && a < mm2.end) { inMod = true; break; }
                    if (inMod) continue;
                    if (rsp && Math.abs(a - rsp) < 0x10000) continue;
                    var mb = readBytes(a - 0x10, 0x60);
                    log("[PS] HIT#" + hit + " mem[" + rn2 + "]@0x" + a.toString(16) + " " + mb.map(hexByte).join(""));
                    dumped++;
                } catch (e3) { }
            }
        }
        try { host.namespace.Debugger.Utility.Control.ExecuteCommand("bc *"); } catch (e) { }
    }

    // ---- 5) bodies at target VAs at final position (partial backfill view) ----
    for (var t5 of TARGETS) {
        try {
            var bb = readBytes(base + t5.rva, 32);
            log("[PS] BODYNOW " + t5.tok + " " + bb.map(hexByte).join(""));
        } catch (e) { }
    }
    log("[PS] done");
}
