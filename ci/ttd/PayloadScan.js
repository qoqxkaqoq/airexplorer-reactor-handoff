// PayloadScan.js — TTD: locate the in-place backfill write of protected method bodies.
// Finds writes into the stub VA of target methods, prints TTD position/value/IP,
// then at the LAST write event: seek there, dump regs/stack/code/pointers to files.
// usage (cdb): .scriptrun <this.js>   after: !tt <pos> is handled inside via ExecuteCommand
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

    // target method body RVAs (from peekil, exes/AirExplorer_baseline_verified.exe)
    const TARGETS = [
        { tok: "0600212A", rva: 0x00195D18 },
        { tok: "06002133", rva: 0x00196088 },
        { tok: "06002127", rva: 0x00195CD4 },
    ];

    function getSession() {
        try { if (host.currentSession) return host.currentSession; } catch (e) { }
        return host.namespace.Debugger.Sessions.First();
    }
    var session = getSession();

    // module base of AirExplorer
    var base = 0;
    var proc = session.Processes.First();
    for (var m of proc.Modules) {
        var nm = String(m.Name);
        if (nm.toLowerCase().indexOf("airexplorer") >= 0) {
            base = Number(m.BaseAddress);
            log("[PS] module " + nm + " base=0x" + base.toString(16));
            break;
        }
    }
    if (!base) { log("[PS] FATAL: AirExplorer module not found"); return; }

    var events = [];
    for (var t of TARGETS) {
        var va = base + t.rva;
        log("[PS] target " + t.tok + " va=0x" + va.toString(16));
        try {
            var ws = session.TTD.Memory(va, va + 16, "w");
            var cnt = 0;
            for (var w of ws) {
                cnt++;
                var ev = {
                    tok: t.tok, va: "0x" + va.toString(16),
                    pos: w.Position ? (String(w.Position.Sequence) + ":" + String(w.Position.Steps)) : String(w.Position),
                    size: Number(w.Size),
                    ip: ("0x" + Number(w.IP).toString(16)),
                    val: ("0x" + Number(w.Value).toString(16)),
                };
                events.push(ev);
                log("[PS] WRITE " + t.tok + " pos=" + ev.pos + " size=" + ev.size + " ip=" + ev.ip + " val=" + ev.val);
                if (cnt > 40) break;
            }
            log("[PS] " + t.tok + " writes=" + cnt);
        } catch (e) {
            log("[PS] TTD.Memory query failed for " + t.tok + ": " + e);
        }
    }

    // at the last event: seek + deep dump
    if (events.length > 0) {
        var last = events[events.length - 1];
        log("[PS] seeking to " + last.pos);
        try {
            host.namespace.Debugger.Utility.Control.ExecuteCommand("!tt " + last.pos);
            var regs = host.currentThread.Registers.User;
            var regDump = {};
            try {
                for (var rn of ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip"]) {
                    regDump[rn] = "0x" + Number(regs[rn]).toString(16);
                }
            } catch (e) { log("[PS] regs x86 failed: " + e); try { for (var rn2 of ["rax", "rcx", "rdx", "rbx", "rsi", "rdi", "rsp", "rbp", "rip", "r8", "r9"]) regDump[rn2] = "0x" + Number(regs[rn2]).toString(16); } catch (e2) { } }
            var out = { targets: TARGETS, events: events, regs: regDump };

            // stack pointers that fall in payload VA window (base+0x620000-ish..base+0x920000)
            var payLo = base + 0x620000, payHi = base + 0x920000;
            var inPay = function (v) { return v >= payLo && v < payHi; };
            try {
                var sp = Number(regs.esp !== undefined ? regs.esp : regs.rsp);
                var stackWords = read1(sp, 512);
                var ptrs = [];
                for (var i = 0; i + 3 < stackWords.length; i += 1) {
                    var v = (stackWords[i] | (stackWords[i+1] << 8) | (stackWords[i+2] << 16) | (stackWords[i+3] << 24)) >>> 0;
                    if (inPay(v) || (v >= base && v < base + 0x927BA4)) ptrs.push({ off: i * 4, val: "0x" + v.toString(16), inPayload: inPay(v) });
                }
                out.stackPtrs = ptrs.slice(0, 80);
            } catch (e) { log("[PS] stack scan failed: " + e); }

            // dump code at rip and data at each payload pointer
            var files = [];
            function dumpFile(name, addr, len) {
                try {
                    var bytes = read1(addr, len);
                    var f = host.namespace.Debugger.Utility.FileSystem.CreateFile("C:\\out\\" + name);
                    f.Write(bytes.map(b => String.fromCharCode(b)).join(""));
                    files.push(name + " @" + ("0x" + addr.toString(16)) + " " + len + "B");
                } catch (e) { log("[PS] dump " + name + " failed: " + e); }
            }
            try {
                var rip = Number(regs.eip !== undefined ? regs.eip : regs.rip);
                dumpFile("code_at_rip.bin", rip - 0x40, 0x180);
            } catch (e) { }
            if (out.stackPtrs) {
                var k = 0;
                for (var p of out.stackPtrs) {
                    if (p.inPayload && k < 6) {
                        var a = parseInt(p.val, 16);
                        dumpFile("payload_at_ptr" + k + ".bin", a - 0x40, 0x200);
                        k++;
                    }
                }
            }
            out.files = files;

            // full body bytes at each target VA now (post-backfill)
            var bodies = {};
            for (var t2 of TARGETS) {
                try {
                    var bb = read1(base + t2.rva, 96);
                    bodies[t2.tok] = bb.map(b => b.toString(16).padStart(2, "0")).join("");
                } catch (e) { }
            }
            out.bodiesAfter = bodies;

            var txt = JSON.stringify(out);
            var f2 = host.namespace.Debugger.Utility.FileSystem.CreateFile("C:\\out\\payloadscan.json");
            f2.Write(txt);
            log("[PS] payloadscan.json written, " + txt.length + " bytes");
        } catch (e) {
            log("[PS] deep dump failed: " + e);
        }
    } else {
        log("[PS] NO WRITE EVENTS FOUND — stubs were never written in trace");
    }
    log("[PS] done");
}
