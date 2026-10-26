#!/usr/bin/env python3
# k26vm.py — interprocedural interpreter for the Reactor runtime flattened methods.
# Models streams/readers/delegates concretely; recurses into small plaintext callees.
import sys, struct
sys.path.insert(0, r'airexplorer-reactor-handoff/work'); sys.path.insert(0, r'work_a1'); sys.path.insert(0, r'work_a1/k26')
import flat
from flatvm import Interp, Mem, Dyn, BINI, COND
import mref

M32 = 0xFFFFFFFF
EXE = r'airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe'
_d = open(EXE, 'rb').read()
pe = struct.unpack_from('<I', _d, 0x3C)[0]
coff = pe + 4
nsec, = struct.unpack_from('<H', _d, coff + 2)
optsz, = struct.unpack_from('<H', _d, coff + 16)
opt = coff + 20
sec0 = opt + optsz
SECS = []
for i in range(nsec):
    o = sec0 + i * 40
    va = struct.unpack_from('<I', _d, o + 12)[0]; vsz = struct.unpack_from('<I', _d, o + 8)[0]
    raw = struct.unpack_from('<I', _d, o + 20)[0]; rawsz = struct.unpack_from('<I', _d, o + 16)[0]
    SECS.append((va, vsz, raw, rawsz))
def rva2off(rva):
    for va, vsz, raw, rawsz in SECS:
        if va <= rva < va + max(vsz, rawsz): return raw + (rva - va)

REFS, METHS, FS, ROWS, STREAMS, SI, BI = mref.load(EXE)

# #US reader
USO = STREAMS['#US'][0] if isinstance(STREAMS.get('#US'), tuple) else None
def read_us(tok):
    o = USO + (tok & 0xFFFFFF)
    b = _d[o]
    if b & 0x80 == 0: ln = b; o += 1
    elif b & 0xC0 == 0x80: ln = ((b & 0x3F) << 8) | _d[o+1]; o += 2
    else: ln = ((b & 0x1F) << 24) | (_d[o+1] << 16) | (_d[o+2] << 8) | _d[o+3]; o += 4
    return _d[o:o+max(0, ln-1)].decode('utf-16-le', 'replace')

def method_il_tok(tok):
    if tok not in METHS: return None
    rva, name = METHS[tok]
    if not rva: return None
    fo = rva2off(rva)
    if fo is None: return None
    b0 = _d[fo]
    if b0 & 3 == 2: return _d[fo+1:fo+1+(b0>>2)]
    hsz = (_d[fo+1] >> 4) * 4
    csz = struct.unpack_from('<I', _d, fo+4)[0]
    return _d[fo+hsz:fo+hsz+csz]

# resource ct by name
RES_BY_NAME = {
    'ErrorReceiver.ValidatorViewer': 'Viewer',
    'ValidatorArgument.EmitterReporter': 'Emitter',
    'ValidatorAllocator.ValidatorProc': 'Proc',
    'CollectorTransaction.ValidatorProject': 'Project',
    'ValidatorGenerator.DefinitionError': 'mainlib',
    'GlobalValidator.FactoryValidator': 'Factory',
}
RES_OFF = {'Viewer': 0x6213C4, 'Emitter': 0x6783B0, 'Proc': 0x6784B4, 'Project': 0x683FE3,
           'mainlib': 0x68A5F7, 'Factory': 0x8C4F02}
RES_LEN = {'Viewer': 0x56FE8, 'Emitter': 0x100, 'Proc': 0xBB2B, 'Project': 0x6610,
           'mainlib': 0x23A907, 'Factory': 0x615CA}


# ---- signature resolution ----
TTO, TSZ = None, None
def _init_streams():
    global TTO, TSZ, BLOB_OFF
    BLOB_OFF = STREAMS['#Blob'][0]
def blob_get(idx):
    o = BLOB_OFF + idx
    b = _d[o]
    if b & 0x80 == 0: ln = b; o += 1
    elif b & 0xC0 == 0x80: ln = ((b & 0x3F) << 8) | _d[o+1]; o += 2
    else: ln = ((b & 0x1F) << 24) | (_d[o+1] << 16) | (_d[o+2] << 8) | _d[o+3]; o += 4
    return _d[o:o+ln]

# MethodDef/MemberRef sig index lookup
_method_sig = {}
_member_sig = {}
def _build_sigmaps():
    # reuse l7b-style walk
    tto, tsz = STREAMS['#~']
    hs = _d[tto+6]
    sif = 4 if hs & 1 else 2; gif = 4 if hs & 2 else 2; bif = 4 if hs & 4 else 2
    valid, = struct.unpack_from('<Q', _d, tto + 8)
    rows = {}
    q = tto + 24
    for b in range(64):
        if valid & (1 << b):
            rows[b], = struct.unpack_from('<I', _d, q); q += 4
    rowstart = q
    def ci_size(tables): return 4 if any(rows.get(t, 0) > 0xFFFF for t in tables) else 2
    RS = ci_size([0x00, 0x1A, 0x23, 0x01]); TDOR = ci_size([0x02, 0x01, 0x1B])
    sz = {
        0x00: 2 + sif + 3*gif, 0x01: RS + sif + sif,
        0x02: 4 + sif + sif + TDOR + ci_size([0x04]) + ci_size([0x06]),
        0x03: ci_size([0x04]), 0x04: 2 + sif + bif, 0x05: ci_size([0x06]),
        0x06: 4 + 2 + 2 + sif + bif + ci_size([0x08]),
        0x07: ci_size([0x06]), 0x08: 2 + 2 + sif, 0x09: 2 + TDOR,
        0x0A: 2 + sif + bif, 0x0B: 2 + ci_size([0x04, 0x08, 0x17]) + bif,
        0x0C: 2 + 2 + bif, 0x0D: 2 + bif, 0x0E: 2 + 2 + bif, 0x0F: 2 + 4 + 2,
        0x10: 4 + 2, 0x11: bif, 0x12: 2 + 2, 0x13: 2, 0x14: 2 + sif + TDOR,
        0x15: 2 + 2, 0x16: 2, 0x17: 2 + sif + bif,
        0x18: 2 + ci_size([0x06, 0x0A]) + ci_size([0x14, 0x17]),
        0x19: 2 + ci_size([0x06, 0x0A]) + ci_size([0x06, 0x0A]),
        0x1A: sif, 0x1B: bif, 0x1C: 2 + ci_size([0x04, 0x06]) + sif + ci_size([0x1A]),
    }
    off = rowstart
    md_off = None; mr_off = None
    for b in sorted(sz):
        if b == 0x06: md_off = off
        if b == 0x0A: mr_off = off
        if b in rows: off += sz[b] * rows[b]
        if b >= 0x0B: break
    MR = ci_size([0x02, 0x01, 0x1B])
    nmd = rows.get(0x06, 0)
    for r in range(nmd):
        ro = md_off + r * sz[0x06]
        sigi, = struct.unpack_from('<I', _d, ro + 12)
        _method_sig[0x06000001 + r] = sigi
    nmr = rows.get(0x0A, 0)
    for r in range(nmr):
        o = mr_off + r * sz[0x0A]
        sigi, = struct.unpack_from('<I', _d, o + 2 + MR)
        _member_sig[0x0A000001 + r] = sigi

def call_sig(tok, nm):
    """returns (paramcount, hasthis) or None"""
    global _SIGINIT
    if not _SIGINIT[0]:
        _build_sigmaps(); _SIGINIT[0] = True
    try:
        if (tok >> 24) == 0x06:
            sig = blob_get(_method_sig[tok])
        elif (tok >> 24) == 0x0A:
            sig = blob_get(_member_sig[tok])
        else:
            return None
    except Exception:
        return None
    if not sig: return None
    conv = sig[0]
    hasthis = bool(conv & 0x20)
    p = 1
    b = sig[p]
    if b & 0x80 == 0: cnt = b
    elif b & 0xC0 == 0x80: cnt = ((b & 0x3F) << 8) | sig[p+1]
    else: cnt = ((b & 0x1F) << 24) | (sig[p+1] << 16) | (sig[p+2] << 8) | sig[p+3]
    return (cnt, hasthis)

_SIGINIT = [False]

class StreamObj:
    def __init__(self, data, pos=0):
        self.data = data; self.pos = pos
class ReaderObj:
    def __init__(self, stream):
        self.s = stream
class Obj:
    _n = 0
    def __init__(self, cls):
        Obj._n += 1
        self.cls = cls; self.fields = {}
        self.id = Obj._n
    def __repr__(self): return '<Obj%d %s>' % (self.id, self.cls)

def mref_name(tok):
    return REFS.get(tok, '?')

def mr_short(tok):
    n = mref_name(tok)
    return n.split('::')[-1] if '::' in n else n

call_sig_fn = call_sig

class VM(Interp):
    def __init__(self, il, depth=0, args=None, globals_=None, trace_arrays=True):
        super().__init__(il, args=args or {}, maxsteps=10**9, maxpaths=1)
        self.depth = depth
        self.g = globals_ if globals_ is not None else {}
        self.trace_arrays = trace_arrays
        self.out_arrays = []
        self.statics = globals_.setdefault('statics', {}) if globals_ is not None else {}

    # ---- main loop (single-path, concrete-first) ----
    def run_vm(self, entry=0):
        ip = entry
        locals_ = {}; addrs = {}; stack = []; mem = Mem()
        steps = 0
        disp_seen = {}
        while True:
            steps += 1
            if steps > self.g.get('step_budget', 3_000_000):
                self.halts.append((ip, 'step-limit')); return None
            x = self.byoff.get(ip)
            if x is None:
                self.halts.append((ip, 'end')); return None
            off, nm, k, op, plen = x
            if nm == 'ldloc':
                nxt = self.byoff.get(ip + flat.ins_len(x))
                if nxt and nxt[1] == 'switch':
                    key = (ip, tuple(sorted((i, v) for i, v in locals_.items() if isinstance(v, (int, tuple))))[:80])
                    disp_seen[key] = disp_seen.get(key, 0) + 1
                    if disp_seen[key] > self.g.get('loop_cut', 6):
                        self.halts.append((ip, 'loop-cut')); return None
            try:
                r = self.step(off, nm, k, op, locals_, addrs, stack, mem, {}, [], ip)
            except ReturnEx as rx:
                return rx.value
            except Exception as e:
                self.halts.append((ip, 'exc:%r' % e)); return None
            if r == 'halt':
                self.halts.append((ip, 'ret'))
                for aid, a in mem.arrays.items():
                    if a['data']:
                        ks = sorted(a['data'])
                        if ks[-1] - ks[0] + 1 <= 128 and all(i in a['data'] for i in range(ks[0], ks[-1]+1)):
                            blob = bytes((a['data'][i] & 0xFF) for i in range(ks[0], ks[-1]+1))
                            self.out_arrays.append((aid, ks[0], blob))
                return None
            if r is None:
                self.halts.append((ip, 'stuck')); return None
            ip = r

    def call_target(self, tok, args, stack, ip):
        """handle call/callvirt/newobj; return (handled, value)"""
        g = self.g
        # --- MethodDef natives & recursion ---
        if isinstance(tok, int) and (tok >> 24) == 0x06:
            if tok == 0x06004217 or tok == 0x060041D1:   # MatchTransaction / CheckRemoteProfiler: (asm, name)->stream
                name = args[1]
                s = name() if callable(name) else name
                nm = None
                if isinstance(s, tuple) and s[0] == 'str': nm = read_us(s[1])
                elif isinstance(s, str): nm = s
                if nm in RES_BY_NAME:
                    key = RES_BY_NAME[nm]
                    return True, StreamObj(g['exe'][RES_OFF[key]:RES_OFF[key]+RES_LEN[key]])
                return True, StreamObj(b'')
            if tok == 0x060041D3:  # (stream, pos) seek
                st = args[0]; p = args[1]
                if isinstance(st, StreamObj) and isinstance(p, int): st.pos = p
                return True, None
            if tok == 0x060041E7:  # reader.ReadUInt32
                r = args[0]
                if isinstance(r, ReaderObj):
                    b = r.s.data[r.s.pos:r.s.pos+4]
                    v = int.from_bytes(b, 'little')
                    r.s.pos += 4
                    return True, v
                return True, Dyn('rdu32')
            if tok == 0x060041E6:  # stream.get_Position
                r = args[0]
                if isinstance(r, ReaderObj): return True, r.s.pos
                if isinstance(r, StreamObj): return True, r.pos
                return True, Dyn('pos')
            if tok == 0x06004191:  # DefineRandomCompressor passthrough (rva mapper) - emulate below
                return True, self.rva_mapper(args)
            if tok == 0x06004264:  # RandomDecryptor .ctor(stream)
                o = Obj('RandomDecryptor'); o.fields['reader'] = ReaderObj(args[0]) if isinstance(args[0], StreamObj) else None
                return True, o
            # generic small-method recursion
            il = g['ilcache'].get(tok)
            if il is None:
                il = method_il_tok(tok)
                g['ilcache'][tok] = il or False
            if il and len(il) <= 400 and self.depth < 6:
                sub = VM(il, depth=self.depth+1, args={i: v for i, v in enumerate(args)}, globals_=g)
                val = sub.run_vm(0)
                for a in sub.out_arrays:
                    self.out_arrays.append((('sub%08X_' % tok) + str(a[0]), a[1], a[2]))
                return True, val if val is not None else Dyn('ret')
            return True, Dyn('call%08X' % tok)
        # --- MemberRef dispatch ---
        if isinstance(tok, int) and (tok >> 24) == 0x0A:
            nm = mr_short(tok)
            full = mref_name(tok)
            if nm == '.ctor':
                if 'typeref#366' in full: return True, ReaderObj(args[0])
                if 'typeref#24' in full: return True, Obj('object')
                return True, Obj(full[:40])
            recv = args[0] if args else None
            if nm == 'GetManifestResourceStream':
                s = args[1] if len(args) > 1 else None
                nmx = None
                if isinstance(s, tuple) and s[0] == 'str': nmx = read_us(s[1])
                if nmx in RES_BY_NAME:
                    key = RES_BY_NAME[nmx]
                    return True, StreamObj(g['exe'][RES_OFF[key]:RES_OFF[key]+RES_LEN[key]])
                return True, StreamObj(b'')
            if nm == 'get_BaseStream':
                if isinstance(recv, ReaderObj): return True, recv.s
                return True, recv
            if nm == 'set_Position':
                if isinstance(recv, StreamObj) and isinstance(args[1], int): recv.pos = args[1]
                elif isinstance(recv, ReaderObj) and isinstance(args[1], int) and recv.s: recv.s.pos = args[1]
                return True, None
            if nm == 'get_Position':
                if isinstance(recv, StreamObj): return True, recv.pos
                if isinstance(recv, ReaderObj) and recv.s: return True, recv.s.pos
                return True, Dyn('pos')
            if nm == 'get_Length':
                if isinstance(recv, StreamObj): return True, len(recv.data)
                return True, Dyn('len')
            if nm == 'ReadBytes':
                n = args[1] if len(args) > 1 else 0
                if isinstance(recv, StreamObj) and isinstance(n, int):
                    b = recv.data[recv.pos:recv.pos+n]; recv.pos += n
                    return True, self.make_arr(b)
                return True, Dyn('bytes')
            if nm == 'ReadUInt32':
                if isinstance(recv, ReaderObj) and recv.s:
                    b = recv.s.data[recv.s.pos:recv.s.pos+4]; recv.s.pos += 4
                    return True, int.from_bytes(b, 'little')
                if isinstance(recv, StreamObj):
                    b = recv.data[recv.pos:recv.pos+4]; recv.pos += 4
                    return True, int.from_bytes(b, 'little')
                return True, Dyn('rdu32')
            if nm == 'Read':
                if isinstance(recv, StreamObj) and len(args) >= 4:
                    arr, i, n = args[1], args[2], args[3]
                    if isinstance(arr, tuple) and arr[0] == 'arr' and isinstance(i, int) and isinstance(n, int):
                        chunk = recv.data[recv.pos:recv.pos+n]; recv.pos += len(chunk)
                        for j, bb in enumerate(chunk): mem_set(self, arr, i+j, bb)
                        return True, len(chunk)
                return True, Dyn('read')
            if nm == 'Close' or nm == 'Dispose':
                return True, None
            if nm == 'get_Unicode' or nm == 'get_ASCII' or nm == 'get_UTF8':
                return True, Obj('Encoding:' + nm)
            if nm == 'GetString' and isinstance(recv, Obj) and recv.cls.startswith('Encoding'):
                arr, i, n = args[1], args[2], args[3]
                if isinstance(arr, tuple) and arr[0] == 'arr':
                    b = bytes(arr_get(self, arr, i+j) & 0xFF for j in range(n))
                    return True, b.decode('utf-16-le', 'replace') if 'Unicode' in recv.cls else b.decode('latin1')
                return True, Dyn('str')
            if nm == 'GetBytes':
                s = args[1] if len(args) > 1 else (args[0] if args else '')
                if isinstance(s, str):
                    return True, self.make_arr(s.encode('utf-16-le') if isinstance(recv, Obj) and 'Unicode' in recv.cls else s.encode('latin1'))
                return True, Dyn('bytes')
            if nm == 'ToInt32':
                v = args[1] if len(args) > 1 else (args[0] if args else 0)
                return True, v & M32 if isinstance(v, int) else Dyn('i32')
            if nm == 'InitializeArray':
                arr, data = args[0], args[1]
                if isinstance(arr, tuple) and arr[0] == 'arr' and isinstance(data, tuple) and data[0] == 'fielddata':
                    off, ln = data[1], data[2]
                    raw = g['fieldData'].get(off, b'')
                    for j in range(ln): mem_set(self, arr, j, raw[j] if j < len(raw) else 0)
                return True, None
            if nm == 'Copy':
                src, si_, dst, di_, n = args[0], args[1], args[2], args[3], args[4]
                if all(isinstance(x, int) for x in (si_, di_, n)) and isinstance(src, tuple) and src[0] == 'arr' and isinstance(dst, tuple) and dst[0] == 'arr':
                    for j in range(n): mem_set(self, dst, di_+j, arr_get(self, src, si_+j))
                    return True, None
                return True, Dyn('copy')
            if nm == 'get_Item':
                if isinstance(recv, tuple) and recv[0] == 'arr' and isinstance(args[1], int):
                    return True, arr_get(self, recv, args[1])
                if isinstance(recv, Obj):
                    return True, recv.fields.get(('item', args[1]), Dyn('item'))
                return True, Dyn('item')
            if nm == 'set_Item':
                if isinstance(recv, Obj) and len(args) >= 3:
                    recv.fields[('item', args[1])] = args[2]
                return True, None
            if nm == 'Add' and isinstance(recv, Obj):
                recv.fields.setdefault('list', []).append((args[1], args[2] if len(args) > 2 else None))
                return True, None
            if nm == 'get_Count' and isinstance(recv, Obj):
                return True, len(recv.fields.get('list', []))
            if nm in ('Enter', 'Exit', 'Trim', 'Concat', 'op_Equality', 'op_Inequality', 'GetName', 'GetReferencedAssemblies', 'get_Name', 'Exists', 'GetTypeFromHandle', 'get_Assembly', 'get_Module', 'GetFields', 'get_MetadataToken', 'ResolveMethod', 'CreateDelegate', 'SetValue', 'GetILGenerator', 'Emit', 'GetParameters', 'get_ParameterType', 'get_ReturnType', 'MakeByRefType', 'get_DeclaringType', 'get_IsStatic', 'get_FieldType', 'get_AssemblyQualifiedName', 'GetMethod', 'GetMethodFromHandle', 'Invoke', 'get_UseMachineKeyStore', 'set_UseMachineKeyStore'):
                if nm == 'Concat':
                    return True, ''.join(a if isinstance(a, str) else (read_us(a[1]) if isinstance(a, tuple) and a[0] == 'str' else '?') for a in args[1:])
                if nm == 'GetManifestResourceNames':
                    return True, self.make_arr([])
                return True, Dyn('mr:%s' % nm)
            return True, Dyn('mr:%s' % nm)
        return False, None

    def rva_mapper(self, args):
        # DefineRandomCompressor(streamreader, count, stream): scan section table
        return Dyn('rvamap')

    def make_arr(self, b):
        a = ('arr', self.g['arrid'][0])
        self.g['arrid'][0] += 1
        self.g['arrays'][a[1]] = {'len': len(b), 'data': {i: v for i, v in enumerate(b)}}
        return a

def arr_get(vm, a, i):
    rec = vm.g['arrays'].get(a[1])
    if rec is None: return 0
    return rec['data'].get(i, 0)

def mem_set(vm, a, i, v):
    rec = vm.g['arrays'].get(a[1])
    if rec is not None: rec['data'][i] = v

class ReturnEx(Exception):
    def __init__(self, value):
        self.value = value


VM.call_sig = staticmethod(call_sig_fn)
