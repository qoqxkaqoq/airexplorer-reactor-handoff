#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step66 v2: faithful multi-frame concrete interpreter for 0600419C + Reactor wrappers.
0600xxxxx calls recurse into dump bodies; framework calls hit BUILTINS (abort if missing).
Goal: exact Key/IV arrays built inline via stelem.i1.
usage: step66_interp419c.py [TRUE|FALSE] [maxsteps]"""
import struct, sys, zipfile
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse, ins_len

GUESS = sys.argv[1] if len(sys.argv) > 1 else 'TRUE'
MAXSTEPS = int(sys.argv[2]) if len(sys.argv) > 2 else 50_000_000

import json, os
TOKNAME = {}
if os.path.exists('/tmp/tokmap.json'):
    TOKNAME = {int(k): v for k, v in json.load(open('/tmp/tokmap.json')).items()}
else:
    import gzip as _gz
    for _l in _gz.open('/workspace/repo_git/work/tokmap_v59.tsv.gz', 'rt'):
        _p = _l.rstrip('\n').split('\t')
        if len(_p) >= 3:
            try:
                TOKNAME[int(_p[1], 16)] = _p[2]
            except ValueError:
                pass

def tname(tok):
    return TOKNAME.get(tok, '')

INTP = ('intp',)  # opaque IntPtr

# ---- manifest resources (cor20 resource area) ----
RES = {}
RESSEL = [os.environ.get('RESSEL', '')]
GETLOG = []

def load_res():
    import dnfile
    pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
    md = pe.net.mdtables
    base = pe.get_offset_from_rva(pe.net.struct.ResourcesRva)
    data = pe.__data__
    for r in md.ManifestResource.rows:
        nm = str(r.Name)
        p = base + r.Offset
        ln = struct.unpack_from('<I', data, p)[0]
        RES[nm] = bytes(data[p + 4:p + 4 + ln])

def _res_pick():
    sel = RESSEL[0]
    for nm in RES:
        if sel and sel in nm:
            return nm
    return sel if sel in RES else (sorted(RES)[0] if RES else '')

def _sread(s, n):
    d = s.f.get('data') if isinstance(s, Obj) else None
    if d is None:
        return []
    pos = s.f.get('pos', 0)
    out = list(d[pos:pos + n])
    s.f['pos'] = pos + n
    return out

def builtin_call(tok, st, name):
    """framework call handling; returns True if handled."""
    # resource/stream machinery by exact token
    if tok == 0x0A0009A7:  # Assembly::GetManifestResourceStream
        nmv = st.pop(); st.pop()  # name, assembly
        sel = _res_pick()
        GETLOG.append(sel)
        o = Obj('ResStream')
        o.f['data'] = list(RES.get(sel, b''))
        o.f['pos'] = 0
        o.f['name'] = sel
        st.append(o)
        return True
    if tok == 0x0A00019C:  # MemoryStream::.ctor(byte[])
        src = st.pop()
        o = Obj('MemoryStream')
        o.f['data'] = list(src) if isinstance(src, (list, bytes)) else []
        o.f['pos'] = 0
        st.append(o)
        return True
    if tok == 0x0A0009A2:  # BinaryReader::get_BaseStream
        br = st.pop()
        st.append(br.f.get('base') if isinstance(br, Obj) else None)
        return True
    if tok == 0x0A0009A9:  # BinaryReader::ReadBytes(int)
        n = st.pop(); br = st.pop()
        base = br.f.get('base') if isinstance(br, Obj) else None
        st.append(_sread(base, n if isinstance(n, int) else 0))
        return True
    if tok == 0x0A0009A8:  # Stream::get_Length
        s = st.pop()
        d = s.f.get('data') if isinstance(s, Obj) else None
        st.append(len(d) if d is not None else 0)
        return True
    nm = tname(tok)
    if not nm:
        return False
    if '::' in nm:
        cls, meth = nm.rsplit('::', 1)
    else:
        cls, meth = nm, ''
    meth = meth.split('(')[0]  # strip signature suffix from tokmap names
    if meth == 'GetModules':
        st.pop()
        st.append([Obj('Module')])
        return True
    if cls.endswith('.IntPtr'):
        if meth == '.ctor':
            v = st.pop() if st else 0
            st.append(('intp', v if isinstance(v, int) else 0))
            return True
        if meth in ('ToInt64', 'ToInt32'):
            v = st.pop()
            st.append(v[1] if isinstance(v, tuple) and v[0] == 'intp' else 0)
            return True
    if cls.endswith('.Version') and meth == '.ctor':
        st.pop(); st.pop(); st.pop(); st.pop()
        st.append(Obj(nm))
        return True
    if cls.endswith('.Type') and meth == 'GetField':
        st.pop(); st.pop()
        st.append(None)  # missing field probe -> null
        return True
    if cls.endswith('Hashtable') and meth == '.ctor':
        st.pop()
        st.append(Obj(nm))
        return True
    if cls.endswith('Marshal'):
        if meth in ('AllocCoTaskMem', 'AllocHGlobal'):
            st.pop()
            global HEAPN
            HEAPN += 0x10000
            st.append(('intp', HEAPN))
            return True
        if meth in ('FreeCoTaskMem', 'FreeHGlobal'):
            st.pop()
            return True
        if meth == 'Copy':
            cnt = st.pop(); dst = st.pop(); start = st.pop(); src = st.pop()
            if isinstance(src, list) and isinstance(dst, tuple) and dst[0] == 'intp':
                for i in range(cnt or 0):
                    HEAP[(dst[1] + i) & 0xFFFFFFFFFFFFFFFF] = src[(start + i)] & 0xFF if isinstance(src[start + i], int) else 0
            elif isinstance(dst, list) and isinstance(src, tuple) and src[0] == 'intp':
                for i in range(cnt or 0):
                    dst[start + i] = HEAP.get((src[1] + i) & 0xFFFFFFFFFFFFFFFF, 0)
            return True
        if meth in ('WriteInt32', 'WriteIntPtr'):
            v = st.pop(); ptr = st.pop()
            if isinstance(ptr, tuple) and ptr[0] == 'intp':
                for i in range(4):
                    HEAP[(ptr[1] + i) & 0xFFFFFFFFFFFFFFFF] = (v >> (8 * i)) & 0xFF
            return True
        if meth in ('ReadInt32', 'ReadIntPtr'):
            ptr = st.pop()
            if isinstance(ptr, tuple) and ptr[0] == 'intp':
                r = 0
                for i in range(8 if meth == 'ReadIntPtr' else 4):
                    r |= HEAP.get((ptr[1] + i) & 0xFFFFFFFFFFFFFFFF, 0) << (8 * i)
                st.append(r)
            else:
                st.append(0)
            return True
        if meth.startswith('Write'):
            st.pop(); st.pop()
            return True
        if meth.startswith('Read'):
            st.pop()
            st.append(0)
            return True
    return False

Z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
BODY_CACHE = {}

SIG = {}  # tok -> (npop_incl_this, isvoid)

def _cint(b, j):
    v = b[j]
    if v & 0x80 == 0:
        return v, j + 1
    if v & 0xC0 == 0x80:
        return ((v & 0x3F) << 8) | b[j + 1], j + 2
    return ((v & 0x1F) << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3], j + 4

def parse_sig(b):
    conv = b[0]
    i = 1
    if conv & 0x10:  # generic
        _, i = _cint(b, i)
    n, i = _cint(b, i)
    ret = b[i]
    return (n + (1 if conv & 0x20 else 0), ret == 0x01)

def build_sig():
    import dnfile
    pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
    md = pe.net.mdtables
    for i, r in enumerate(md.MemberRef.rows):
        try:
            SIG[0x0A000000 + i + 1] = parse_sig(bytes(r.Signature.value))
        except Exception:
            pass
    for i, r in enumerate(md.MethodDef.rows):
        try:
            SIG[0x06000000 + i + 1] = parse_sig(bytes(r.Signature.value))
        except Exception:
            pass

RETB = {}  # tok -> ret ELEMENT_TYPE byte (for opaque returns)

NATIVE_MISSING = {0x0600419E, 0x0600419F, 0x0600425C, 0x0600425D, 0x06004261, 0x0600426B,
                  0x0600426F, 0x06004273, 0x06004277, 0x0600427B, 0x0600427F}

def build_retb():
    import dnfile
    pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
    md = pe.net.mdtables

    def retb(b):
        conv = b[0]
        i = 1
        if conv & 0x10:
            _, i = _cint(b, i)
        _, i = _cint(b, i)
        return b[i]
    for i, r in enumerate(md.MemberRef.rows):
        try:
            RETB[0x0A000000 + i + 1] = retb(bytes(r.Signature.value))
        except Exception:
            pass
    for i, r in enumerate(md.MethodDef.rows):
        try:
            RETB[0x06000000 + i + 1] = retb(bytes(r.Signature.value))
        except Exception:
            pass

def body(tok):
    """tok int -> (ins, byoff, ilsize) parsed; cached."""
    key = '%08X' % tok
    if key in BODY_CACHE:
        return BODY_CACHE[key]
    try:
        d = Z.read('m_%s.bin' % key)
    except KeyError:
        BODY_CACHE[key] = None
        return None
    ilSize = struct.unpack_from('<i', d, 4)[0]
    il = d[24:24 + ilSize]
    ins = parse(il)
    r = (ins, {x[0]: i for i, x in enumerate(ins)}, ilSize)
    BODY_CACHE[key] = r
    return r

M32 = 0xFFFFFFFF

def s32(v):
    v &= M32
    return v - 0x100000000 if v & 0x80000000 else v

class Abort(Exception):
    pass

class Obj:
    __slots__ = ('cls', 'f')
    def __init__(self, cls):
        self.cls = cls
        self.f = {}
    def __repr__(self):
        return '<%s>' % (self.cls or 'obj')

STATIC = {}     # fieldtok -> value
STATIC[0x0A000066] = ('intp', 0)  # System.IntPtr::Zero
OBJN = 0
HEAPN = 0x1000
HEAP = {}

class Frame:
    __slots__ = ('tok', 'ins', 'byoff', 'ip', 'st', 'locs', 'nret', 'ctor_obj', 'isvoid')
    def __init__(self, tok):
        b = body(tok)
        self.tok = tok
        self.ins, self.byoff, _ = b
        self.ip = 0
        self.st = []
        self.locs = {}
        self.nret = None
        self.ctor_obj = None
        self.isvoid = False

ARITY_CACHE = {}

def arity(tok):
    """max ldarg index + 1 (heuristic param count)"""
    if tok in ARITY_CACHE:
        return ARITY_CACHE[tok]
    b = body(tok)
    n = 0
    if b:
        for x in b[0]:
            nm = x[1]
            if nm.startswith('ldarg.'):
                try:
                    n = max(n, int(nm[-1]) + 1)
                except ValueError:
                    pass
            elif nm in ('ldarg.s', 'ldarga.s', 'starg.s'):
                n = max(n, x[3] + 1)
            elif nm in ('ldarg', 'ldarga', 'starg'):
                n = max(n, x[3] + 1)
    ARITY_CACHE[tok] = n
    return n

class Interp:
    def __init__(self):
        self.frames = []
        self.steps = 0
        self.trace = []
        self.writes = []      # (arr, idx, val) with arr = list object
        self.arr_info = {}    # id(list) -> (len, first_write_ip)
        self.calls_unhandled = []
        self.arrays = {}

    def push(self, tok):
        if body(tok) is None:
            return False
        self.frames.append(Frame(tok))
        return True

    def step(self):
        fr = self.frames[-1]
        ip = fr.ip
        x = fr.ins[fr.byoff[ip]] if ip in fr.byoff else None
        if x is None:
            raise Abort('fell off end in %08X at 0x%04X' % (fr.tok, ip))
        off, name, k, op, plen = x
        L = ins_len(x)
        st, locs = fr.st, fr.locs
        self.steps += 1
        self.trace.append((fr.tok, off, name))
        if len(self.trace) > 500:
            self.trace.pop(0)
        if fr.tok == 0x0600419C and 0x1BE0 <= off <= 0x1C00:
            with open('/workspace/repo_git/work/s5/dbg/step313.log', 'a') as fh:
                fh.write('0x%04X %s st=%s loc68=%r loc77=%s\n' % (off, name,
                        [type(v).__name__ for v in st], locs.get(68),
                        'arr%d' % len(locs[77]) if isinstance(locs.get(77), list) else repr(locs.get(77))))

        if name in ('nop', 'break'):
            fr.ip = ip + L; return
        if name == 'ldc.i4.m1':
            st.append(M32); fr.ip = ip + L; return
        if name.startswith('ldc.i4.') and name[-1].isdigit():
            st.append(int(name[-1])); fr.ip = ip + L; return
        if name == 'ldc.i4.s':
            st.append(s32(op) & M32); fr.ip = ip + L; return
        if name == 'ldc.i4':
            st.append(op & M32); fr.ip = ip + L; return
        if name == 'ldc.i8':
            st.append(op & 0xFFFFFFFFFFFFFFFF); fr.ip = ip + L; return
        if name == 'ldnull':
            st.append(None); fr.ip = ip + L; return

        if name in ('ldloca.s', 'ldloca'):
            st.append(('addr', op, fr.tok)); fr.ip = ip + L; return
        if name.startswith('ldloc') or name.startswith('stloc'):
            if name[-1] in '0123' and name in ('ldloc.0','ldloc.1','ldloc.2','ldloc.3','stloc.0','stloc.1','stloc.2','stloc.3'):
                v = int(name[-1]); load = name.startswith('ldloc')
            elif name in ('ldloc.s', 'ldloc', 'stloc.s', 'stloc'):
                v = op; load = name.startswith('ldloc')
            else:
                raise Abort('bad loc op %s' % name)
            if load:
                val = locs.get(v, 0)
                if isinstance(val, list):
                    self.arrays[id(val)] = val
                st.append(val)
            else:
                val = st.pop()
                if isinstance(val, list):
                    self.arrays[id(val)] = val
                locs[v] = val
                if v == 68:
                    with open('/workspace/repo_git/work/s5/dbg/w68.log', 'a') as fh:
                        fh.write('%08X 0x%04X stloc %r stacktypes=%s\n' % (fr.tok, ip, val, [type(x).__name__ for x in st]))
            fr.ip = ip + L; return
        if name in ('ldarg.0', 'ldarg.1', 'ldarg.2', 'ldarg.3'):
            st.append(fr.locs.get(int(name[-1]), 0)); fr.ip = ip + L; return
        if name in ('ldarg', 'ldarg.s'):
            st.append(fr.locs.get(op, 0)); fr.ip = ip + L; return
        if name in ('starg', 'starg.s'):
            v68 = st.pop()
            fr.locs[op] = v68
            if op == 68:
                with open('/workspace/repo_git/work/s5/dbg/w68.log', 'a') as fh:
                    fh.write('%08X 0x%04X starg %r\n' % (fr.tok, ip, v68))
            fr.ip = ip + L; return
        if name in ('ldarga', 'ldarga.s'):
            st.append(('argaddr', op, fr.tok)); fr.ip = ip + L; return
        if name.startswith('ldarg') or name.startswith('starg') or name.startswith('ldarga'):
            raise Abort('arg op %s in %08X at 0x%04X' % (name, fr.tok, ip))

        if name == 'dup':
            st.append(st[-1]); fr.ip = ip + L; return
        if name == 'pop':
            st.pop(); fr.ip = ip + L; return

        if name == 'newarr':
            cnt = st.pop()  # element type comes from token operand
            if not isinstance(cnt, int):
                raise Abort('newarr count %r in %08X at 0x%04X' % (cnt, fr.tok, ip))
            arr = [0] * cnt
            self.arrays[id(arr)] = arr
            st.append(arr); fr.ip = ip + L; return
        if name == 'ldlen':
            a = st.pop()
            if not isinstance(a, list):
                raise Abort('ldlen %r in %08X at 0x%04X' % (a, fr.tok, ip))
            st.append(len(a)); fr.ip = ip + L; return
        if name.startswith('ldelem.'):
            idx = st.pop(); a = st.pop()
            if not isinstance(a, list) or not isinstance(idx, int):
                raise Abort('ldelem %r/%r in %08X at 0x%04X alllocs=%r' % (type(a).__name__, idx, fr.tok, ip, {k: (type(val).__name__, val if not isinstance(val, (list, Obj)) else ('arr%d' % len(val) if isinstance(val, list) else repr(val))) for k, val in fr.locs.items()}))
            v = a[idx] if 0 <= idx < len(a) else 0
            if name == 'ldelem.i1' and isinstance(v, int):
                v = ((v & 0xFF) - 256 if v & 0x80 else v & 0xFF) & M32
            st.append(v & M32 if isinstance(v, int) else v); fr.ip = ip + L; return
        if name.startswith('stelem'):
            val = st.pop(); idx = st.pop(); a = st.pop()
            if not isinstance(a, list):
                raise Abort('stelem %r in %08X at 0x%04X' % (type(a).__name__, fr.tok, ip))
            if not isinstance(idx, int):
                raise Abort('stelem non-concrete idx=%r in %08X at 0x%04X' % (idx, fr.tok, ip))
            if name not in ('stelem', 'stelem.ref', 'stelem.i', 'stelem.i8'):
                if not isinstance(val, int):
                    raise Abort('stelem non-concrete val=%r in %08X at 0x%04X' % (val, fr.tok, ip))
                if name == 'stelem.i1':
                    val &= 0xFF
            a[idx] = val
            self.writes.append((a, idx, val))
            fr.ip = ip + L; return

        if name in ('add', 'sub', 'mul', 'and', 'or', 'xor'):
            b = st.pop(); a = st.pop()
            # pointer arithmetic: (arraddr|intp) +- int
            for ptr, other in ((a, b), (b, a)):
                if isinstance(ptr, tuple) and ptr[0] in ('arraddr', 'intp') and isinstance(other, int) and name in ('add', 'sub'):
                    delta = other if name == 'add' else -other
                    st.append((ptr[0], ptr[1], ptr[2] + delta) if ptr[0] == 'arraddr' else ('intp', (ptr[1] + delta) & 0xFFFFFFFFFFFFFFFF))
                    fr.ip = ip + L; break
            else:
                if not isinstance(a, int) or not isinstance(b, int):
                    raise Abort('%s %r/%r in %08X at 0x%04X' % (name, a, b, fr.tok, ip))
                if name in ('and', 'or', 'xor') and (a > M32 or b > M32):
                    st.append({'and': a & b, 'or': a | b, 'xor': a ^ b}[name] & 0xFFFFFFFFFFFFFFFF)
                else:
                    st.append({'add': (a + b), 'sub': (a - b), 'mul': (a * b),
                               'and': a & b, 'or': a | b, 'xor': a ^ b}[name] & M32)
                fr.ip = ip + L; return
            return
        if name in ('div', 'rem', 'div.un', 'rem.un'):
            b = st.pop(); a = st.pop()
            if not isinstance(a, int) or not isinstance(b, int) or (b & M32) == 0:
                raise Abort('%s %r/%r in %08X at 0x%04X' % (name, a, b, fr.tok, ip))
            if name.endswith('.un'):
                r = (a // b) if name == 'div.un' else (a % b)
            else:
                sa, sb = s32(a), s32(b)
                q = abs(sa) // abs(sb) * (1 if (sa < 0) == (sb < 0) else -1)
                r = q if name == 'div' else (sa - q * sb)
            st.append(r & M32); fr.ip = ip + L; return
        if name in ('shl', 'shr', 'shr.un'):
            b = st.pop(); a = st.pop()
            if not isinstance(a, int) or not isinstance(b, int):
                raise Abort('%s %r/%r in %08X at 0x%04X' % (name, a, b, fr.tok, ip))
            n = b & 31
            st.append({'shl': (a << n), 'shr.un': (a & M32) >> n,
                       'shr': (s32(a) >> n)}[name] & M32)
            fr.ip = ip + L; return
        if name == 'neg':
            st.append((-st.pop()) & M32); fr.ip = ip + L; return
        if name == 'not':
            st.append(st.pop() ^ M32); fr.ip = ip + L; return

        if name.startswith('conv.'):
            a = st.pop()
            if isinstance(a, int):
                if name == 'conv.i1': a = s32(a & 0xFF) & M32
                elif name == 'conv.i2': a = s32(a & 0xFFFF) & M32
                elif name == 'conv.u1': a &= 0xFF
                elif name == 'conv.u2': a &= 0xFFFF
                elif name == 'conv.i8': a = a | 0xFFFFFFFF00000000 if a & 0x80000000 else a & M32
                else: a &= M32
            st.append(a); fr.ip = ip + L; return

        if name in ('ceq', 'cgt', 'clt', 'cgt.un', 'clt.un'):
            b = st.pop(); a = st.pop()
            if name == 'ceq' and (isinstance(a, (Obj, list)) or isinstance(b, (Obj, list))):
                st.append(1 if a is b else 0); fr.ip = ip + L; return
            if not isinstance(a, int) or not isinstance(b, int):
                raise Abort('%s %r/%r in %08X at 0x%04X' % (name, a, b, fr.tok, ip))
            if name == 'ceq': r = (a & M32) == (b & M32)
            elif name == 'cgt.un': r = (a & M32) > (b & M32)
            elif name == 'clt.un': r = (a & M32) < (b & M32)
            elif name == 'cgt': r = s32(a) > s32(b)
            else: r = s32(a) < s32(b)
            st.append(1 if r else 0); fr.ip = ip + L; return

        if name in ('br', 'br.s'):
            fr.ip = op; return
        if name in ('leave', 'leave.s'):
            st.clear(); fr.ip = op; return
        base = name.split('.')[0] if name.endswith('.s') else name
        if base in ('brfalse', 'brtrue'):
            v = st.pop()
            if isinstance(v, tuple) and v[0] in ('fld', 'str', 'tok', 'addr', 'argaddr'):
                # non-null reference gates (ldstr token / ldtoken / addresses):
                # Reactor never branches on real null here -> brtrue taken
                r = base == 'brtrue'
                self.trace.append((fr.tok, ip, 'GATE%s' % ('T' if r else 'F')))
                fr.ip = op if r else ip + L; return
            if isinstance(v, Obj) or isinstance(v, list):
                r = base == 'brtrue'  # non-null reference
            elif isinstance(v, tuple) and v[0] == 'intp':
                r = (v[1] != 0) if base == 'brtrue' else (v[1] == 0)
            elif isinstance(v, (int, type(None))):
                r = (v is not None and v != 0) if base == 'brtrue' else (v is None or v == 0)
            else:
                raise Abort('%s on %r in %08X at 0x%04X' % (name, v, fr.tok, ip))
            fr.ip = op if r else ip + L; return
        if base in ('beq', 'bne.un', 'bge', 'ble', 'bgt', 'blt', 'bge.un', 'ble.un', 'bgt.un', 'blt.un'):
            b = st.pop(); a = st.pop()
            if isinstance(a, (Obj, list)) or isinstance(b, (Obj, list)) or \
               (isinstance(a, tuple) and a[0] == 'intp') or (isinstance(b, tuple) and b[0] == 'intp'):
                nulla = a is None or (isinstance(a, tuple) and a[0] == 'intp' and a[1] == 0)
                nullb = b is None or (isinstance(b, tuple) and b[0] == 'intp' and b[1] == 0)
                if base in ('beq', 'bne.un'):
                    eq = (a is b) or (nulla and nullb)
                    r = eq if base == 'beq' else not eq
                else:
                    raise Abort('ref cmp %s in %08X at 0x%04X' % (base, fr.tok, ip))
                fr.ip = op if r else ip + L; return
            if not isinstance(a, int) or not isinstance(b, int):
                raise Abort('%s %r/%r in %08X at 0x%04X' % (name, a, b, fr.tok, ip))
            r = {'beq': (a & M32) == (b & M32), 'bne.un': (a & M32) != (b & M32),
                 'bge': s32(a) >= s32(b), 'ble': s32(a) <= s32(b),
                 'bgt': s32(a) > s32(b), 'blt': s32(a) < s32(b),
                 'bge.un': (a & M32) >= (b & M32), 'ble.un': (a & M32) <= (b & M32),
                 'bgt.un': (a & M32) > (b & M32), 'blt.un': (a & M32) < (b & M32)}[base]
            fr.ip = op if r else ip + L; return
        if name == 'switch':
            v = st.pop()
            if not isinstance(v, int):
                raise Abort('switch %r in %08X at 0x%04X' % (v, fr.tok, ip))
            if fr.tok == 0x0600419C:
                tgt = op[v] if 0 <= v < len(op) else -1
                with open('/workspace/repo_git/work/s5/dbg/swdisp.log', 'a') as fh:
                    fh.write('0x%04X v=%d -> %04X depth=%d\n' % (ip, v, tgt, len(st)))
            fr.ip = op[v] if 0 <= v < len(op) else ip + L; return

        if name == 'ret':
            rv = st[-1] if st else None
            done = self.frames.pop()
            if done.isvoid:
                rv = ('void',)
            else:
                rv = done.ctor_obj if done.ctor_obj is not None else rv
            if self.frames:
                if rv != ('void',):
                    self.frames[-1].st.append(rv)
            else:
                self.nret = rv
            return
        if name in ('throw', 'rethrow'):
            raise Abort('throw in %08X at 0x%04X' % (fr.tok, ip))
        if name in ('endfinally', 'endfilter'):
            raise Abort('%s in %08X at 0x%04X' % (name, fr.tok, ip))

        if name == 'ldstr':
            st.append(('str', op)); fr.ip = ip + L; return
        if name in ('ldsfld', 'ldsflda'):
            st.append(STATIC.get(op)); fr.ip = ip + L; return
        if name == 'stsfld':
            STATIC[op] = st.pop(); fr.ip = ip + L; return
        if name in ('ldfld', 'ldflda'):
            o = st.pop()
            if isinstance(o, Obj):
                st.append(o.f.get(op))
            elif isinstance(o, tuple) and o[0] == 'addr':
                _, slot, atok = o
                cur = None
                for tfr in self.frames:
                    if tfr.tok == atok:
                        cur = tfr.locs.get(slot)
                        break
                st.append(cur.f.get(op) if isinstance(cur, Obj) else None)
            else:
                raise Abort('ldfld on %r (%08X) in %08X at 0x%04X' % (o, op, fr.tok, ip))
            fr.ip = ip + L; return
        if name == 'stfld':
            v = st.pop(); o = st.pop()
            if isinstance(o, Obj):
                o.f[op] = v
            elif isinstance(o, tuple) and o[0] == 'addr':
                _, slot, atok = o
                for tfr in self.frames:
                    if tfr.tok == atok:
                        cur = tfr.locs.get(slot)
                        if not isinstance(cur, Obj):
                            cur = Obj('struct@%d' % slot)
                            tfr.locs[slot] = cur
                        cur.f[op] = v
                        break
            else:
                raise Abort('stfld on %r in %08X at 0x%04X' % (o, fr.tok, ip))
            fr.ip = ip + L; return
        if name in ('box', 'castclass', 'isinst', 'ldobj'):
            if name in ('castclass', 'isinst', 'ldobj'):
                v = st.pop()
                st.append(v)
            fr.ip = ip + L; return
        if name in ('unbox.any', 'unbox'):
            v = st.pop()
            st.append(v[1] if isinstance(v, tuple) and v[0] == 'box' else v)
            fr.ip = ip + L; return
        if name == 'ldelema':
            idx = st.pop(); arr = st.pop()
            if not isinstance(arr, list) or not isinstance(idx, int):
                raise Abort('ldelema %r/%r in %08X at 0x%04X' % (type(arr).__name__, idx, fr.tok, ip))
            self.arrays[id(arr)] = arr
            with open('/workspace/repo_git/work/s5/dbg/ldelema.log', 'a') as fh:
                fh.write('%08X 0x%04X arr=%s len=%d idx=%d depth=%d\n' % (fr.tok, ip, type(arr).__name__, len(arr), idx, len(st)))
            st.append(('arraddr', arr, idx)); fr.ip = ip + L; return
        if name in ('ldind.i1', 'ldind.u1', 'ldind.i2', 'ldind.u2', 'ldind.i4', 'ldind.u4', 'ldind.i8', 'ldind.ref', 'ldind.i'):
            a = st.pop()
            sz = {'ldind.i1': 1, 'ldind.u1': 1, 'ldind.i2': 2, 'ldind.u2': 2,
                  'ldind.i4': 4, 'ldind.u4': 4, 'ldind.i8': 8, 'ldind.ref': 8, 'ldind.i': 8}[name]
            if isinstance(a, tuple) and a[0] == 'arraddr':
                _, arr, off = a
                v = 0
                for i in range(sz):
                    x = arr[off + i] if 0 <= off + i < len(arr) else 0
                    v |= (x & 0xFF) << (8 * i)
                st.append(v)
            elif isinstance(a, tuple) and a[0] == 'intp':
                v = 0
                for i in range(sz):
                    v |= HEAP.get(((a[1] + i) & 0xFFFFFFFFFFFFFFFF), 0) << (8 * i)
                st.append(v)
            elif isinstance(a, tuple) and a[0] == 'addr':
                st.append(self._addr_load(a))
            else:
                raise Abort('ldind %r in %08X at 0x%04X stack=%r loc68=%r loc44=%r alllocs=%r' % (a, fr.tok, ip, [type(v).__name__ for v in st], fr.locs.get(68), fr.locs.get(44), {k: (type(val).__name__, val if not isinstance(val, list) else 'arr%d' % len(val)) for k, val in fr.locs.items()}))
            fr.ip = ip + L; return
        if name in ('stind.i1', 'stind.i2', 'stind.i4', 'stind.i8', 'stind.ref', 'stind.i'):
            v = st.pop(); a = st.pop()
            sz = {'stind.i1': 1, 'stind.i2': 2, 'stind.i4': 4, 'stind.i8': 8, 'stind.ref': 8, 'stind.i': 8}[name]
            if isinstance(a, tuple) and a[0] == 'arraddr':
                _, arr, off = a
                self.arrays[id(arr)] = arr
                for i in range(sz):
                    b = (v >> (8 * i)) & 0xFF
                    if 0 <= off + i < len(arr):
                        old = arr[off + i]
                        arr[off + i] = b
                        if b != old:
                            self.writes.append((arr, off + i, b))
            elif isinstance(a, tuple) and a[0] == 'intp':
                for i in range(sz):
                    HEAP[(a[1] + i) & 0xFFFFFFFFFFFFFFFF] = (v >> (8 * i)) & 0xFF
            elif isinstance(a, tuple) and a[0] == 'addr':
                self._addr_store(a, v)
            else:
                raise Abort('stind %r in %08X at 0x%04X' % (a, fr.tok, ip))
            fr.ip = ip + L; return
        if name == 'initobj':
            a = st.pop()
            if isinstance(a, tuple) and a[0] == 'addr':
                self._addr_store(a, 0)
            fr.ip = ip + L; return
        if name in ('ldftn', 'ldvirtftn'):
            st.append(Obj('ftn@%08X' % op)); fr.ip = ip + L; return
        if name in ('ldtoken', 'sizeof', 'refanyval', 'ckfinite', 'arglist', 'localloc', 'mkrefany', 'refanytype', 'cpobj', 'stobj', 'ldelema', 'constrained.', 'unaligned.', 'volatile.', 'tail.', 'readonly.'):
            if name in ('ldtoken', 'sizeof', 'refanyval'):
                st.pop() if name == 'refanyval' else None
                st.append(('tok', op))
            elif name in ('cpobj', 'stobj', 'ldelema'):
                raise Abort('%s in %08X at 0x%04X' % (name, fr.tok, ip))
            else:
                st.pop() if name in ('ckfinite', 'localloc') else None
            fr.ip = ip + L; return
        if name in ('cpblk', 'initblk'):
            raise Abort('%s in %08X at 0x%04X' % (name, fr.tok, ip))

        if name in ('call', 'callvirt', 'newobj', 'jmp'):
            tok = op
            tbl = tok >> 24
            if tbl == 0x06 and tok != 0x0600419C:
                # in-assembly method: recurse
                if body(tok) is None:
                    if name == 'newobj' and tok == 0x06004264:
                        # RandomDecryptor::.ctor (missing body): this._AdvancedDecryptor = new BinaryReader(arg)
                        arg = st.pop()
                        br = Obj('BinaryReader')
                        br.f['base'] = arg
                        o = Obj('RandomDecryptor')
                        o.f[0x04001FE1] = br
                        st.append(o)
                        self.trace.append((fr.tok, ip, 'RANDDEC-CTOR'))
                        fr.ip = ip + L; return
                    if name == 'newobj':
                        # missing body (forcedump-failed): opaque object
                        n = 1
                        sig = SIG.get(tok)
                        if sig:
                            n = sig[0] - 1
                        for _ in range(max(0, n)):
                            st.pop()
                        st.append(Obj('%08X*' % tok))
                        self.trace.append((fr.tok, ip, 'OPAQUE-CTOR %08X' % tok))
                        fr.ip = ip + L; return
                    if tok in NATIVE_MISSING:
                        # missing-body native family: opaque model
                        sig = SIG.get(tok)
                        n = sig[0] if sig else 0
                        for _ in range(max(0, n)):
                            st.pop()
                        rb = RETB.get(tok, 0)
                        if rb == 0x01:
                            pass  # void
                        elif rb in (0x18, 0x19, 0x0A, 0x0B):  # I, U, I8, U8
                            st.append(('intp', 0))
                        else:
                            st.append(0)
                        self.trace.append((fr.tok, ip, 'NATIVE-OPAQUE %08X' % tok))
                        fr.ip = ip + L; return
                    raise Abort('call %s %08X %s at %08X/0x%04X: no dump body' % (name, tok, tname(tok), fr.tok, ip))
                sig = SIG.get(tok)
                if sig:
                    n, isvoid = sig
                    nf_isvoid = isvoid
                else:
                    n = arity(tok)
                    nf_isvoid = False
                if name == 'newobj':
                    n = n - 1 if sig else n  # exclude this
                if n:
                    if len(st) < n:
                        raise Abort('call arg underflow %s %08X %s at %08X/0x%04X stack=%d need=%d' % (name, tok, tname(tok), fr.tok, ip, len(st), n))
                    args = [st.pop() for _ in range(n)][::-1]
                else:
                    args = []
                nf = Frame(tok)
                nf.isvoid = nf_isvoid
                if name == 'newobj':
                    global OBJN
                    OBJN += 1
                    nf.ctor_obj = Obj('%08X' % tok)
                    nf.locs[0] = nf.ctor_obj
                    for i, v in enumerate(args):
                        nf.locs[i + 1] = v
                else:
                    for i, v in enumerate(args):
                        nf.locs[i] = v
                self.frames.append(nf)
                fr.ip = ip + L
                if name == 'jmp':
                    raise Abort('jmp %08X in %08X at 0x%04X' % (tok, fr.tok, ip))
                return
            # framework / other
            if name == 'newobj':
                n = 1
                sig = SIG.get(tok)
                if sig:
                    n = sig[0] - 1  # exclude created this
                for _ in range(max(0, n)):
                    st.pop()
                st.append(Obj('%08X' % tok))
                fr.ip = ip + L; return
            if name in ('call', 'callvirt') and builtin_call(tok, st, name):
                fr.ip = ip + L; return
            sig = SIG.get(tok)
            if sig:
                npop, isvoid = sig
                for _ in range(npop):
                    st.pop()
                if not isvoid:
                    st.append(0)
                self.trace.append((fr.tok, ip, 'FB %08X %s' % (tok, tname(tok))))
                fr.ip = ip + L; return
            raise Abort('CALL %s %08X %s in %08X at 0x%04X stack=%r' % (name, tok, tname(tok), fr.tok, ip, [type(v).__name__ for v in st]))

        raise Abort('UNHANDLED %s in %08X at 0x%04X' % (name, fr.tok, ip))

    def _addr_load(self, a):
        if a[0] == 'argaddr':
            _, slot, tok = a
            for fr in self.frames:
                if fr.tok == tok:
                    return fr.locs.get(slot, 0)
            return 0
        _, slot, tok = a
        for fr in self.frames:
            if fr.tok == tok:
                return fr.locs.get(slot, 0)
        return 0

    def _addr_store(self, a, v):
        if a[0] == 'argaddr':
            _, slot, tok = a
            for fr in self.frames:
                if fr.tok == tok:
                    fr.locs[slot] = v
                    if slot == 68:
                        with open('/workspace/repo_git/work/s5/dbg/w68.log', 'a') as fh:
                            fh.write('%08X addr-store(argaddr) %r\n' % (fr.tok, v))
                    return
            return
        _, slot, tok = a
        for fr in self.frames:
            if fr.tok == tok:
                fr.locs[slot] = v
                if slot == 68:
                    with open('/workspace/repo_git/work/s5/dbg/w68.log', 'a') as fh:
                        fh.write('%08X addr-store %r\n' % (fr.tok, v))

    def run(self, entry=0x0600419C):
        self.push(entry)
        while self.frames:
            if self.steps >= MAXSTEPS:
                raise Abort('max steps %d' % self.steps)
            self.step()

it = Interp()
build_sig()
build_retb()
load_res()
print('resources loaded:', {k: len(v) for k, v in RES.items()})
try:
    it.run()
    print('COMPLETED. steps=%d' % it.steps)
except Abort as e:
    print('ABORT:', e)
print('steps=%d writes=%d arrays=%d frames_left=%d' % (it.steps, len(it.writes), len(it.arrays), len(it.frames)))
print('GetManifestResourceStream picks:', GETLOG)
print('unhandled:', it.calls_unhandled[:5])
print('last trace:')
for t in it.trace[-16:]:
    print('   %08X 0x%04X %s' % t)
print('=== arrays ===')
import glob as _g
os.makedirs('/workspace/repo_git/work/s5/dbg/arrays', exist_ok=True)
for f in _g.glob('/workspace/repo_git/work/s5/dbg/arrays/*.bin'):
    os.remove(f)
_n = 0
for aid, arr in it.arrays.items():
    nz = sum(1 for v in arr if isinstance(v, int) and v)
    if len(arr) > 64:
        _n += 1
        with open('/workspace/repo_git/work/s5/dbg/arrays/arr%02d_len%d.bin' % (_n, len(arr)), 'wb') as fh:
            fh.write(bytes(v & 0xFF if isinstance(v, int) else 0 for v in arr))
        print('  arr%d len=%d nonzero=%d -> /workspace/repo_git/work/s5/dbg/arrays/arr%02d_len%d.bin' % (_n, len(arr), nz, _n, len(arr)))
        print('    head: %s' % ' '.join('%02X' % v if isinstance(v, int) else '??' for v in arr[:48]))
    else:
        print('  arr len=%d nonzero=%d: %s' % (len(arr), nz,
              ' '.join('%02X' % v if isinstance(v, int) else '??' for v in arr[:80])))
