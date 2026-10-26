#!/usr/bin/env python3
# l7b_blocks.py — v2: full MethodDef enumeration + per-basic-block stack simulation of stelem.i1
import sys, struct, json, binascii
sys.path.insert(0, r'airexplorer-reactor-handoff/work'); sys.path.insert(0, r'work_a1')
import flat

EXE = r'airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe'
d = open(EXE, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3C)[0]
coff = pe + 4
nsec, = struct.unpack_from('<H', d, coff + 2)
optsz, = struct.unpack_from('<H', d, coff + 16)
opt = coff + 20
sec0 = opt + optsz
secs = []
for i in range(nsec):
    o = sec0 + i * 40
    va = struct.unpack_from('<I', d, o + 12)[0]; vsz = struct.unpack_from('<I', d, o + 8)[0]
    raw = struct.unpack_from('<I', d, o + 20)[0]; rawsz = struct.unpack_from('<I', d, o + 16)[0]
    secs.append((va, vsz, raw, rawsz))
def rva2off(rva):
    for va, vsz, raw, rawsz in secs:
        if va <= rva < va + max(vsz, rawsz): return raw + (rva - va)
cor = rva2off(struct.unpack_from('<I', d, opt + (0x60 if struct.unpack_from('<H', d, opt)[0] == 0x10B else 0x70) + 14 * 8)[0])
md_rva, md_sz = struct.unpack_from('<II', d, cor + 8)
mo = rva2off(md_rva)
vlen, = struct.unpack_from('<I', d, mo + 12)
p = mo + 16 + vlen
nstr, = struct.unpack_from('<H', d, p + 2); p += 4
streams = {}
for i in range(nstr):
    so, ssz = struct.unpack_from('<II', d, p)
    nm = d[p + 8:d.index(b'\0', p + 8)].decode()
    streams[nm] = (mo + so, ssz); p += 8 + len(nm) + 1; p = (p + 3) & ~3
tto, tsz = streams['#~']
hs = d[tto + 6]
si = 4 if hs & 1 else 2
gi = 4 if hs & 2 else 2
bi = 4 if hs & 4 else 2
valid, = struct.unpack_from('<Q', d, tto + 8)
rows = {}
q = tto + 24
for b in range(64):
    if valid & (1 << b):
        rows[b], = struct.unpack_from('<I', d, q); q += 4
rowstart = q
def ci_size(tables): return 4 if any(rows.get(t, 0) > 0xFFFF for t in tables) else 2
RS = ci_size([0x00, 0x1A, 0x23, 0x01])
TDOR = ci_size([0x02, 0x01, 0x1B])
sz = {
    0x00: 2 + si + 3 * gi, 0x01: RS + si + si,
    0x02: 4 + si + si + TDOR + ci_size([0x04]) + ci_size([0x06]),
    0x04: 2 + si + bi, 0x06: 4 + 2 + 2 + si + bi + ci_size([0x08]),
}
so_str, _ = streams['#Strings']
off = rowstart
for b in sorted(sz):
    if b >= 0x06: break
    if b in rows: off += sz[b] * rows[b]
nmd = rows.get(0x06, 0)
MDRW = 4 + 2 + 2 + si + bi + ci_size([0x08])
methods = []
for r in range(nmd):
    ro = off + r * MDRW
    rva, = struct.unpack_from('<I', d, ro)
    namei, = struct.unpack_from('<I' if si == 4 else '<H', d, ro + 8)
    e = d.index(b'\0', so_str + namei)
    nm = d[so_str + namei:e].decode('utf8', 'replace')
    if rva:
        methods.append((0x06000001 + r, rva, nm))
print('methods with RVA:', len(methods))

BIN = {'add': lambda a, b: (a + b) & 0xFFFFFFFF, 'sub': lambda a, b: (a - b) & 0xFFFFFFFF,
       'xor': lambda a, b: a ^ b, 'and': lambda a, b: a & b, 'or': lambda a, b: a | b,
       'mul': lambda a, b: (a * b) & 0xFFFFFFFF}

def block_stores(il):
    """per-basic-block constant simulation; return stores [(arrdesc, idx, val, off)]"""
    try:
        ins = list(flat.parse(il))
    except Exception:
        return []
    if not ins: return []
    # basic block boundaries
    starts = {0}
    for i, (off, nm, k, op, plen) in enumerate(ins):
        if k in ('br1', 'br4'):
            if i + 1 < len(ins): starts.add(ins[i + 1][0])
            starts.add(op)
        elif nm in ('brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'beq', 'beq.s', 'bne.un', 'bne.un.s',
                    'bge', 'bge.s', 'bgt', 'bgt.s', 'ble', 'ble.s', 'blt', 'blt.s',
                    'bge.un', 'bge.un.s', 'bgt.un', 'bgt.un.s', 'ble.un', 'ble.un.s', 'blt.un', 'blt.un.s'):
            if i + 1 < len(ins): starts.add(ins[i + 1][0])
            starts.add(op)
        elif nm == 'switch':
            if i + 1 < len(ins): starts.add(ins[i + 1][0])
            for t in op: starts.add(t)
        elif nm in ('ret', 'throw', 'rethrow', 'endfinally', 'endfilter'):
            if i + 1 < len(ins): starts.add(ins[i + 1][0])
        elif nm in ('leave', 'leave.s'):
            if i + 1 < len(ins): starts.add(ins[i + 1][0])
    out = []
    i = 0
    n = len(ins)
    while i < n:
        if ins[i][0] not in starts:
            i += 1; continue
        # simulate block from empty stack
        stack = []
        j = i
        while j < n:
            off, nm, k, op, plen = ins[j]
            if j > i and ins[j][0] in starts and nm not in ('dup',):
                break
            if nm in ('ldc.i4', 'ldc.i4.s'):
                stack.append(op & 0xFFFFFFFF)
            elif nm == 'ldc.i4.m1':
                stack.append(0xFFFFFFFF)
            elif nm in ('ldloc', 'ldloc.s'):
                stack.append(('v', 'L', op))
            elif nm in ('ldloc.0', 'ldloc.1', 'ldloc.2', 'ldloc.3'):
                stack.append(('v', 'L', int(nm[-1])))
            elif nm in ('ldarg', 'ldarg.s'):
                stack.append(('v', 'A', op))
            elif nm in ('ldarg.0', 'ldarg.1', 'ldarg.2', 'ldarg.3'):
                stack.append(('v', 'A', int(nm[-1])))
            elif nm == 'ldsfld':
                stack.append(('f', op))
            elif nm == 'dup':
                if stack: stack.append(stack[-1])
            elif nm == 'pop':
                if stack: stack.pop()
            elif nm in BIN:
                if len(stack) >= 2:
                    b = stack.pop(); a = stack.pop()
                    stack.append(BIN[nm](a, b) if isinstance(a, int) and isinstance(b, int) else None)
            elif nm == 'not':
                if stack:
                    a = stack.pop(); stack.append((~a) & 0xFFFFFFFF if isinstance(a, int) else None)
            elif nm == 'neg':
                if stack:
                    a = stack.pop(); stack.append((-a) & 0xFFFFFFFF if isinstance(a, int) else None)
            elif nm in ('stelem.i1', 'stelem.i'):
                if len(stack) >= 3:
                    v = stack.pop(); idx = stack.pop(); arr = stack.pop()
                    if isinstance(v, int) and isinstance(idx, int) and isinstance(arr, tuple) and arr and arr[0] in ('v', 'f'):
                        out.append((arr, idx, v & 0xFF if nm == 'stelem.i1' else v & 0xFFFFFFFF, off))
            elif nm.startswith('stelem'):
                if len(stack) >= 3:
                    stack.pop(); stack.pop(); stack.pop()
            elif nm in ('stloc', 'stloc.s', 'starg', 'starg.s') or nm.startswith('stloc.') or nm.startswith('starg.') or nm == 'stsfld':
                if stack: stack.pop()
            elif nm in ('ret', 'throw', 'rethrow', 'endfinally', 'endfilter', 'leave', 'leave.s', 'br', 'br.s'):
                break
            elif nm in ('call', 'callvirt', 'newobj'):
                stack = []  # unknown signature: flush
            elif nm.startswith('ldelem'):
                if len(stack) >= 2:
                    stack.pop(); stack.pop(); stack.append(('elem', off))
            elif nm == 'ldlen':
                if stack: stack.pop(); stack.append(('len', off))
            elif nm == 'newarr':
                if stack: stack.pop(); stack.append(('newarr', off))
            elif nm.startswith('conv'):
                pass
            elif nm in ('brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'beq', 'beq.s', 'bne.un', 'bne.un.s',
                        'bge', 'bge.s', 'bgt', 'bgt.s', 'ble', 'ble.s', 'blt', 'blt.s', 'bge.un', 'bge.un.s',
                        'bgt.un', 'bgt.un.s', 'ble.un', 'ble.un.s', 'blt.un', 'blt.un.s'):
                break
            elif nm == 'switch':
                break
            elif nm in ('nop', 'ldnull', 'ldstr', 'ldtoken', 'ldsflda', 'ldfld', 'ldflda', 'ldftn', 'ldvirtftn',
                        'box', 'unbox', 'unbox.any', 'castclass', 'isinst', 'ldobj', 'cpobj', 'ldstr'):
                if nm in ('ldnull',):
                    stack.append(None)
                elif nm in ('ldfld', 'ldflda', 'ldsflda'):
                    if stack: stack.pop(); stack.append(('fld', op))
                elif nm in ('box', 'castclass', 'isinst', 'unbox.any', 'ldtoken', 'ldstr'):
                    pass
                else:
                    pass
            elif nm in ('ldind.i1', 'ldind.u1', 'ldind.i2', 'ldind.u2', 'ldind.i4', 'ldind.u4', 'ldind.i8', 'ldind.ref'):
                if stack: stack.pop(); stack.append(('ind', off))
            else:
                stack = []
            j += 1
        i = j if j > i else i + 1
    return out

KV = binascii.unhexlify('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943')
KM = binascii.unhexlify('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481')
KF = binascii.unhexlify('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a')
KNOWN = (('Viewer', KV), ('mainlib', KM), ('Factory', KF))

def method_il(rva):
    fo = rva2off(rva)
    b0 = d[fo]
    if b0 & 3 == 2:
        return d[fo+1:fo+1+(b0>>2)]
    hsz = (d[fo+1] >> 4) * 4
    csz = struct.unpack_from('<I', d, fo+4)[0]
    return d[fo+hsz:fo+hsz+csz]

allstores = {}
nstore = 0
for tok, rva, nm in methods:
    try:
        il = method_il(rva)
    except Exception:
        continue
    if len(il) < 40: continue
    st = block_stores(il)
    if st:
        allstores[tok] = (nm, st)
        nstore += len(st)
print('methods with stores:', len(allstores), 'stores:', nstore)
json.dump({hex(t): [v[0], [[a[0][0], a[0][1], a[0][2] if len(a[0]) > 2 else -1, a[1], a[2]] for a in v[1]]]
           for t, v in allstores.items()}, open('work_a1/k26/arrstores2.json', 'w'))

# rebuild arrays
def arrkey(a): return (a[0], a[1], a[2] if len(a) > 2 else -1)
cands = []
for tok, (nm, st) in allstores.items():
    groups = {}
    for arr, idx, val, off in st:
        groups.setdefault(arrkey(arr), {})[idx] = val
    for ak, m in groups.items():
        idxs = sorted(m)
        if not idxs: continue
        runs = []
        cur = [idxs[0]]
        for x in idxs[1:]:
            if x == cur[-1] + 1: cur.append(x)
            else: runs.append(cur); cur = [x]
        runs.append(cur)
        for r in runs:
            if len(r) >= 16:
                data = bytes(m[i] for i in r)
                cands.append((tok, nm, ak, r[0], len(r), data))
print('reconstructed arrays >=16B:', len(cands))
hits = 0
for tok, nm, ak, start, ln, data in cands:
    for kn, K in KNOWN:
        for o in range(0, ln - 31):
            if data[o:o+32] == K:
                print('*** KEY %s in 0x%08X %s arr=%s start=%d' % (kn, tok, nm, ak, start + o))
                hits += 1
print('known-key hits:', hits)
json.dump([[hex(t), nm, list(ak), st, ln, data.hex()] for t, nm, ak, st, ln, data in cands],
          open('work_a1/k26/arrcands.json', 'w'))
