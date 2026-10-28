#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step101: (a) dissect shims 041DB-041EE (post-Write chain in 4192),
(b) extract ALL stelem.i1 pairs in 4192 grouped by target array local var
   -> build AES key/IV candidates -> offline AES-128-CBC decrypt res5."""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

il = open(ALL, 'rb').read()
idx = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), int(p[4]))

import dnfile
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables
us = bytes(pe.net.metadata.streams[b'#US'].__data__)

def usdec(t):
    p = t & 0xFFFFFF
    b0 = us[p]
    if b0 & 0x80 == 0:
        ln, p = b0, p + 1
    elif b0 & 0xC0 == 0x80:
        ln = ((b0 & 0x3F) << 8) | us[p + 1]; p += 2
    else:
        ln = ((b0 & 0x1F) << 24) | (us[p + 1] << 16) | (us[p + 2] << 8) | us[p + 3]; p += 4
    return us[p:p + max(0, ln - 1)].decode('utf-16-le', 'replace')

def mref(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            return '06:%06x:%s' % (r, str(md.MethodDef.rows[r - 1].Name))
        if t == 0x0A:
            row = md.MemberRef.rows[r - 1]
            c = row.Class
            r2 = c.row if hasattr(c, 'row') else c
            cn = '?'
            if hasattr(r2, 'TypeName'):
                cn = (str(r2.TypeNamespace) + '.' if str(r2.TypeNamespace) else '') + str(r2.TypeName)
            elif hasattr(r2, 'Name'):
                cn = str(r2.Name)
            return '0A:' + cn + '::' + str(row.Name)
    except Exception:
        pass
    return hex(tok)

# ---------- (a) shims 041DB..041EE ----------
print('=== shims 041DB-041EE ===')
for tok in range(0x060041DB, 0x060041EF):
    if tok not in idx:
        continue
    cl, pos = idx[tok]
    b2 = il[pos:pos + cl]
    ins2 = parse(b2)
    names = []
    for e in ins2:
        nm = e[1]
        if nm in ('call', 'callvirt', 'newobj'):
            raw = struct.unpack_from('<I', b2, e[0] + 1)[0]
            names.append('%s@%04x=%s' % (nm, e[0], mref(raw)))
        elif nm == 'ldstr':
            raw = struct.unpack_from('<I', b2, e[0] + 1)[0]
            names.append('ldstr@%04x=%r' % (e[0], usdec(raw)))
        elif nm in ('ldc.i4', 'ldc.i4.s'):
            names.append('ldc@%04x=%d' % (e[0], e[3] or 0))
    print('  %s len=%d: %s' % (hex(tok), cl, ' | '.join(names)))

# ---------- (b) stelem extraction in 4192 ----------
TOK = 0x06004192
cl, pos = idx[TOK]
b = il[pos:pos + cl]
ins = parse(b)
N = len(ins)

# walk all blocks; simulate per-block stack; collect (array_var, idx, val, blockoff)
TERM = ('br', 'br.s', 'brfalse', 'brfalse.s', 'brtrue', 'brtrue.s', 'beq', 'beq.s', 'bge', 'bge.s',
        'bgt', 'bgt.s', 'ble', 'ble.s', 'blt', 'blt.s', 'bne.un', 'bne.un.s', 'switch', 'ret',
        'throw', 'leave', 'leave.s', 'endfinally', 'rethrow')
starts = set([0])
for i, e in enumerate(ins):
    if e[1] in TERM and i + 1 < N:
        starts.add(ins[i + 1][0])
    if e[1] == 'switch':
        starts.update(e[3])
    elif e[1].startswith(('br', 'ble', 'bge', 'bgt', 'blt', 'beq', 'leave')):
        starts.add(e[3])
starts = sorted(s for s in starts if s is not None)
blocks = {}
for si, s in enumerate(starts):
    end = starts[si + 1] if si + 1 < len(starts) else None
    body = [e for e in ins if e[0] >= s and (end is None or e[0] < end)]
    if body:
        blocks[s] = body

pairs = {}   # (arr, idx) -> set(vals)
seq = []     # (blockoff, arr, idx, val) in block order
for s, body in blocks.items():
    stack = []
    for e in body:
        nm, op = e[1], e[3]
        if nm in ('ldc.i4', 'ldc.i4.s'):
            stack.append(('c', op if op is not None else 0))
        elif nm in ('ldc.i4.0','ldc.i4.1','ldc.i4.2','ldc.i4.3','ldc.i4.4','ldc.i4.5','ldc.i4.6','ldc.i4.7','ldc.i4.8','ldc.i4.m1'):
            stack.append(('c', {'ldc.i4.m1': -1}.get(nm, int(nm[-1]))))
        elif nm in ('ldloc', 'ldloc.s'):
            stack.append(('v', op))
        elif nm == 'add':
            if len(stack) >= 2:
                t2, t1 = stack.pop(), stack.pop()
                if t1[0] == 'v' and t2[0] == 'c':
                    stack.append(('a', (t1[1], t2[1])))
                elif t1[0] == 'c' and t2[0] == 'c':
                    stack.append(('c', t1[1] + t2[1]))
                else:
                    stack = []
        elif nm == 'sub':
            if len(stack) >= 2:
                t2, t1 = stack.pop(), stack.pop()
                if t1[0] == 'v' and t2[0] == 'c':
                    stack.append(('a', (t1[1], -t2[1])))
                elif t1[0] == 'c' and t2[0] == 'c':
                    stack.append(('c', t1[1] - t2[1]))
                else:
                    stack = []
        elif nm in ('newarr',):
            stack = []
        elif nm in ('stloc', 'stloc.s'):
            if stack:
                stack.pop()
        elif nm == 'stelem.i1':
            if len(stack) >= 3:
                val, idxn, arr = stack.pop(), stack.pop(), stack.pop()
                ai = None
                if arr[0] == 'v':
                    ai = arr[1]
                elif arr[0] == 'a':
                    ai = arr[1]
                ii = None
                if idxn[0] == 'c':
                    ii = idxn[1]
                elif idxn[0] == 'a':
                    ii = idxn[1]
                vi = None
                if val[0] == 'c':
                    vi = val[1]
                elif val[0] == 'a':
                    vi = val[1]
                if ai is not None and ii is not None and vi is not None:
                    key = (ai, ii)
                    pairs.setdefault(key, set()).add(vi & 0xFF)
                    seq.append((s, ai, ii, vi & 0xFF))
            stack = []
        else:
            stack = []

print('\n=== stelem.i1 pairs: %d (arr,idx) keys ===' % len(pairs))
arrs = sorted(set(k[0] for k in pairs))
print('array vars:', [hex(a) if isinstance(a, int) else a for a in arrs])
for a in arrs:
    ks = sorted(k[1] for k in pairs if k[0] == a)
    print('  arr loc%s: idxs=%s' % (a, ks))
    conflicts = {i: v for i, v in ((i, sorted(pairs[(a, i)])) for i in ks) if len(v) > 1}
    if conflicts:
        print('    conflicts:', conflicts)

# build candidate arrays: unique value per idx
def build(a):
    out = {}
    ok = True
    for (a2, i), vs in pairs.items():
        if a2 != a:
            continue
        if len(vs) == 1:
            out[i] = next(iter(vs))
        else:
            ok = False
    return out, ok

for a in arrs:
    d, ok = build(a)
    mx = max(d) if d else -1
    arr = [0] * (mx + 1)
    for i, v in d.items():
        arr[i] = v
    print('\narr loc%s unique=%s len=%d hex=%s' % (a, ok, len(arr), bytes(arr).hex()))

# also dump seq order for the two candidate arrays
print('\n=== seq (block, arr, idx, val) count=%d ===' % len(seq))
for s, a, i, v in seq[:80]:
    print('  blk%04x loc%s[%d] = %02x' % (s, a, i, v))
