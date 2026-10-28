#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step102: (a) confirm key/IV array identity (ldloc 21->stloc 16?),
(b) per-block last-wins stelem reconstruction -> candidate AES key/IV,
(c) offline AES-CBC decrypt res5 with candidates -> PKCS7/XML validation,
(d) recon: TypeDef owner of shim 041D8 + its static fields; MemberRef File::WriteAllBytes."""
import sys, struct, itertools
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
RES5 = '/workspace/repo_git/work/s5/mem5/r5/res5_cipher.bin'

il = open(ALL, 'rb').read()
idx = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), int(p[4]))

import dnfile
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

TOK = 0x06004192
cl, pos = idx[TOK]
b = il[pos:pos + cl]
ins = parse(b)
N = len(ins)

# (a) find 'ldloc 21' followed closely by 'stloc 16' (or any loc->16 copies)
print('=== stloc 16 sites ===')
for i, e in enumerate(ins):
    if e[1] in ('stloc', 'stloc.s') and e[3] == 16:
        prev = ins[i - 1]
        print('  @%04x stloc16 <- %s %s' % (e[0], prev[1], prev[3]))

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

# (b) per-block last-wins for loc1 and loc21
def block_arrays(body):
    """returns {arr: {idx: val}} last-wins within block"""
    stack = []
    out = {}
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
        elif nm in ('newarr', 'stloc', 'stloc.s'):
            stack = []
        elif nm == 'stelem.i1':
            if len(stack) >= 3:
                val, idxn, arr = stack.pop(), stack.pop(), stack.pop()
                def tv(t):
                    if t[0] == 'c':
                        return t[1] & 0xFF
                    if t[0] == 'a':
                        return t[1][0] & 0xFF
                    return None
                av = arr[1] if arr[0] in ('v', 'a') else None
                iv = tv(idxn)
                vv = tv(val)
                if av is not None and iv is not None and vv is not None:
                    out.setdefault(av, {})[iv] = vv
            stack = []
        else:
            stack = []
    return out

cand_blocks = []
for s, body in blocks.items():
    d = block_arrays(body)
    if 1 in d or 21 in d:
        cand_blocks.append((s, d))

print('\n=== blocks writing loc1/loc21: %d ===' % len(cand_blocks))
for s, d in cand_blocks:
    parts = []
    for a in sorted(d):
        idxs = sorted(d[a])
        parts.append('loc%d[%s]' % (a, ','.join(map(str, idxs))))
    print('  blk%04x: %s' % (s, ' + '.join(parts)))

# (c) candidate generation + offline AES test
res5 = open(RES5, 'rb').read()
try:
    from Crypto.Cipher import AES
    HAVE = 'pycryptodome'
except ImportError:
    try:
        from Cryptodome.Cipher import AES
        HAVE = 'pycryptodome-c'
    except ImportError:
        AES = None
        HAVE = None
print('\n[crypto lib]', HAVE)

def try_decrypt(key, iv, tag):
    if AES is None or not key or not iv:
        return False
    for kl in (16, 24, 32):
        if len(key) < kl:
            continue
        k = bytes(key[:kl])
        try:
            c = AES.new(k, AES.MODE_CBC, bytes(iv))
            pt = c.decrypt(res5)
        except Exception:
            continue
        # PKCS7 check
        pad = pt[-1]
        padok = 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad
        xml = pt.startswith(b'<') or b'RSAKeyValue' in pt[:64]
        if padok or xml:
            print('[HIT] %s keylen=%d pad=%d xml=%s' % (tag, kl, pad, xml))
            print('  key=%s' % k.hex())
            print('  iv=%s' % bytes(iv).hex())
            print('  pt[:96]=%r' % pt[:96])
            return True
    return False

# global last-wins (by block offset order)
g1, g21 = {}, {}
for s, d in sorted(cand_blocks):
    if 1 in d:
        g1.update(d[1])
    if 21 in d:
        g21.update(d[21])

def mkarr(d, n):
    a = [0] * n
    for i, v in d.items():
        if i < n:
            a[i] = v
    return a

iv1 = mkarr(g1, 16)
key21 = mkarr(g21, 32)
print('\nglobal last-wins: iv(loc1)=%s' % bytes(iv1).hex())
print('                  key(loc21)=%s' % bytes(key21).hex())
try_decrypt(key21, iv1, 'global-lastwins')

# per-block combos: for loc21 blocks x loc1 blocks
kblocks = [s for s, d in cand_blocks if 21 in d]
iblocks = [s for s, d in cand_blocks if 1 in d]
print('\ntrying per-block combos: %d kblocks x %d iblocks' % (len(kblocks), len(iblocks)))
hits = 0
for ks in kblocks:
    d21 = dict(cand_blocks[[s for s, _ in cand_blocks].index(ks)][1].get(21, {}))
    for isb in iblocks:
        d1 = dict(cand_blocks[[s for s, _ in cand_blocks].index(isb)][1].get(1, {}))
        key = mkarr(d21, 32)
        iv = mkarr(d1, 16)
        if try_decrypt(key, iv, 'blk%04x/blk%04x' % (ks, isb)):
            hits += 1
print('per-block hits:', hits)

# also: maybe key is 16B (loc1 as key, loc21 as iv) or swapped roles
print('\ncross try: key=loc1 iv=loc21 / swapped')
for ks in kblocks:
    d21 = dict(cand_blocks[[s for s, _ in cand_blocks].index(ks)][1].get(21, {}))
    key = mkarr(d21, 32)
    iv = mkarr(g1, 16)
    try_decrypt(iv, key[:16], 'cross-A')
    try_decrypt(key[:16], iv, 'cross-B')

# (d) recon: owner type of 041D8 + statics; File::WriteAllBytes memberref
print('\n=== owner of 041D8 ===')
tokrow = 0x041D8
m = md.MethodDef.rows[tokrow - 1]
for ti, td in enumerate(md.TypeDef.rows):
    mlist = [mi.row for mi in td.MethodList if hasattr(mi, 'row')]
    if any(x is m for x in mlist) or (mlist and any(str(x.Name) == str(m.Name) for x in mlist)):
        pass
# simpler: MethodSemantics/parent via TypeDef method ranges
owner = None
for ti, td in enumerate(md.TypeDef.rows):
    for mi in td.MethodList:
        r = mi.row if hasattr(mi, 'row') else mi
        if r is m:
            owner = td
            break
    if owner:
        break
if owner:
    print('owner: %s.%s' % (owner.TypeNamespace, owner.TypeName))
    for f in owner.FieldList:
        fr = f.row if hasattr(f, 'row') else f
        print('  fld %s sig=%s' % (fr.Name, fr.Signature.__bytes__().hex() if hasattr(fr.Signature, '__bytes__') else '?'))

print('\n=== MemberRef File::WriteAllBytes / File class refs ===')
for i, mr in enumerate(md.MemberRef.rows):
    cn = ''
    try:
        c = mr.Class
        r2 = c.row if hasattr(c, 'row') else c
        if hasattr(r2, 'TypeName'):
            cn = str(r2.TypeNamespace) + '.' + str(r2.TypeName)
    except Exception:
        pass
    if cn == 'System.IO.File':
        print('  0A:%06x File::%s' % (i + 1, mr.Name))
