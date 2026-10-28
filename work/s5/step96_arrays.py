#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step96: extract hardcoded byte arrays built via stelem.i1 inside 06004192
(crypto key/IV candidates). Uses flat.parse + constant folding of the value
expression and index expression."""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

EXE = '/workspace/repo_git/exes/AirExplorer_a1.exe'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

il = open(ALL, 'rb').read()
idx = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), int(p[4]))

cl, pos = idx[0x06004192]
b = il[pos:pos + cl]
ins = parse(b)
off2i = {e[0]: i for i, e in enumerate(ins)}

def fold_back(start_i, want_ops=('ldc.i4', 'ldc.i4.s', 'ldc.i4.m1')):
    """fold the expression ending right before start_i; returns int or None"""
    stack = []
    j = start_i
    steps = 0
    while j >= 0 and steps < 30:
        steps += 1
        e = ins[j]
        nm = e[1]
        if nm in ('ldc.i4', 'ldc.i4.s'):
            stack.append(e[3]); j -= 1
        elif nm == 'ldc.i4.m1':
            stack.append(-1); j -= 1
        elif nm.startswith('ldc.i4.'):
            stack.append(int(nm[-1])); j -= 1
        elif nm == 'add':
            if len(stack) >= 2:
                x, y = stack.pop(), stack.pop()  # order: pushed y then x; x+y
                stack.append(y + x)
            j -= 1
        elif nm == 'sub':
            if len(stack) >= 2:
                x, y = stack.pop(), stack.pop()
                stack.append(y - x)
            j -= 1
        elif nm == 'ldloc' or nm == 'ldloc.s':
            return None  # runtime value, stop
        elif nm == 'conv.i1' or nm == 'conv.u1' or nm == 'conv.i4' or nm == 'conv.i8' or nm == 'conv.u8':
            j -= 1
        elif nm == 'ldlen' or nm.startswith('ldelem') or nm == 'ldsfld' or nm == 'ldfld':
            return None
        else:
            return None
    if len(stack) == 1:
        v = stack[0]
        v &= 0xFFFFFFFF
        return v - 0x100000000 if v >= 0x80000000 else v
    return None

# scan stelem.i1 sites: pattern [.. arr .. idx .. val ..] stelem.i1
stelems = [i for i, e in enumerate(ins) if e[1] == 'stelem.i1']
print('[4192] stelem.i1 count=%d' % len(stelems))

pairs = {}  # idx -> val (fold)
fails = 0
for i in stelems:
    # value expr: fold backwards from i-1; index expr: before that
    # find val first: scan back for boundary (ldc or arithmetic chain)
    val = fold_back(i)
    # naive: find the two constant expressions preceding stelem
    # walk back collecting two folded expressions
    seq = []
    j = i - 1
    got = []
    tries = 0
    while j >= 0 and tries < 40 and len(got) < 2:
        tries += 1
        e = ins[j]
        # attempt fold from j backwards
        v = fold_back(j)
        if v is not None:
            got.append(v)
            # skip the instruction range consumed: walk back over contiguous const/arith ops
            k = j
            ops = 0
            while k >= 0 and ops < 10:
                nm = ins[k][1]
                if nm in ('ldc.i4', 'ldc.i4.s', 'ldc.i4.m1') or nm.startswith('ldc.i4.') or nm in ('add', 'sub', 'conv.i1', 'conv.u1', 'conv.i4'):
                    k -= 1
                    ops += 1
                else:
                    break
            j = k
        else:
            j -= 1
    if len(got) >= 2:
        idxv, valv = got[1], got[0]  # idx pushed first, val second
        pairs[idxv] = valv
    else:
        fails += 1

print('[4192] folded idx->val pairs=%d fails=%d' % (len(pairs), fails))
ks = sorted(pairs)
if ks:
    lo, hi = ks[0], ks[-1]
    print('[4192] idx range %d..%d' % (lo, hi))
    arr = [None] * (hi + 1)
    for k, v in pairs.items():
        arr[k] = v & 0xFF
    # contiguous runs
    run = []
    runs = []
    for i, v in enumerate(arr):
        if v is not None:
            run.append((i, v))
        else:
            if run:
                runs.append(run); run = []
    if run:
        runs.append(run)
    print('[4192] contiguous runs=%d' % len(runs))
    for r in runs:
        vals = bytes(v for _, v in r)
        print('  idx %d..%d len=%d: %s' % (r[0][0], r[-1][0], len(vals), vals.hex()))
        try:
            print('    ascii: %r' % vals.decode('ascii'))
        except Exception:
            pass
