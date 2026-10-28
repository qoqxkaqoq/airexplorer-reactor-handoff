#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step96b: stack-simulation extraction of stelem.i1 (idx,val) pairs in 4192.
Walks forward through blocks, maintaining a mini stack; folds ldc/add/sub;
marks unknown as 'R'. Records (idx,val) when both known."""
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

def i32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v

stack = []
pairs = {}
cur_arr = None
for e in ins:
    nm, k, op = e[1], e[2], e[3]
    if nm in ('ldc.i4', 'ldc.i4.s'):
        stack.append(op)
    elif nm in ('ldc.i4.0','ldc.i4.1','ldc.i4.2','ldc.i4.3','ldc.i4.4','ldc.i4.5','ldc.i4.6','ldc.i4.7','ldc.i4.8'):
        stack.append(int(nm[-1]))
    elif nm == 'ldc.i4.m1':
        stack.append(-1)
    elif nm in ('ldloc', 'ldloc.s', 'ldarg', 'ldarg.s', 'ldarg.0','ldarg.1','ldarg.2','ldarg.3',
                'ldloc.0','ldloc.1','ldloc.2','ldloc.3'):
        stack.append('R')
    elif nm in ('add', 'sub'):
        if len(stack) >= 2:
            y, x = stack.pop(), stack.pop()
            if isinstance(x, int) and isinstance(y, int):
                stack.append(i32(x - y if nm == 'sub' else x + y))
            else:
                stack.append('R')
        else:
            stack = ['R']
    elif nm == 'stelem.i1':
        if len(stack) >= 3:
            v, ix, ar = stack.pop(), stack.pop(), stack.pop()
            if isinstance(ix, int) and isinstance(v, int):
                pairs[ix] = v & 0xFF
            elif isinstance(ix, int):
                pairs.setdefault(ix, 'R')
        stack = []
    elif nm in ('dup',):
        if stack:
            stack.append(stack[-1])
    elif nm in ('pop',):
        if stack:
            stack.pop()
    elif nm in ('nop', 'conv.i1', 'conv.u1', 'conv.i4', 'conv.i8', 'conv.u8', 'conv.i', 'conv.u',
                'br', 'br.s', 'brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'leave', 'leave.s',
                'beq', 'bge', 'bgt', 'ble', 'blt', 'bne.un', 'switch', 'stloc', 'stloc.s', 'ldtoken',
                'ldstr', 'ldsfld', 'stsfld', 'ldfld', 'ret', 'throw', 'endfinally', 'rethrow',
                'newarr', 'ldlen', 'ldc.i8', 'box', 'unbox.any', 'castclass', 'isinst'):
        if nm in ('stloc', 'stloc.s', 'throw', 'ret', 'newarr', 'leave', 'leave.s', 'br', 'br.s', 'switch', 'endfinally', 'rethrow'):
            stack = []
        # others: neutral (keep stack; conservative enough for stelem windows)
    else:
        # call/callvirt/newobj/ldelem/ldflda etc: pops unknown, pushes R
        stack = ['R'] if nm in ('call', 'callvirt', 'newobj', 'ldelem.u1', 'ldelem.i1', 'ldelem.i4', 'ldfld', 'ldsfld', 'ldlen') else []

print('[4192] stelem pairs=%d' % len(pairs))
known = {k: v for k, v in pairs.items() if v != 'R'}
print('[4192] fully-known pairs=%d runtime=%d' % (len(known), len(pairs) - len(known)))
if pairs:
    ks = sorted(k for k in pairs if isinstance(k, int))
    lo, hi = ks[0], ks[-1]
    print('[4192] idx span %d..%d' % (lo, hi))
    arr = [None] * (hi + 1)
    mixed = 0
    for k, v in pairs.items():
        if v == 'R':
            mixed += 1
        else:
            arr[k] = v
    runs, run = [], []
    for i, v in enumerate(arr):
        if v is not None:
            run.append(v)
        else:
            if run:
                runs.append(run); run = []
    if run:
        runs.append(run)
    print('[4192] runs=%d (gaps=%d)' % (len(runs), mixed))
    for r in runs:
        vals = bytes(r)
        print('  len=%d @span: %s' % (len(vals), vals.hex()))
        try:
            print('    ascii: %r' % vals.decode('ascii'))
        except Exception:
            pass
    # known-value density
    print('[4192] known=%d of span=%d' % (len(known), hi - lo + 1))
