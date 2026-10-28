#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step95 v2: control-flow-flattening walker for 06004192, using flat.parse's
pre-parsed operands (off, name, kind, operand, plen)."""
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

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            return '06:' + str(md.MethodDef.rows[r - 1].Name)
        if t == 0x0A:
            row = md.MemberRef.rows[r - 1]
            cn = '?'
            try:
                c = row.Class
                r2 = c.row if hasattr(c, 'row') else c
                if hasattr(r2, 'TypeName'):
                    cn = (str(r2.TypeNamespace) + '.' if str(r2.TypeNamespace) else '') + str(r2.TypeName)
                elif hasattr(r2, 'Name'):
                    cn = str(r2.Name)
            except Exception:
                pass
            return '0A:' + cn + '::' + str(row.Name)
    except Exception:
        return hex(tok)
    return hex(tok)

cl, pos = idx[0x06004192]
b = il[pos:pos + cl]
ins = parse(b)
N = len(ins)
off2i = {e[0]: i for i, e in enumerate(ins)}

TERM = ('br', 'br.s', 'brfalse', 'brfalse.s', 'brtrue', 'brtrue.s', 'beq', 'beq.s', 'bge', 'bge.s',
        'bgt', 'bgt.s', 'ble', 'ble.s', 'blt', 'blt.s', 'bne.un', 'bne.un.s', 'bge.un', 'bge.un.s',
        'bgt.un', 'bgt.un.s', 'ble.un', 'ble.un.s', 'blt.un', 'blt.un.s', 'switch', 'ret', 'throw',
        'leave', 'leave.s', 'endfinally', 'rethrow')

# blocks
starts = set([0])
for i, e in enumerate(ins):
    if e[1] in TERM:
        if i + 1 < N:
            starts.add(ins[i + 1][0])
    if e[1] == 'switch':
        starts.update(e[3])
    elif e[1].startswith('br') or e[1].startswith('ble') or e[1].startswith('bge') or \
         e[1].startswith('bgt') or e[1].startswith('blt') or e[1].startswith('beq') or e[1].startswith('leave'):
        starts.add(e[3])
starts = sorted(s for s in starts if s is not None)
blocks = {}
for si, s in enumerate(starts):
    end = starts[si + 1] if si + 1 < len(starts) else None
    body = [e for e in ins if e[0] >= s and (end is None or e[0] < end)]
    if body:
        blocks[s] = body

def block_effect(body):
    """returns (sets[(dst,val)], moves[(dst,src,delta)])"""
    sets, moves = [], []
    stack = []
    for e in body:
        nm, k, op = e[1], e[2], e[3]
        if nm in ('ldc.i4', 'ldc.i4.s'):
            stack.append(('c', op))
        elif nm in ('ldc.i4.0','ldc.i4.1','ldc.i4.2','ldc.i4.3','ldc.i4.4','ldc.i4.5','ldc.i4.6','ldc.i4.7','ldc.i4.8','ldc.i4.m1'):
            stack.append(('c', {'ldc.i4.m1':-1}.get(nm, int(nm[-1]))))
        elif nm in ('ldloc', 'ldloc.s'):
            stack.append(('v', op))
        elif nm == 'add':
            if len(stack) >= 2:
                t2, t1 = stack.pop(), stack.pop()
                if t1[0] == 'v' and t2[0] == 'c':
                    stack.append(('a', (t1[1], t2[1])))
                else:
                    stack = []
        elif nm in ('stloc', 'stloc.s'):
            if stack:
                t = stack.pop()
                if t[0] == 'c':
                    sets.append((op, t[1]))
                elif t[0] == 'a':
                    sets.append((op, (t[1][0], t[1][1])))
        elif nm in ('nop', 'dup', 'pop'):
            pass
        else:
            stack = []
    return sets, moves

def i32(v):
    v &= 0xFFFFFFFF
    return v - 0x100000000 if v >= 0x80000000 else v

def summarize(body):
    parts = []
    for e in body:
        nm, k, op = e[1], e[2], e[3]
        if nm in ('call', 'callvirt', 'newobj'):
            parts.append('%s@%04x=%s' % (nm, e[0], mname(op)))
        elif nm == 'ldstr':
            parts.append('ldstr@%04x=%r' % (e[0], usdec(op)))
        elif nm in ('ldsfld', 'stsfld', 'ldfld'):
            try:
                parts.append('%s@%04x=fld:%s' % (nm, e[0], md.Field.rows[(op & 0xFFFFFF) - 1].Name))
            except Exception:
                pass
        elif nm == 'throw':
            parts.append('THROW@%04x' % e[0])
        elif nm == 'ret':
            parts.append('RET@%04x' % e[0])
        elif nm == 'ldtoken':
            parts.append('ldtoken@%04x=%s' % (e[0], hex(op)))
        elif nm == 'newarr':
            parts.append('newarr@%04x' % e[0])
    return parts

state = {}
cur = 0
visited = set()
order = []
steps = 0
while steps < 3000:
    steps += 1
    if cur not in blocks:
        print('[walk] dead-end %04x' % cur); break
    body = blocks[cur]
    sets, _ = block_effect(body)
    for v, val in sets:
        if isinstance(val, tuple):
            src, delta = val
            base = state.get(src, 0)
            if isinstance(base, tuple):
                base = 0
            state[v] = i32(base + delta)
        else:
            state[v] = val
    sm = summarize(body)
    visited.add(cur)
    order.append((cur, len(body), sm))
    last = body[-1]
    nm = last[1]
    nxt = None
    if nm == 'switch':
        tgts = last[3]
        dv = None
        for e in reversed(body[:-1]):
            if e[1] in ('ldloc', 'ldloc.s'):
                dv = e[3]; break
            if e[1] in ('stloc', 'stloc.s'):
                continue
            break
        val = state.get(dv)
        if val is None or not (0 <= val < len(tgts)):
            print('[walk] switch@%04x unknown state var=%s val=%s cases=%d - stop' % (last[0], dv, val, len(tgts)))
            break
        nxt = tgts[val]
    elif nm in ('br', 'br.s', 'leave', 'leave.s'):
        nxt = last[3]
    elif nm in TERM:
        if nm in ('ret', 'throw', 'endfinally', 'rethrow'):
            print('[walk] terminator %s@%04x - stop' % (nm, last[0])); break
        fi = off2i[last[0]] + 1
        nxt = ins[fi][0] if fi < N else None
    else:
        fi = off2i[last[0]] + 1
        nxt = ins[fi][0] if fi < N else None
    if nxt is None or nxt not in blocks:
        print('[walk] bad target %s' % nxt); break
    cur = nxt
    if len(visited) > 600:
        print('[walk] cap'); break

print('\n=== execution order (%d blocks, %d uniq) ===' % (len(order), len(visited)))
for off, ln, sm in order:
    print('  %04x len=%d : %s' % (off, ln, ' | '.join(sm[:5]) if sm else '-'))
