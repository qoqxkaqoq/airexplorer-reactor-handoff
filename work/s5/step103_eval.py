#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step103: deterministic intra-block evaluator for 4192's key-building block
(blk0be0): track locals through stloc/ldloc, resolve add/sub chains, last-wins
stelem.i1 -> final AES Key(loc21,32B) / IV(loc1,16B) -> offline AES-CBC res5."""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

il = open('/workspace/repo_git/work/s5/mem5/il_all.bin', 'rb').read()
idx = {}
for line in open('/workspace/repo_git/work/s5/mem5/il_index.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), int(p[4]))

cl, pos = idx[0x06004192]
b = il[pos:pos + cl]
ins = parse(b)

# blk0be0 = from off 0xbe0 to next branch target; find end: next start after last stelem
# simpler: run from 0xbe0 until we hit AES-factory region; stop when 'stloc.s 5' (iv done) or
# scan whole 0xbe0..0x2200 span linearly (it's one dispatch-free run per earlier finding)
def run(start_off, end_off, label):
    seq = [e for e in ins if start_off <= e[0] < end_off]
    locals_ = {}
    stack = []
    writes = {}      # (arr,idx) -> val (last wins)
    worder = []      # ordered (off, arr, idx, val)
    unknown = 0
    arrmap = {}
    def ev(t):
        # returns int, ('arr', off) or None
        if t is None:
            return None
        if t[0] == 'c':
            return t[1]
        if t[0] == 'arr':
            return t
        if t[0] == 'a':
            if t[1][0] in locals_ and isinstance(locals_[t[1][0]], int):
                return locals_[t[1][0]] + t[1][1]
            return None
        if t[0] == 'v':
            return locals_.get(t[1])
        return None
    for e in seq:
        o, nm, op = e[0], e[1], e[3]
        if nm in ('ldc.i4', 'ldc.i4.s'):
            stack.append(('c', op if op is not None else 0))
        elif nm in ('ldc.i4.0','ldc.i4.1','ldc.i4.2','ldc.i4.3','ldc.i4.4','ldc.i4.5','ldc.i4.6','ldc.i4.7','ldc.i4.8','ldc.i4.m1'):
            stack.append(('c', {'ldc.i4.m1': -1}.get(nm, int(nm[-1]))))
        elif nm in ('ldloc', 'ldloc.s'):
            stack.append(('v', op))
        elif nm == 'add':
            if len(stack) >= 2:
                t2, t1 = stack.pop(), stack.pop()
                if t1[0] == 'c' and t2[0] == 'c':
                    stack.append(('c', t1[1] + t2[1]))
                elif t1[0] == 'v' and t2[0] == 'c':
                    stack.append(('a', (t1[1], t2[1])))
                elif t1[0] == 'c' and t2[0] == 'v':
                    stack.append(('a', (t2[1], t1[1])))
                else:
                    stack.append(('u', None))
            else:
                stack.append(('u', None))
        elif nm == 'sub':
            if len(stack) >= 2:
                t2, t1 = stack.pop(), stack.pop()
                if t1[0] == 'c' and t2[0] == 'c':
                    stack.append(('c', t1[1] - t2[1]))
                elif t1[0] == 'v' and t2[0] == 'c':
                    stack.append(('a', (t1[1], -t2[1])))
                else:
                    stack.append(('u', None))
            else:
                stack.append(('u', None))
        elif nm in ('conv.u8', 'conv.i8', 'conv.i4', 'conv.u4', 'conv.u', 'conv.i', 'nop'):
            pass
        elif nm == 'dup':
            if stack:
                stack.append(stack[-1])
        elif nm == 'newarr':
            if stack:
                stack.pop()
            stack.append(('arr', e[0]))
        elif nm in ('stloc', 'stloc.s'):
            t = stack.pop() if stack else ('u', None)
            v = ev(t)
            if isinstance(v, tuple):
                arrmap[v[1]] = op
            locals_[op] = v
        elif nm == 'stelem.i1':
            if len(stack) >= 3:
                tv_, ti, ta = stack.pop(), stack.pop(), stack.pop()
                vv, iv, av = ev(tv_), ev(ti), ev(ta)
                akey = av if isinstance(av, tuple) else av
                if vv is not None and iv is not None and akey is not None:
                    writes[(akey, iv & 0xFF)] = vv & 0xFF
                    worder.append((o, akey, iv & 0xFF, vv & 0xFF))
                else:
                    unknown += 1
            stack = []
        elif nm in ('call', 'callvirt', 'newobj', 'ldsfld', 'stsfld', 'ldfld', 'stfld', 'ldstr', 'ldtoken', 'newarr', 'ldlen', 'ldelem', 'ldelem.u1', 'ldelem.i4', 'ldelem.ref', 'stelem', 'stelem.ref', 'stelem.i4', 'brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'br', 'br.s', 'ble', 'bge', 'bgt', 'blt', 'beq', 'bne.un', 'leave', 'leave.s', 'ret', 'throw', 'box', 'unbox.any', 'castclass', 'isinst'):
            stack = []
            if nm in ('brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'br', 'br.s', 'leave', 'leave.s', 'ret', 'throw'):
                break
    print('[%s] writes=%d unknown-skips=%d' % (label, len(worder), unknown))
    return writes, worder, arrmap

# scan spans: keys region 0xbe0..0x2200 (before AES-factory call @21ff)
writes, worder, arrmap = run(0xbe0, 0x21ff, 'span be0-21ff')
def arrname(a):
    if isinstance(a, tuple):
        return 'loc%d' % arrmap.get(a[1], a[1])
    return 'loc%s' % a

# rebuild writes keyed by resolved local name: stloc of ('arr',off) recorded via arrmap
named = {}
for (a, i), v in writes.items():
    if isinstance(a, tuple):
        a2 = arrmap.get(a[1], a[1])
    else:
        a2 = a
    named[(a2, i)] = v
writes = named

arrs = sorted(set(a for a, i in writes))
for a in arrs:
    ks = sorted(i for a2, i in writes if a2 == a)
    print('arr %s: nidx=%d idxs=%s' % (arrname(a), len(ks), ks))

def mkarr(d, n, aid):
    a = [0] * n
    for (a2, i), v in d.items():
        if a2 == aid and i < n:
            a[i] = v
    return a

key = mkarr(writes, 32, 16)   # loc16 (32B)
iv = mkarr(writes, 16, 5)     # loc5 (16B)
print('KEY(loc16) = %s' % bytes(key).hex())
print('IV (loc5)  = %s' % bytes(iv).hex())
# also loc21 alias dump in case key block differs
import json

from Crypto.Cipher import AES
res5 = open('/workspace/repo_git/work/s5/mem5/r5/res5_cipher.bin', 'rb').read()
for kl in (32, 16):
    for kv, ivv, tag in ((bytes(key[:kl]), bytes(iv), 'k21/i1'), (bytes(iv), bytes(key[:16]), 'cross')):
        try:
            pt = AES.new(kv, AES.MODE_CBC, ivv).decrypt(res5)
        except Exception:
            continue
        pad = pt[-1]
        padok = 1 <= pad <= 16 and pt[-pad:] == bytes([pad]) * pad
        xml = pt.startswith(b'<') or b'RSAKeyValue' in pt[:64]
        print('try %s kl=%d padok=%s xml=%s pt[:48]=%r' % (tag, kl, padok, xml, pt[:48]))
        if padok or xml:
            print('  FULL PT: %r' % pt)
