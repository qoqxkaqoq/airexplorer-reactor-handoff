# -*- coding: utf-8 -*-
"""step54: linear per-block scan of 0600419C switch blocks — extract constant
stelem.i1 writes; focus on loc4 (AES key source per 0600419C@0x5E05/0x818F chain)."""
import struct, zipfile, collections
z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
d = z.read('m_0600419C.bin')
il = d[24:24+struct.unpack('<I', d[4:8])[0]]
ins = cildasm_disasm_all = None
import sys
sys.path.insert(0, '/workspace/repo_git/work/s5')
import cildasm
ins = cildasm.disasm(il)
by_off = {t[0]: i for i, t in enumerate(ins)}

cnt = struct.unpack_from('<I', il, 0x17)[0]
tbl = [struct.unpack_from('<i', il, 0x1B+i*4)[0] for i in range(cnt)]
POST = 0x1B + cnt*4

def block_range(start):
    i = by_off[start]
    out = []
    while i < len(ins):
        o, nm, opb, nxt, tg = ins[i]
        out.append(ins[i])
        if nm in ('br', 'br.s'):
            break
        if nm in ('ret', 'throw') or nm.startswith('leave'):
            break
        i += 1
    return out

def const_writes(block):
    """linear scan: track loc4B/loc2D constant assignments; return writes"""
    stack = []
    locs = {}
    writes = []
    for o, nm, opb, nxt, tg in block:
        if nm == 'ldc.i4' and opb and len(opb) == 4:
            stack.append(struct.unpack('<i', bytes(opb))[0])
        elif nm == 'ldc.i4.s':
            stack.append(struct.unpack('<b', bytes(opb))[0])
        elif nm.startswith('ldc.i4.'):
            stack.append({'ldc.i4.0':0,'ldc.i4.1':1,'ldc.i4.2':2,'ldc.i4.3':3,'ldc.i4.4':4,'ldc.i4.5':5,'ldc.i4.6':6,'ldc.i4.7':7,'ldc.i4.8':8}.get(nm, 0))
        elif nm in ('add', 'sub', 'xor', 'and', 'or'):
            if len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                stack.append(({'add': a+b, 'sub': a-b, 'xor': a^b, 'and': a&b, 'or': a|b}[nm]) & 0xFFFFFFFF if isinstance(a, int) and isinstance(b, int) else None)
            else:
                stack.append(None)
        elif nm == 'fe.stloc' and opb and len(opb) == 2:
            l = struct.unpack('<H', bytes(opb))[0]
            locs[l] = stack.pop() if stack else None
        elif nm == 'fe.ldloc' and opb and len(opb) == 2:
            l = struct.unpack('<H', bytes(opb))[0]
            stack.append(locs.get(l, ('v', l)))
        elif nm in ('ldsfld', 'ldfld', 'call', 'callvirt', 'newobj', 'ldarg', 'ldarga', 'ldloca', 'ldc.r4', 'ldc.r8', 'ldnull', 'ldstr', 'ldtoken', 'box', 'unbox.any', 'castclass', 'isinst', 'ldelem.i1', 'ldelem.u1', 'ldelem.i4', 'ldelem.ref', 'ldlen', 'dup', 'ldc.i8'):
            if nm == 'dup':
                if stack: stack.append(stack[-1])
            else:
                npop = {'ldfld':1,'ldflda':1,'ldelem.i1':2,'ldelem.u1':2,'ldelem.i4':2,'ldelem.ref':2,'ldlen':1,'castclass':1,'isinst':1,'box':1,'unbox.any':1}.get(nm, 0)
                for _ in range(npop):
                    if stack: stack.pop()
                stack.append(('ext', nm))
        elif nm in ('stelem.i1', 'stelem.i4', 'stelem.i8', 'stelem.ref'):
            if len(stack) >= 3:
                arr, idx, val = stack[-3], stack[-2], stack[-1]
                ai = arr[1] if isinstance(arr, tuple) and arr[0] == 'v' else (arr if isinstance(arr, int) else -1)
                writes.append((ai, idx if isinstance(idx, int) else None, val if isinstance(val, int) else None, o))
                del stack[-3:]
        elif nm in ('pop',):
            if stack: stack.pop()
        elif nm.startswith('stloc') or nm == 'fe.stloc':
            if nm != 'fe.stloc':
                stack.pop() if stack else None
        elif nm in ('nop', 'conv.i4', 'conv.i8', 'conv.u4', 'conv.u8', 'conv.i', 'conv.u'):
            pass
        elif nm in ('brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'beq', 'bne.un', 'bge', 'ble', 'bgt', 'blt') or nm.startswith(('brtrue.s', 'brfalse.s')):
            npop = 1 if ('brtrue' in nm or 'brfalse' in nm) else 2
            for _ in range(npop):
                if stack: stack.pop()
        elif nm.startswith('br'):
            break
    return writes

# scan all blocks
allw = collections.defaultdict(list)  # arr -> list of (idx, val, off, block)
for bi in range(cnt):
    start = POST + tbl[bi]
    if start not in by_off:
        continue
    blk = block_range(start)
    for arr, idx, val, off in const_writes(blk):
        if arr >= 0 and idx is not None and val is not None:
            allw[arr].append((idx, val & 0xFF, off, bi))

print('arrays written (constant-determined):')
for arr in sorted(allw):
    ws = allw[arr]
    mx = max(w[0] for w in ws)
    if mx < 64:
        per_idx = collections.defaultdict(set)
        for idx, val, off, bi in ws:
            per_idx[idx].add(val)
        nconf = sum(1 for i, s in per_idx.items() if len(s) > 1)
        print('arr loc%d: %d writes, idx 0..%d, conflicting idx: %d' % (arr, len(ws), mx, nconf))

print()
print('=== loc4 (AES key) writes ===')
ws = sorted(allw.get(4, []))
by_idx = collections.defaultdict(list)
for idx, val, off, bi in ws:
    by_idx[idx].append((val, off, bi))
for idx in sorted(by_idx):
    print(' loc4[%2d] = %s' % (idx, ['%02X @%04X blk%d' % t for t in by_idx[idx]]))
print()
print('=== loc33 (0x21) writes ===')
ws = sorted(allw.get(33, []))
by_idx = collections.defaultdict(list)
for idx, val, off, bi in ws:
    by_idx[idx].append((val, off, bi))
for idx in sorted(by_idx):
    print(' loc33[%2d] = %s' % (idx, ['%02X @%04X blk%d' % t for t in by_idx[idx]]))
