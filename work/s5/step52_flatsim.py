# -*- coding: utf-8 -*-
"""step52: switch-flattener state machine evaluator for 0600419C.
Dispatch: loc48 = loc1B + K48 (per-block const), loc1B += K1B, br -> switch at 0x0012.
Collect stelem.i1 writes to recover AES key/IV arrays."""
import struct, sys, zipfile, collections, json
sys.path.insert(0, '/workspace/repo_git/work/s5')
import cildasm

DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(DUMP)
d = z.read('m_0600419C.bin')
ilsz = struct.unpack('<I', d[4:8])[0]
il = d[24:24+ilsz]
ins = cildasm.disasm(il)
by_off = {}
for i, t in enumerate(ins):
    by_off[t[0]] = i
N = len(ins)
M32 = 0xFFFFFFFF

SW_OFF = None
SW_TABLE = None
for o, nm, opb, nxt, tg in ins:
    if nm == 'switch':
        if len(opb) % 4 == 0 and len(opb) > 4:
            cnt = struct.unpack_from('<I', bytes(opb), 0)[0]
            if cnt == len(opb) // 4 - 1:  # opb includes 4-byte count prefix
                opb = opb[4:]
        n = len(opb) // 4
        SW_OFF = o
        SW_TABLE = [struct.unpack_from('<i', bytes(opb), i*4)[0] for i in range(n)]
        break
POST = SW_OFF + 5 + len(SW_TABLE) * 4
print('switch @0x%04X targets=%d post=0x%04X' % (SW_OFF, len(SW_TABLE), POST))

# state-1B init: first instruction ldc.i4 -> stloc 1b00
INIT_1B = struct.unpack('<I', bytes(ins[0][2]))[0]
print('init loc1B=0x%08X' % INIT_1B)

def run_block(start, locs, writes, depth):
    """Execute linearly from instruction index of start; locs mutable copy.
    Returns ('dispatch', new_locs) or ('branch', target_off) or ('cond', t, f, locs) or ('end', locs)."""
    if start not in by_off:
        return ('end', dict(locs))
    i = by_off[start]
    stack = []
    locs = dict(locs)
    while i < N:
        o, nm, opb, nxt, tg = ins[i]
        if nm == 'switch':
            v = stack.pop() if stack else None
            if isinstance(v, int) and 0 <= v < len(SW_TABLE):
                t = POST + SW_TABLE[v]
                return ('branch', t, locs)
            return ('branch', POST, locs)  # fallthrough
        if nm in ('br', 'br.s'):
            t = o + (5 if len(opb) == 4 else 2) + struct.unpack('<i', bytes(opb))[0]
            return ('branch', t, locs)
        if nm in ('brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'beq', 'beq.s', 'bne.un', 'bne.un.s', 'bge', 'bge.s', 'ble', 'ble.s', 'bgt', 'bgt.s', 'blt', 'blt.s'):
            one = nm.startswith('brtrue') or nm.startswith('brfalse')
            need = 1 if one else 2
            if len(stack) < need:
                return ('end', locs)  # structurally invalid path -> prune
            t = o + (5 if len(opb) == 4 else 2) + (struct.unpack('<i', bytes(opb))[0] if len(opb) == 4 else struct.unpack('<b', bytes(opb))[0])
            # static decision when values known
            if one:
                v = stack[-1]
                if isinstance(v, int):
                    taken = (v != 0) if nm.startswith('brtrue') else (v == 0)
                    return ('branch', t if taken else (o + (5 if len(opb) == 4 else 2)), locs)
            else:
                a, b = stack[-2], stack[-1]
                if isinstance(a, int) and isinstance(b, int):
                    ops = {'beq': a == b, 'bne.un': (a & M32) != (b & M32), 'bge': a >= b, 'ble': a <= b, 'bgt': a > b, 'blt': a < b}
                    base = nm.split('.')[0]
                    taken = ops.get(base)
                    if taken is not None:
                        return ('branch', t if taken else (o + (5 if len(opb) == 4 else 2)), locs)
            return ('cond', t, o + (5 if len(opb) == 4 else 2), locs)
        if nm == 'stelem.i1' or nm == 'stelem.i4' or nm == 'stelem.i8' or nm == 'stelem.ref':
            if len(stack) >= 3:
                arr, idx, val = stack[-3], stack[-2], stack[-1]
                writes.append((arr if isinstance(arr, int) else -1,
                               idx if isinstance(idx, int) else None,
                               val if isinstance(val, int) else None, o, nm))
                del stack[-3:]
            i += 1
            continue
        if nm == 'ldc.i4' and opb and len(opb) == 4:
            stack.append(struct.unpack('<i', bytes(opb))[0]); i += 1; continue
        if nm == 'ldc.i4.s':
            stack.append(struct.unpack('<b', bytes(opb))[0]); i += 1; continue
        if nm == 'ldc.i4.m1':
            stack.append(-1); i += 1; continue
        if nm.startswith('ldc.i4.'):
            stack.append({'ldc.i4.0':0,'ldc.i4.1':1,'ldc.i4.2':2,'ldc.i4.3':3,'ldc.i4.4':4,'ldc.i4.5':5,'ldc.i4.6':6,'ldc.i4.7':7,'ldc.i4.8':8}[nm]); i += 1; continue
        if nm in ('add', 'sub', 'xor', 'and', 'or', 'mul'):
            if len(stack) >= 2:
                b, a = stack.pop(), stack.pop()
                if isinstance(a, int) and isinstance(b, int):
                    f = {'add': lambda x,y:(x+y)&M32, 'sub': lambda x,y:(x-y)&M32, 'xor': lambda x,y:(x^y)&M32, 'and': lambda x,y:(x&y)&M32, 'or': lambda x,y:(x|y)&M32, 'mul': lambda x,y:(x*y)&M32}[nm]
                    stack.append(f(a, b))
                else:
                    stack.append(None)
            i += 1; continue
        if nm == 'fe.stloc' and opb and len(opb) == 2:
            l = struct.unpack('<H', bytes(opb))[0]
            locs[l] = stack.pop() if stack else None
            i += 1; continue
        if nm == 'fe.ldloc' and opb and len(opb) == 2:
            l = struct.unpack('<H', bytes(opb))[0]
            stack.append(locs.get(l))
            i += 1; continue
        if nm == 'dup':
            if stack: stack.append(stack[-1])
            i += 1; continue
        if nm == 'pop':
            if stack: stack.pop()
            i += 1; continue
        if nm in ('ret', 'throw', 'endfinally') or nm.startswith('leave'):
            return ('end', locs)
        if nm.startswith('ldarg') or nm in ('ldsfld', 'ldfld', 'ldstr', 'ldtoken', 'ldnull', 'newobj', 'call', 'callvirt', 'box', 'unbox.any', 'castclass', 'isinst', 'ldloca.s', 'ldloca', 'ldsflda', 'ldflda', 'ldelem.ref', 'ldelem.i1', 'ldelem.u1', 'ldelem.i2', 'ldelem.i4', 'ldelem.i8', 'ldelem.u4', 'ldlen', 'ldelem', 'ldelem.u2'):
            nargs = 0
            if nm in ('ldelem.ref','ldelem.i1','ldelem.u1','ldelem.i2','ldelem.i4','ldelem.i8','ldelem.u4','ldelem.u2','ldlen'):
                nargs = 1 if nm == 'ldlen' else 2
            elif nm in ('ldfld','ldflda','callvirt','castclass','isinst','box','unbox.any','ldstr','ldtoken','newobj'):
                nargs = {'ldfld':1,'ldflda':1,'callvirt':0,'castclass':1,'isinst':1,'box':1,'unbox.any':1,'ldstr':0,'ldtoken':0,'newobj':0}.get(nm, 0)
            for _ in range(nargs):
                if stack: stack.pop()
            stack.append(None)
            i += 1; continue
        if nm in ('conv.i4','conv.i8','conv.u4','conv.u8','conv.i','conv.u','nop'):
            i += 1; continue
        i += 1
    return ('end', locs)

writes = []
seen = set()
# initial state
init_locs = {0x1B: INIT_1B, 0x48: 0x212}
queue = [(0, init_locs)]
steps = 0
DISPATCH_OFF = 0x0012
while queue and steps < 2000000:
    off, locs = queue.pop()
    steps += 1
    key = (off, locs.get(0x1B), locs.get(0x48))
    if key in seen:
        continue
    seen.add(key)
    r = run_block(off, locs, writes, 0)
    if r[0] == 'branch':
        t, locs2 = r[1], r[2]
        if t == DISPATCH_OFF:
            # dispatch switch on loc48
            v = locs2.get(0x48)
            if isinstance(v, int) and 0 <= v < len(SW_TABLE):
                queue.append((POST + SW_TABLE[v], locs2))
            elif isinstance(v, int):
                queue.append((POST, locs2))
            else:
                print('!! dispatch with unknown loc48 at step', steps)
        else:
            queue.append((t, locs2))
    elif r[0] == 'cond':
        t, f, locs2 = r[1], r[2], r[3]
        queue.append((f, locs2))
        queue.append((t, locs2))
    # 'end' -> dead end

print('steps=%d visited=%d writes=%d' % (steps, len(seen), len(writes)))
# candidate value sets per (arr, idx)
cand = collections.defaultdict(collections.Counter)
for arr, idx, val, off, nm in writes:
    if arr >= 0 and idx is not None and val is not None:
        cand[arr][(idx, val & 0xFF)] += 1
sets_out = {}
for arr, ctr in cand.items():
    idxs = collections.defaultdict(list)
    for (idx, val), c in ctr.items():
        idxs[idx].append((val, c))
    mx = max(idxs)
    if mx < 64:
        sets_out[str(arr)] = {str(i): vals for i, vals in idxs.items()}
json.dump(sets_out, open('/workspace/repo_git/work/s5/out_419c_cand.json', 'w'))
for arr in sorted(sets_out, key=int):
    ws = sets_out[arr]
    print('arr loc%s: idx max %s, multi-valued idx: %s' % (
        arr, max(int(x) for x in ws),
        {i: len(v) for i, v in ws.items() if len(v) > 1}))
# majority arrays
for arr in ('0x20', '16', '32'):
    a = str(int(arr, 0)) if isinstance(arr, str) else arr
maj = {}
for arr, ws in sets_out.items():
    vals = []
    for i in range(max(int(x) for x in ws) + 1):
        vs = ws.get(str(i))
        if not vs:
            vals.append(None); continue
        vals.append(max(vs, key=lambda t: t[1])[0])
    maj[arr] = vals
    print('majority arr loc%s:' % arr, ' '.join('%02X' % v if v is not None else '??' for v in vals))
json.dump(maj, open('/workspace/repo_git/work/s5/out_419c_majority.json', 'w'))
print('saved out_419c_cand.json / out_419c_majority.json')
groups = collections.defaultdict(dict)
conflicts = collections.defaultdict(list)
for arr, idx, val, off, nm in writes:
    if arr >= 0 and idx is not None:
        if idx in groups[arr] and groups[arr][idx] != val:
            conflicts[arr].append((idx, groups[arr][idx], val))
        elif idx not in groups[arr]:
            groups[arr][idx] = val
for arr in sorted(groups):
    ws = groups[arr]
    mx = max(ws)
    if mx < 64:
        print('arr loc%d: idx 0..%d:' % (arr, mx))
        print('  ', [('%02X' % ws.get(i, -1)) if i in ws else '?' for i in range(mx+1)])
for arr in sorted(conflicts):
    print('arr loc%d conflicts: %d e.g. %s' % (arr, len(conflicts[arr]), conflicts[arr][:3]))
# dump full arrays for AES-sized candidates
import json
out = {str(a): {str(k): v for k, v in ws.items()} for a, ws in groups.items() if max(ws) < 64}
open('/workspace/repo_git/work/s5/out_419c_arrays.json', 'w').write(json.dumps(out))
print('saved out_419c_arrays.json')
