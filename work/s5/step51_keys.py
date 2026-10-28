# -*- coding: utf-8 -*-
"""step51: DFS-walk 0600419C flattened IL, collect stelem.i1 writes (array, idx, value)
to recover AES key/IV arrays built from obfuscated constants."""
import struct, sys, zipfile, collections
sys.path.insert(0, '/workspace/repo_git/work/s5')
import cildasm

DUMP = '/workspace/repo_git/work/dump_official_16598.zip'
z = zipfile.ZipFile(DUMP)
d = z.read('m_0600419C.bin')
ilsz = struct.unpack('<I', d[4:8])[0]
il = d[24:24+ilsz]
ins = cildasm.disasm(il)
by_off = {o: i for i, (o, nm, opb, nxt, tg) in enumerate(ins)}
N = len(ins)

def sim(stack_state_start=0):
    """DFS over branch edges; at each step maintain stack of simple values.
    Returns writes: list of (path_id, arr_loc, idx, val) and stloc const map."""
    writes = []
    seen_edges = set()
    paths = []  # completed paths
    # stack items: ('c', value) constant or ('v', loc) variable or ('?',) unknown
    def step(idx, stack, locs, path, depth):
        if depth > 6000 or len(paths) > 400:
            return
        if idx >= N:
            return
        o, nm, opb, nxt, tg = ins[idx]
        if nm in ('br', 'br.s'):
            t = by_off.get(o + 5 + struct.unpack('<i', bytes(opb))[0])
            if t is not None and (idx, t) not in seen_edges:
                seen_edges.add((idx, t))
                step(t, stack[:], dict(locs), path + [idx], depth + 1)
            return
        if nm in ('brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'beq', 'beq.s', 'bne.un', 'bne.un.s', 'blt', 'bge', 'ble', 'bgt', 'blt.un', 'bge.un', 'ble.un', 'bgt.un', 'blt.s', 'bge.s', 'ble.s', 'bgt.s', 'bne.un.s', 'beq.s', 'blt.un.s', 'bge.un.s', 'ble.un.s', 'bgt.un.s'):
            # stack: [v, target] -> pop both
            s2 = stack[:-2] if len(stack) >= 2 else []
            # target offset
            t = None
            if opb and len(opb) == 4 and nm in ('brtrue', 'brfalse', 'bne.un', 'beq', 'bge', 'ble', 'bgt', 'blt'):
                t = by_off.get(o + 5 + struct.unpack('<i', bytes(opb))[0])
            elif opb and len(opb) == 1:
                t = by_off.get(o + 2 + struct.unpack('<b', bytes(opb))[0])
            # explore both fallthrough and target
            if t is not None and (idx, t) not in seen_edges:
                seen_edges.add((idx, t))
                step(t, s2[:], dict(locs), path + [idx], depth + 1)
            step(idx + 1, s2[:], dict(locs), path + [idx], depth + 1)
            return
        if nm == 'stelem.i1' or nm == 'stelem.i4' or nm == 'stelem.ref' or nm == 'stelem.i8':
            if len(stack) >= 3:
                arr, i, v = stack[-3], stack[-2], stack[-1]
                ai = arr[1] if arr[0] == 'v' else -1
                iv = i[1] if i[0] == 'c' else None
                vv = v[1] if v[0] == 'c' else None
                writes.append((len(paths), ai, iv, vv, o, nm))
                stack = stack[:-3]
            step(idx + 1, stack, locs, path, depth + 1)
            return
        if nm.startswith('ldc.i4'):
            if nm == 'ldc.i4.m1':
                stack.append(('c', -1))
            elif opb:
                if len(opb) == 1:
                    stack.append(('c', opb[0] if nm != 'ldc.i4.s' else struct.unpack('<b', bytes(opb))[0]))
                elif len(opb) == 4:
                    stack.append(('c', struct.unpack('<i', bytes(opb))[0]))
                else:
                    stack.append(('?',))
            else:
                stack.append(('c', {'ldc.i4.0': 0, 'ldc.i4.1': 1, 'ldc.i4.2': 2, 'ldc.i4.3': 3, 'ldc.i4.4': 4, 'ldc.i4.5': 5, 'ldc.i4.6': 6, 'ldc.i4.7': 7, 'ldc.i4.8': 8}.get(nm, 0)))
            step(idx + 1, stack, locs, path, depth + 1)
            return
        if nm in ('add', 'sub', 'xor', 'and', 'or', 'mul'):
            if len(stack) >= 2:
                b, a = stack[-1], stack[-2]
                stack = stack[:-2]
                if a[0] == 'c' and b[0] == 'c':
                    f = {'add': lambda x, y: x + y, 'sub': lambda x, y: x - y, 'xor': lambda x, y: x ^ y, 'and': lambda x, y: x & y, 'or': lambda x, y: x | y, 'mul': lambda x, y: x * y}[nm]
                    stack.append(('c', f(a[1], b[1]) & 0xFFFFFFFF))
                else:
                    stack.append(('?',))
            step(idx + 1, stack, locs, path, depth + 1)
            return
        if nm == 'fe.stloc' or nm == 'stloc' or nm.startswith('stloc'):
            if stack:
                v = stack[-1]
                stack = stack[:-1]
                if opb and len(opb) == 2 and nm == 'fe.stloc':
                    locs[struct.unpack('<H', bytes(opb))[0]] = v
                elif opb and len(opb) == 1:
                    locs[opb[0]] = v
                else:
                    locs[{'stloc.0': 0, 'stloc.1': 1, 'stloc.2': 2, 'stloc.3': 3}.get(nm, 0)] = v
            step(idx + 1, stack, locs, path, depth + 1)
            return
        if nm == 'fe.ldloc' or nm == 'ldloc' or nm.startswith('ldloc'):
            if opb and len(opb) == 2 and nm == 'fe.ldloc':
                l = struct.unpack('<H', bytes(opb))[0]
            elif opb and len(opb) == 1:
                l = opb[0]
            else:
                l = {'ldloc.0': 0, 'ldloc.1': 1, 'ldloc.2': 2, 'ldloc.3': 3}.get(nm, 0)
            stack.append(locs.get(l, ('v', l)))
            step(idx + 1, stack, locs, path, depth + 1)
            return
        if nm in ('dup',):
            if stack: stack.append(stack[-1])
            step(idx + 1, stack, locs, path, depth + 1)
            return
        if nm in ('pop',):
            if stack: stack.pop()
            step(idx + 1, stack, locs, path, depth + 1)
            return
        # calls / newobj / ldelem / ret / leave / throw / nop etc. — clobber stack heuristically
        if nm in ('call', 'callvirt', 'newobj'):
            stack.append(('?',))
            step(idx + 1, stack, locs, path, depth + 1)
            return
        if nm.startswith('leave') or nm == 'ret' or nm == 'throw' or nm == 'endfinally':
            paths.append((path, dict(locs)))
            return
        if nm.startswith('ldarg') or nm in ('nop', 'ldlen', 'conv.i4', 'conv.i8', 'conv.u8', 'conv.u4', 'conv.i', 'conv.u', 'ldnull', 'ldc.i4.s', 'ldtoken', 'box', 'unbox.any', 'castclass', 'isinst', 'ldelem.ref', 'ldelem.i1', 'ldelem.u1', 'ldelem.i4', 'ldelem.i8'):
            if nm in ('ldnull',):
                stack.append(('?',))
            elif nm in ('ldlen',):
                if stack: stack.pop()
                stack.append(('?',))
            elif nm in ('conv.i4', 'conv.i8', 'conv.u8', 'conv.u4', 'conv.i', 'conv.u'):
                if stack and stack[-1][0] == 'c':
                    stack[-1] = ('c', stack[-1][1] & 0xFFFFFFFF)
            elif nm.startswith('ldarg'):
                stack.append(('?',))
            elif nm in ('box', 'unbox.any', 'castclass', 'isinst', 'ldtoken', 'ldelem.ref', 'ldelem.i1', 'ldelem.u1', 'ldelem.i4', 'ldelem.i8'):
                if nm in ('ldelem.ref', 'ldelem.i1', 'ldelem.u1', 'ldelem.i4', 'ldelem.i8'):
                    if len(stack) >= 2: stack = stack[:-2]
                stack.append(('?',))
            step(idx + 1, stack, locs, path, depth + 1)
            return
        # unknown opcodes: just continue
        step(idx + 1, stack, locs, path, depth + 1)

    step(0, [], {}, [], 0)
    return writes, paths

writes, paths = sim()
print('paths completed: %d, writes: %d' % (len(paths), len(writes)))
# group writes by array local
groups = collections.defaultdict(list)
for p, arr, idx, val, off, nm in writes:
    if arr >= 0 and idx is not None and val is not None:
        groups[arr].append((idx, val & 0xFF, off))
for arr in sorted(groups):
    ws = groups[arr]
    idxs = sorted(set(w[0] for w in ws))
    conflict = len(ws) != len(idxs)
    print('arr loc%d: %d writes, idx range %s, conflict=%s' % (arr, len(ws), ('%d..%d' % (min(idxs), max(idxs))) if idxs else '-', conflict))
    if arr in (0x04, 0x21, 0x2d) or (idxs and max(idxs) < 40):
        vals = {}
        for i, v, off in ws:
            vals.setdefault(i, set()).add(v)
        print('   vals:', {i: sorted(s) for i, s in sorted(vals.items())[:40]})
