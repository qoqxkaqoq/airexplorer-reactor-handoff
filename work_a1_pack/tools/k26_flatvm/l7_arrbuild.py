#!/usr/bin/env python3
# l7_arrbuild.py — reconstruct byte arrays built via obfuscated stelem.i1 in plaintext IL
# Stack-simulate constant propagation; record (method, arrloc, index, value) stores.
import sys, struct, json
sys.path.insert(0, r'airexplorer-reactor-handoff/work'); sys.path.insert(0, r'work_a1')
import flat, mref

EXE = r'airexplorer-reactor-handoff/exes/AirExplorer_baseline_verified.exe'
refs, meths, FS, rows, streams, si, bi = mref.load(EXE)
d = open(EXE, 'rb').read()
pe = struct.unpack_from('<I', d, 0x3C)[0]; nsec = struct.unpack_from('<H', d, pe+6)[0]; optsz = struct.unpack_from('<H', d, pe+20)[0]
def rva2off(rva):
    for i in range(nsec):
        o = pe+24+optsz+i*40
        vsz, va, rsz, raw = struct.unpack_from('<4I', d, o+8)
        if va <= rva < va+max(vsz, rsz): return raw+(rva-va)

CONST_OPS = {'ldc.i4', 'ldc.i4.s'}
BIN_OPS = {'add': lambda a, b: (a + b) & 0xFFFFFFFF, 'sub': lambda a, b: (a - b) & 0xFFFFFFFF,
           'xor': lambda a, b: a ^ b, 'and': lambda a, b: a & b, 'or': lambda a, b: a | b,
           'mul': lambda a, b: (a * b) & 0xFFFFFFFF}

def method_il(tok):
    rva, name = meths[tok]
    fo = rva2off(rva)
    b0 = d[fo]
    if b0 & 3 == 2:
        return d[fo+1:fo+1+(b0>>2)]
    hsz = (d[fo+1] >> 4) * 4
    csz = struct.unpack_from('<I', d, fo+4)[0]
    return d[fo+hsz:fo+hsz+csz]

def simulate(il):
    """returns list of (arrdesc, index, value) for stelem.i1 with fully-static operands,
       plus partial info for dynamic ones"""
    stores = []
    try:
        ins = list(flat.parse(il))
    except Exception:
        return stores
    stack = []  # values: int constants or None(unknown)
    for off, nm, k, op, plen in ins:
        if nm in ('ldc.i4', 'ldc.i4.s'):
            stack.append(op & 0xFFFFFFFF)
        elif nm == 'ldc.i4.m1':
            stack.append(0xFFFFFFFF)
        elif nm in ('ldloc', 'ldloc.s', 'ldloc.0', 'ldloc.1', 'ldloc.2', 'ldloc.3',
                    'ldarg', 'ldarg.s', 'ldarg.0', 'ldarg.1', 'ldarg.2', 'ldarg.3'):
            stack.append(('v', nm, op))
        elif nm in ('ldsfld',):
            stack.append(('f', op))
        elif nm == 'dup':
            if stack: stack.append(stack[-1])
        elif nm == 'pop':
            if stack: stack.pop()
        elif nm in BIN_OPS:
            if len(stack) >= 2:
                b = stack.pop(); a = stack.pop()
                if isinstance(a, int) and isinstance(b, int):
                    stack.append(BIN_OPS[nm](a, b))
                else:
                    stack.append(None)
            else:
                stack.append(None)
        elif nm == 'not':
            if stack:
                a = stack.pop()
                stack.append((~a) & 0xFFFFFFFF if isinstance(a, int) else None)
        elif nm == 'neg':
            if stack:
                a = stack.pop()
                stack.append((-a) & 0xFFFFFFFF if isinstance(a, int) else None)
        elif nm == 'stelem.i1':
            if len(stack) >= 3:
                v = stack.pop(); idx = stack.pop(); arr = stack.pop()
                # arr: ('v', ldloc, localnum) etc.
                if isinstance(v, int) and isinstance(idx, int) and arr is not None and isinstance(arr, tuple):
                    stores.append((arr, idx, v & 0xFF, off))
        elif nm == 'stelem.i':
            if len(stack) >= 3:
                v = stack.pop(); idx = stack.pop(); arr = stack.pop()
                if isinstance(v, int) and isinstance(idx, int) and arr is not None and isinstance(arr, tuple):
                    stores.append((arr, idx, v & 0xFFFFFFFF, off))
        elif nm.startswith('stelem'):
            if len(stack) >= 3:
                stack.pop(); stack.pop(); stack.pop()
        elif nm in ('stloc', 'stloc.s', 'stloc.0', 'stloc.1', 'stloc.2', 'stloc.3',
                    'stsfld', 'starg', 'starg.s', 'call', 'callvirt', 'newobj', 'ret', 'throw', 'leave', 'leave.s', 'endfinally', 'rethrow'):
            ncons = 1
            if nm in ('stloc', 'stloc.s') or nm.startswith('stloc.'):
                ncons = 1
            elif nm == 'stsfld':
                ncons = 1
            elif nm == 'starg' or nm == 'starg.s':
                ncons = 1
            elif nm in ('ret', 'throw', 'endfinally', 'rethrow'):
                ncons = 0
            elif nm in ('leave', 'leave.s'):
                ncons = 0
            elif nm in ('call', 'callvirt', 'newobj'):
                ncons = 0  # unknown consumption; flush stack to be safe? keep simple: flush
                stack = []
            for _ in range(ncons):
                if stack: stack.pop()
        elif nm in ('br', 'br.s', 'brtrue', 'brtrue.s', 'brfalse', 'brfalse.s', 'beq', 'beq.s',
                    'bne.un', 'bne.un.s', 'bge', 'bge.s', 'bgt', 'bgt.s', 'ble', 'ble.s', 'blt', 'blt.s',
                    'bge.un', 'bge.un.s', 'bgt.un', 'bgt.un.s', 'ble.un', 'ble.un.s', 'blt.un', 'blt.un.s'):
            if nm.startswith('br'):
                pass  # no pop
            else:
                if stack: stack.pop()
            # control flow joins make static sim invalid; keep going (flattened code: acceptable noise)
        elif nm == 'switch':
            if stack: stack.pop()
        elif nm.startswith('ldelem'):
            if len(stack) >= 2:
                stack.pop(); stack.pop(); stack.append(('elem',))
        elif nm in ('ldlen',):
            if stack: stack.pop(); stack.append(('len',))
        elif nm in ('newarr',):
            if stack: stack.pop(); stack.append(('newarr', off))
        elif nm in ('add', 'sub') and False:
            pass
        else:
            # unknown/unhandled: conservatively clear (avoid bogus pairings)
            if nm.startswith('conv'):
                pass  # conversions preserve value
            else:
                stack = []
    return stores

if __name__ == '__main__':
    # target methods: all plaintext methods with IL >= 40 bytes
    targets = []
    for tok, (rva, name) in meths.items():
        try:
            il = method_il(tok)
        except Exception:
            continue
        if len(il) >= 40:
            targets.append((tok, name, il))
    print('methods scanned:', len(targets))
    allstores = {}
    for tok, name, il in targets:
        st = simulate(il)
        if st:
            allstores[tok] = (name, st)
    total = sum(len(v[1]) for v in allstores.values())
    print('methods with static stelem stores:', len(allstores), 'total stores:', total)
    json.dump({hex(t): [v[0], [[a[0][1], a[0][2] if len(a[0]) > 2 else -1, a[1], a[2]] for a in v[1]]]
               for t, v in allstores.items()}, open('work_a1/k26/arrstores.json', 'w'))
    # quick: rebuild arrays per (method, arrloc) and look for 32B candidates
    def arrkey(a):
        return (a[0][1], a[0][2] if len(a[0]) > 2 else -1)
    cands = []
    for tok, (name, st) in allstores.items():
        groups = {}
        for arr, idx, val, off in st:
            groups.setdefault(arrkey(arr), {})[idx] = val
        for ak, m in groups.items():
            idxs = sorted(m)
            if not idxs: continue
            # contiguous run detection
            runs = []
            cur = [idxs[0]]
            for x in idxs[1:]:
                if x == cur[-1] + 1: cur.append(x)
                else: runs.append(cur); cur = [x]
            runs.append(cur)
            for r in runs:
                if len(r) >= 16:
                    data = bytes(m[i] for i in r)
                    cands.append((tok, name, ak, r[0], len(r), data))
    print('reconstructed arrays >=16B:', len(cands))
    import binascii
    KV = binascii.unhexlify('f59997908a8bf27e5dfba62181d9f423762aa08505365dafe4274cfbdd503943')
    KM = binascii.unhexlify('cbf9094942db0b2e7a8a37224c70a1531686854305bb96ac54ab6d0dc30ef481')
    KF = binascii.unhexlify('37038b1c606ca165c7f772c0e2a6ff545e4a9d0ea55139779f7ecb7404fa9a3a')
    hits = 0
    for tok, name, ak, start, ln, data in cands:
        for kn, K in (('Viewer', KV), ('mainlib', KM), ('Factory', KF)):
            for off in range(0, max(1, ln - 31)):
                if data[off:off+32] == K:
                    print('*** KEY %s found in 0x%08X %s arr=%s start=%d' % (kn, tok, name, ak, start + off))
                    hits += 1
    print('known-key hits:', hits)
