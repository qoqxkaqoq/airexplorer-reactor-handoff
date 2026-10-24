#!/usr/bin/env python3
# Concrete interpreter for flattened dump method bodies.
# Goal: run m_0600428A from entry to `newobj DeflateStream` and export the
# decrypted byte[] (the deflate stream feeding it).
# usage: interp.py <dumpfile> [stopTokenHex]
import struct, sys, gzip
sys.path.insert(0, '/workspace/airexplorer-reactor-handoff/work')
from flat import ONE, TWO, KSZ

M32 = 0xFFFFFFFF
M64 = (1 << 64) - 1

def parse(il):
    ins = []
    i, n = 0, len(il)
    while i < n:
        off = i
        b = il[i]
        if b == 0xFE:
            name, k = TWO[il[i+1]]; plen = 2; i += 2
        else:
            name, k = ONE[b]; plen = 1; i += 1
        if k == 'sw':
            cnt = struct.unpack_from('<i', il, i)[0]
            base = i + 4 + cnt * 4
            targets = [base + struct.unpack_from('<i', il, i + 4 + 4*t)[0] for t in range(cnt)]
            ins.append((off, name, 'sw', targets, plen)); i += 4 + cnt*4
        elif k == 'br1':
            d = struct.unpack_from('<b', il, i)[0]; ins.append((off, name, 'br1', i+1+d, plen)); i += 1
        elif k == 'br4':
            d = struct.unpack_from('<i', il, i)[0]; ins.append((off, name, 'br4', i+4+d, plen)); i += 4
        elif k == 'b':
            ins.append((off, name, 'b', struct.unpack_from('<b', il, i)[0], plen)); i += 1
        elif k == 'i':
            ins.append((off, name, 'i', struct.unpack_from('<i', il, i)[0], plen)); i += 4
        elif k == 'i8':
            ins.append((off, name, 'i8', struct.unpack_from('<q', il, i)[0], plen)); i += 8
        elif k == 'var1':
            ins.append((off, name, 'var', il[i], plen)); i += 1
        elif k == 'var2':
            ins.append((off, name, 'var', struct.unpack_from('<H', il, i)[0], plen)); i += 2
        elif k in ('tok', 'str'):
            ins.append((off, name, k, struct.unpack_from('<I', il, i)[0], plen)); i += 4
        else:
            sz = KSZ[k]
            ins.append((off, name, k, il[i:i+sz].hex() if sz else None, plen)); i += sz
    return ins

def ins_len(x):
    off, name, k, op, plen = x
    if k == 'sw': return plen + 4 + 4*len(op)
    if k == 'br1': return plen + 1
    if k == 'br4': return plen + 4
    if k == 'var': return plen * 2
    return plen + KSZ[k]

# ---- value model: (raw u64, kind)  kind in 'i4','i8','ref','nint'
def V_I4(v): return (v & M32, 'i4')
def V_I8(v): return (v & M64, 'i8')
def V_REF(o): return (o, 'ref')

def sig(v, k):
    # signed interpretation
    if k == 'i4': return v - (1 << 32) if v & 0x80000000 else v
    return v - (1 << 64) if v & (1 << 63) else v

def wide(k1, k2):
    return 'i8' if 'i8' in (k1, k2) else 'i4'

# ---- external object model
class StreamObj:
    def __init__(self, name, data):
        self.name, self.data, self.pos = name, data, 0
class BinReader:
    def __init__(self, s): self.s = s
class MemStream:
    def __init__(self, data): self.data, self.pos = data, 0
class DeflateStream:
    def __init__(self, s): self.s = s

class Stop(Exception):
    pass

# token -> builtin handler name
BUILTINS = {
    0x06004290: 'GetTypeFromHandle',
    0x06004291: 'GetResourceStream',
    0x06004292: 'RD_BaseStream',
    0x06004293: 'Stream_set_Position',
    0x06004294: 'Stream_get_Length',
    0x06004295: 'RD_ReadBytes',
    0x0600429B: 'ImplementOrderedContainer',
    0x06004264: 'RD_ctor',
    0x06004297: 'Stream_CopyTo',
    0x06004299: 'MemStream_ToArray',
    0x06004298: 'Dispose',
    0x0600429A: 'Dispose',
    0x06004296: 'CallConcreteReceiver',
    0x0600429C: 'GetResourceNames',
    0x0A00012D: 'MemStream_ctor',
    0x06004196: 'ResourceName',
    0x0A000997: 'Type_get_Assembly',
    0x0A000996: 'Type_GetTypeFromHandle',
    0x0A00019C: 'MemStream_ctor_bytes',
    0x0A000A3D: 'DeflateStream_ctor',
    0x060042A7: 'CallConcreteReceiver',
    0x04001FE8: None,  # ldsfld handled separately
}
STOP_TOKEN = None

def main():
    global STOP_TOKEN
    path = sys.argv[1]
    STOP_TOKEN = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x0A000A3D
    RES = sys.argv[3] if len(sys.argv) > 3 else '/workspace/airexplorer-reactor-handoff/work/res_ValidatorGenerator.DefinitionError.bin'
    bin = open(path, 'rb').read()
    ilSize = struct.unpack_from('<i', bin, 4)[0]
    il = bin[24:24+ilSize]
    ins = parse(il)
    byoff = {x[0]: x for x in ins}
    sw_targets = next(x[3] for x in ins if x[1] == 'switch')

    st = []            # value stack
    locals_ = [None] * 400
    heap = {}          # id -> bytearray
    nextid = [1]
    isFinalizer = [False]
    step = [0]

    def push(v, k): st.append((v & M64, k))
    def pop(): return st.pop()
    def popi(): v, k = st.pop(); return v

    def arr_new(nbytes):
        aid = nextid[0]; nextid[0] += 1
        heap[aid] = bytearray(nbytes)
        return aid
    def arr_of(ref):
        return heap[ref]

    def builtin(tok, args):
        h = BUILTINS.get(tok)
        if h is None:
            raise Stop(f'unknown call token 0x{tok:08X} args={args!r} at step {step[0]}')
        if h == 'GetTypeFromHandle' or h == 'Type_GetTypeFromHandle':
            return V_REF('TYPE')
        if h == 'Type_get_Assembly':
            return V_REF('ASM')
        if h == 'ResourceName':
            print(f'  [builtin] InstantiateTransferableProgram({sig(args[0][0], args[0][1])})')
            return V_REF('ValidatorGenerator.DefinitionError')
        if h == 'GetResourceStream':
            data = open(RES, 'rb').read()
            print(f'  [builtin] GetManifestResourceStream -> {len(data)} bytes')
            return V_REF(StreamObj('main', data))
        if h == 'MemStream_ctor':
            print('  [builtin] new MemoryStream() [output]')
            return V_REF(MemStream(b''))
        if h == 'Stream_CopyTo':
            src, dst = args[0][0], args[1][0]
            if isinstance(src, DeflateStream):
                import zlib
                if src.s.data:
                    dst.data = zlib.decompressobj(-15).decompress(src.s.data)
                    print(f'  [builtin] DeflateStream.CopyTo -> {len(dst.data)} bytes')
                else:
                    dst.data = b''
                    print('  [builtin] DeflateStream.CopyTo over EMPTY input!')
            else:
                dst.data = src.data
                print(f'  [builtin] Stream.CopyTo {len(src.data)} -> dst')
            return None
        if h == 'MemStream_ToArray':
            aid = nextid[0]; nextid[0] += 1
            heap[aid] = bytearray(args[0][0].data)
            return V_REF(aid)
        if h == 'Dispose':
            return None
        if h == 'CallConcreteReceiver':
            print(f'  [builtin] CallConcreteReceiver(array#{args[0][0]}) len={len(heap.get(args[0][0], b""))}')
            return V_REF('REFLECT_RESULT')
        if h == 'GetResourceNames':
            return V_REF('NAMES')
        if h == 'RD_ctor':
            return V_REF(BinReader(args[0][0]))
        if h == 'RD_BaseStream':
            return V_REF(args[0][0].s)
        if h == 'Stream_set_Position':
            args[0][0].pos = sig(args[1][0], args[1][1]); return None
        if h == 'Stream_get_Length':
            return V_I8(len(args[0][0].data))
        if h == 'RD_ReadBytes':
            rd = args[0][0]; n = sig(args[1][0], args[1][1])
            data = rd.s.data[rd.s.pos:rd.s.pos+n]; rd.s.pos += n
            aid = nextid[0]; nextid[0] += 1
            heap[aid] = bytearray(data)
            print(f'  [builtin] ReadBytes({n}) -> array#{aid}')
            return V_REF(aid)
        if h == 'MemStream_ctor_bytes':
            d = bytes(heap[args[0][0]])
            print(f'  [builtin] new MemoryStream(byte[{len(d)}])')
            return V_REF(MemStream(d))
        if h == 'DeflateStream_ctor':
            data = bytes(args[0][0].data)
            if data:
                raise Export('deflate-input', data)
            print('  [builtin] WARNING: DeflateStream ctor over EMPTY stream, continue')
            return V_REF(DeflateStream(args[0][0]))
        if h == 'ImplementOrderedContainer':
            return V_REF(args[0][0])
        raise Stop(f'unhandled builtin {h}')

    class Export(Exception):
        def __init__(self, tag, data):
            self.tag, self.data = tag, data

    ip = 0
    guard = 600_000_000
    import time
    t0 = time.time()
    last_rep = [0]
    def report():
        now = time.time() - t0
        if now - last_rep[0] > 5:
            last_rep[0] = now
            print(f'  [progress] step={step[0]} ip=0x{ip:X} stack={len(st)}', flush=True)
    try:
        while guard > 0:
            guard -= 1
            step[0] += 1
            if step[0] % 20000 == 0:
                report()
            x = byoff.get(ip)
            if x is None:
                raise Stop(f'bad ip 0x{ip:X}')
            off, name, k, op, plen = x
            L = ins_len(x)
            if name == 'nop':
                ip += L
            elif name == 'ldc.i4' or (name.startswith('ldc.i4.') and name != 'ldc.i4.s' and name != 'ldc.i4.m1'):
                if name == 'ldc.i4':
                    push(op & M32, 'i4')
                else:
                    m = name.split('.')[-1]
                    v = {'m1': M32, '0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8}[m]
                    push(v, 'i4')
                ip += L
            elif name == 'ldc.i4.s':
                push(op & M32, 'i4'); ip += L
            elif name == 'ldc.i8':
                push(op & M64, 'i8'); ip += L
            elif name in ('ldloc', 'ldloc.s'):
                if isinstance(locals_[op], tuple):
                    st.append(locals_[op])
                else:
                    st.append((0, 'i4'))
                ip += L
            elif name in ('stloc', 'stloc.s'):
                locals_[op] = st.pop(); ip += L
            elif name.startswith('ldloc.') and name[6:].isdigit():
                idx = int(name[6:])
                st.append(locals_[idx] if isinstance(locals_[idx], tuple) else (0, 'i4')); ip += 1
            elif name.startswith('stloc.') and name[6:].isdigit():
                locals_[int(name[6:])] = st.pop(); ip += 1
            elif name in ('ldarg', 'ldarg.s', 'ldarga', 'ldarga.s') or name.startswith('ldarg.'):
                # this=this for instance methods
                if 'a' in name: push(0, 'nint'); ip += L
                else: push(0, 'nint'); ip += 1
            elif name == 'ldnull':
                push(0, 'ref'); ip += L
            elif name == 'dup':
                st.append(st[-1]); ip += 1
            elif name == 'pop':
                st.pop(); ip += 1
            elif name in ('add', 'sub', 'mul', 'and', 'or', 'xor'):
                b = pop(); a = pop()
                kk = wide(a[1], b[1]); mw = M64 if kk == 'i8' else M32
                va, vb = a[0], b[0]
                if name == 'add': r = va + vb
                elif name == 'sub': r = va - vb
                elif name == 'mul': r = va * vb
                elif name == 'and': r = va & vb
                elif name == 'or': r = va | vb
                else: r = va ^ vb
                push(r & mw, kk); ip += 1
            elif name in ('div.un', 'rem.un', 'div', 'rem'):
                b = pop(); a = pop()
                kk = wide(a[1], b[1]); mw = M64 if kk == 'i8' else M32
                if name.endswith('.un'):
                    vb, va = b[0] or 1, a[0]
                    r = va // vb if name.startswith('div') else va % vb
                else:
                    vb, va = sig(b[0], b[1]), sig(a[0], a[1])
                    if vb == 0: raise Stop('div by 0')
                    r = int(va / vb) if name.startswith('div') else va - int(va / vb) * vb
                push(r & mw, kk); ip += 1
            elif name == 'shl':
                b = pop(); a = pop()
                kk = a[1]; mw = M64 if kk == 'i8' else M32
                sh = b[0] & (63 if kk == 'i8' else 31)
                push((a[0] << sh) & mw, kk); ip += 1
            elif name in ('shr', 'shr.un'):
                b = pop(); a = pop()
                kk = a[1]; mw = M64 if kk == 'i8' else M32
                sh = b[0] & (63 if kk == 'i8' else 31)
                if name == 'shr.un' or kk == 'i8':
                    push((a[0] & mw) >> sh, kk)
                else:
                    push((sig(a[0], 'i4') >> sh) & M32, kk)
                ip += 1
            elif name == 'neg':
                a = pop(); mw = M64 if a[1] == 'i8' else M32
                push((-a[0]) & mw, a[1]); ip += 1
            elif name == 'not':
                a = pop(); mw = M64 if a[1] == 'i8' else M32
                push(a[0] ^ mw, a[1]); ip += 1
            elif name.startswith('conv.'):
                a = pop()
                c = name[5:]
                if c in ('i8', 'u8'):
                    kk = 'i8'
                    v = a[0] if a[1] == 'i8' or c == 'u8' else (sig(a[0], a[1]) & M64 if c == 'i8' else a[0])
                    push(v & M64, kk)
                elif c in ('i4', 'u4'):
                    push(a[0] & M32, 'i4')
                elif c in ('i', 'u', 'r.un', 'r4', 'r8', 'i1', 'u1', 'i2', 'u2', 'ovf.i8.un', 'ovf.i.un', 'ovf.u.un', 'ovf.i4.un', 'ovf.u4.un', 'ovf.i8', 'ovf.i', 'ovf.u', 'ovf.i4', 'ovf.u4', 'ovf.i1', 'ovf.u1', 'ovf.i2', 'ovf.u2', 'ovf.i1.un', 'ovf.u1.un', 'ovf.i2.un', 'ovf.u2.un', 'ovf.i8.un'):
                    if a[1] == 'ref':
                        push(a[0], 'nint')
                    elif c in ('i1', 'u1', 'i2', 'u2'):
                        bits = 8 if c.endswith('1') else 16
                        if c.startswith('i'):
                            sv = sig(a[0] & ((1 << bits) - 1), 'i4' if bits == 32 else 'i4')
                            push(sv & M32, 'i4')
                        else:
                            push(a[0] & ((1 << bits) - 1), 'i4')
                    else:
                        push(a[0], 'i8' if a[1] == 'i8' else 'i4')
                ip += L
            elif name in ('ldtoken',):
                push(op, 'i4'); ip += L
            elif name == 'ldstr':
                push(op, 'ref'); ip += L
            elif name in ('ldsfld', 'ldsflda'):
                if op == 0x04001FE8:
                    push(1 if isFinalizer[0] else 0, 'i4')
                elif op == 0x040020B8:
                    push(hash('MODOBJ') & M64, 'ref')
                else:
                    raise Stop(f'ldsfld 0x{op:08X}')
                ip += L
            elif name == 'stsfld':
                if op == 0x04001FE8:
                    isFinalizer[0] = bool(popi() & 1)
                elif op in (0x04001FE7, 0x04001FE6, 0x04001FCD):
                    st.pop()
                else:
                    raise Stop(f'stsfld 0x{op:08X}')
                ip += L
            elif name in ('ldfld', 'ldflda'):
                if op in (0x04002091, 0x04002093):
                    st.pop()  # module obj
                    push(0, 'i4')
                    ip += L
                else:
                    raise Stop(f'ldfld 0x{op:08X}')
            elif name == 'stfld':
                st.pop(); st.pop(); ip += L
            elif name == 'newarr':
                cnt = popi()
                elem = op
                sz = 1 if op == 0x0100005B else 4
                aid = arr_new(cnt * sz)
                push(aid, 'ref'); ip += L
            elif name == 'ldlen':
                a = pop()
                push(len(heap[a[0]]), 'i4'); ip += 1
            elif name == 'ldelem.u1':
                idx = popi(); aref = pop()
                push(heap[aref[0]][idx], 'i4'); ip += 1
            elif name == 'ldelem.i1':
                idx = popi(); aref = pop()
                v = heap[aref[0]][idx]
                push(v - 256 if v > 127 else v, 'i4'); ip += 1
            elif name == 'ldelem.u2':
                idx = popi(); aref = pop()
                push(struct.unpack_from('<H', heap[aref[0]], idx)[0], 'i4'); ip += 1
            elif name == 'ldelem.i4' or name == 'ldelem.u4':
                idx = popi(); aref = pop()
                push(struct.unpack_from('<I', heap[aref[0]], idx)[0], 'i4'); ip += 1
            elif name == 'stelem.i1':
                v = popi(); idx = popi(); aref = pop()
                heap[aref[0]][idx] = v & 0xFF; ip += 1
            elif name == 'stelem.i2':
                v = popi(); idx = popi(); aref = pop()
                struct.pack_into('<H', heap[aref[0]], idx, v & 0xFFFF); ip += 1
            elif name == 'stelem.i4':
                v = popi(); idx = popi(); aref = pop()
                struct.pack_into('<I', heap[aref[0]], idx, v & M32); ip += 1
            elif name == 'ldelem.ref':
                idx = popi(); aref = pop()
                raise Stop('ldelem.ref')
            elif name == 'stelem.ref':
                v = pop(); idx = popi(); aref = pop()
                raise Stop('stelem.ref')
            elif name == 'switch':
                idx = popi()
                tgt = op[idx] if 0 <= idx < len(op) else ip + L
                ip = tgt
            elif k == 'br1' or k == 'br4':
                un = name.endswith('.un')
                if name in ('br', 'br.s'):
                    ip = op
                elif name in ('brtrue', 'brtrue.s'):
                    v = pop()
                    ip = op if (v[0] != 0) else ip + L
                elif name in ('brfalse', 'brfalse.s'):
                    v = pop()
                    ip = op if (v[0] == 0) else ip + L
                else:
                    b = pop(); a = pop()
                    kk = wide(a[1], b[1])
                    if un or kk == 'i8':
                        av, bv = a[0], b[0]
                        if a[1] == 'i4' and kk == 'i8': av = sig(a[0], 'i4') & M64
                        if b[1] == 'i4' and kk == 'i8': bv = sig(b[0], 'i4') & M64
                    else:
                        av, bv = sig(a[0], 'i4'), sig(b[0], 'i4')
                    cmpv = {
                        'beq': av == bv, 'bne.un': av != bv,
                        'bgt': av > bv, 'bgt.un': av > bv,
                        'bge': av >= bv, 'bge.un': av >= bv,
                        'blt': av < bv, 'blt.un': av < bv,
                        'ble': av <= bv, 'ble.un': av <= bv,
                    }[name.rstrip('.s')]
                    ip = op if cmpv else ip + L
            elif name in ('call', 'callvirt'):
                args = []
                ip += L
                tgt = op
                # consume args by target signature knowledge (kept per-builtin)
                # pop all args pushed for this call: we rely on builtins' known arity
                ARITY = {
                    0x06004290: 1, 0x06004291: 2, 0x06004292: 1, 0x06004293: 2,
                    0x06004294: 1, 0x06004295: 2, 0x0600429B: 2, 0x06004196: 1,
                    0x0A000997: 1, 0x0A000996: 1,
                    0x06004296: 1, 0x0600429C: 1, 0x060042A7: 1,
                    0x06004297: 2, 0x06004299: 1, 0x06004298: 1, 0x0600429A: 1,
                }
                ar = ARITY.get(tgt)
                if ar is None:
                    raise Stop(f'call unknown token 0x{tgt:08X}')
                args = [st.pop() for _ in range(ar)][::-1]
                r = builtin(tgt, args)
                if r is not None:
                    st.append(r)
            elif name == 'newobj':
                ip += L
                AR = {0x0A00019C: 1, 0x0A000A3D: 2, 0x06004264: 1, 0x0A000905: 1,
                      0x0A00012D: 0}
                ar = AR.get(op)
                if ar is None:
                    raise Stop(f'newobj unknown token 0x{op:08X}')
                args = [st.pop() for _ in range(ar)][::-1]
                r = builtin(op, args)
                if r is not None:
                    st.append(r)
            elif name == 'ret':
                raise Stop('ret reached')
            elif name in ('leave', 'leave.s'):
                ip = op
            elif name in ('endfinally', 'endfilter'):
                raise Stop(f'{name}')
            elif name == 'throw':
                raise Stop('throw')
            else:
                raise Stop(f'unimplemented opcode {name}')
    except Export as e:
        out = f'/tmp/mainlib_{e.tag}.bin'
        open(out, 'wb').write(e.data)
        print(f'EXPORTED {e.tag}: {len(e.data)} bytes -> {out}')
        print('head:', e.data[:64].hex())
        try:
            import zlib
            d = zlib.decompressobj(-15)
            plain = d.decompress(e.data)
            po = f'/tmp/mainlib_plain.bin'
            open(po, 'wb').write(plain)
            print(f'INFLATED: {len(plain)} bytes -> {po}')
            print('plain head:', plain[:96].hex())
        except Exception as ex:
            print('inflate failed:', ex)
        return
    except Stop as e:
        print(f'STOP: {e}')
        print(f'ip=0x{ip:X} step={step[0]} stack={st[-6:]}')
        return
    print('guard exhausted')

if __name__ == '__main__':
    main()
