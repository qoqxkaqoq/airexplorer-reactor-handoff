#!/usr/bin/env python3
# Control-flow-flattening linearizer for dump method bodies (pure python).
# usage: flat.py <dumpfile> [stateVar] [switchVar]
import struct, sys, gzip

# opcode tables: byte -> (name, operand_kind)
# kinds: n,b,i,i8,r4,r8,br1,br4,sw,str,tok,var1,var2
ONE, TWO = {}, {}
_single = [
    (0x00,'nop','n'),(0x01,'break','n'),(0x02,'ldarg.0','n'),(0x03,'ldarg.1','n'),(0x04,'ldarg.2','n'),(0x05,'ldarg.3','n'),
    (0x06,'ldloc.0','n'),(0x07,'ldloc.1','n'),(0x08,'ldloc.2','n'),(0x09,'ldloc.3','n'),
    (0x0A,'stloc.0','n'),(0x0B,'stloc.1','n'),(0x0C,'stloc.2','n'),(0x0D,'stloc.3','n'),
    (0x0E,'ldarg.s','var1'),(0x0F,'ldarga.s','var1'),(0x10,'starg.s','var1'),(0x11,'ldloc.s','var1'),(0x12,'ldloca.s','var1'),(0x13,'stloc.s','var1'),
    (0x14,'ldnull','n'),(0x15,'ldc.i4.m1','n'),(0x16,'ldc.i4.0','n'),(0x17,'ldc.i4.1','n'),(0x18,'ldc.i4.2','n'),(0x19,'ldc.i4.3','n'),
    (0x1A,'ldc.i4.4','n'),(0x1B,'ldc.i4.5','n'),(0x1C,'ldc.i4.6','n'),(0x1D,'ldc.i4.7','n'),(0x1E,'ldc.i4.8','n'),
    (0x1F,'ldc.i4.s','b'),(0x20,'ldc.i4','i'),(0x21,'ldc.i8','i8'),(0x22,'ldc.r4','r4'),(0x23,'ldc.r8','r8'),
    (0x25,'dup','n'),(0x26,'pop','n'),(0x27,'jmp','tok'),(0x28,'call','tok'),(0x29,'calli','tok'),(0x2A,'ret','n'),
    (0x2B,'br.s','br1'),(0x2C,'brfalse.s','br1'),(0x2D,'brtrue.s','br1'),(0x2E,'beq.s','br1'),(0x2F,'bge.s','br1'),
    (0x30,'bgt.s','br1'),(0x31,'ble.s','br1'),(0x32,'blt.s','br1'),(0x33,'bne.un.s','br1'),(0x34,'bge.un.s','br1'),
    (0x35,'bgt.un.s','br1'),(0x36,'ble.un.s','br1'),(0x37,'blt.un.s','br1'),
    (0x38,'br','br4'),(0x39,'brfalse','br4'),(0x3A,'brtrue','br4'),(0x3B,'beq','br4'),(0x3C,'bge','br4'),
    (0x3D,'bgt','br4'),(0x3E,'ble','br4'),(0x3F,'blt','br4'),(0x40,'bne.un','br4'),(0x41,'bge.un','br4'),
    (0x42,'bgt.un','br4'),(0x43,'ble.un','br4'),(0x44,'blt.un','br4'),(0x45,'switch','sw'),
    (0x46,'ldind.i1','n'),(0x47,'ldind.u1','n'),(0x48,'ldind.i2','n'),(0x49,'ldind.u2','n'),(0x4A,'ldind.i4','n'),(0x4B,'ldind.u4','n'),
    (0x4C,'ldind.i8','n'),(0x4D,'ldind.i','n'),(0x4E,'ldind.r4','n'),(0x4F,'ldind.r8','n'),(0x50,'ldind.ref','n'),
    (0x51,'stind.ref','n'),(0x52,'stind.i1','n'),(0x53,'stind.i2','n'),(0x54,'stind.i4','n'),(0x55,'stind.i8','n'),
    (0x56,'stind.r4','n'),(0x57,'stind.r8','n'),
    (0x58,'add','n'),(0x59,'sub','n'),(0x5A,'mul','n'),(0x5B,'div','n'),(0x5C,'div.un','n'),(0x5D,'rem','n'),(0x5E,'rem.un','n'),
    (0x5F,'and','n'),(0x60,'or','n'),(0x61,'xor','n'),(0x62,'shl','n'),(0x63,'shr','n'),(0x64,'shr.un','n'),(0x65,'neg','n'),(0x66,'not','n'),
    (0x67,'conv.i1','n'),(0x68,'conv.i2','n'),(0x69,'conv.i4','n'),(0x6A,'conv.i8','n'),(0x6B,'conv.r4','n'),(0x6C,'conv.r8','n'),
    (0x6D,'conv.u4','n'),(0x6E,'conv.u8','n'),(0x6F,'callvirt','tok'),(0x70,'cpobj','tok'),(0x71,'ldobj','tok'),(0x72,'ldstr','str'),
    (0x73,'newobj','tok'),(0x74,'castclass','tok'),(0x75,'isinst','tok'),(0x76,'conv.r.un','n'),(0x79,'unbox','tok'),(0x7A,'throw','n'),
    (0x7B,'ldfld','tok'),(0x7C,'ldflda','tok'),(0x7D,'stfld','tok'),(0x7E,'ldsfld','tok'),(0x7F,'ldsflda','tok'),(0x80,'stsfld','tok'),(0x81,'stobj','tok'),
    (0x82,'conv.ovf.i1.un','n'),(0x83,'conv.ovf.i2.un','n'),(0x84,'conv.ovf.i4.un','n'),(0x85,'conv.ovf.i8.un','n'),
    (0x86,'conv.ovf.u1.un','n'),(0x87,'conv.ovf.u2.un','n'),(0x88,'conv.ovf.u4.un','n'),(0x89,'conv.ovf.u8.un','n'),
    (0x8A,'conv.ovf.i.un','n'),(0x8B,'conv.ovf.u.un','n'),(0x8C,'box','tok'),(0x8D,'newarr','tok'),(0x8E,'ldlen','n'),(0x8F,'ldelema','tok'),
    (0x90,'ldelem.i1','n'),(0x91,'ldelem.u1','n'),(0x92,'ldelem.i2','n'),(0x93,'ldelem.u2','n'),(0x94,'ldelem.i4','n'),(0x95,'ldelem.u4','n'),
    (0x96,'ldelem.i8','n'),(0x97,'ldelem.i','n'),(0x98,'ldelem.r4','n'),(0x99,'ldelem.r8','n'),(0x9A,'ldelem.ref','n'),
    (0x9B,'stelem.i','n'),(0x9C,'stelem.i1','n'),(0x9D,'stelem.i2','n'),(0x9E,'stelem.i4','n'),(0x9F,'stelem.i8','n'),
    (0xA0,'stelem.r4','n'),(0xA1,'stelem.r8','n'),(0xA2,'stelem.ref','n'),(0xA3,'ldelem','tok'),(0xA4,'stelem','tok'),(0xA5,'unbox.any','tok'),
    (0xB3,'conv.ovf.i1','n'),(0xB4,'conv.ovf.u1','n'),(0xB5,'conv.ovf.i2','n'),(0xB6,'conv.ovf.u2','n'),
    (0xB7,'conv.ovf.i4','n'),(0xB8,'conv.ovf.u4','n'),(0xB9,'conv.ovf.i8','n'),(0xBA,'conv.ovf.u8','n'),
    (0xC2,'refanyval','tok'),(0xC3,'ckfinite','n'),(0xC6,'mkrefany','tok'),(0xD0,'ldtoken','tok'),
    (0xD1,'conv.u2','n'),(0xD2,'conv.u1','n'),(0xD3,'conv.i','n'),(0xD4,'conv.ovf.i','n'),(0xD5,'conv.ovf.u','n'),
    (0xD6,'add.ovf','n'),(0xD7,'add.ovf.un','n'),(0xD8,'mul.ovf','n'),(0xD9,'mul.ovf.un','n'),(0xDA,'sub.ovf','n'),(0xDB,'sub.ovf.un','n'),
    (0xDC,'endfinally','n'),(0xDD,'leave','br4'),(0xDE,'leave.s','br1'),(0xDF,'stind.i','n'),(0xE0,'conv.u','n'),
]
for op, name, k in _single: ONE[op] = (name, k)
_two = [
    (0x00,'arglist','n'),(0x01,'ceq','n'),(0x02,'cgt','n'),(0x03,'cgt.un','n'),(0x04,'clt','n'),(0x05,'clt.un','n'),
    (0x06,'ldftn','tok'),(0x07,'ldvirtftn','tok'),(0x09,'ldarg','var2'),(0x0A,'ldarga','var2'),(0x0B,'starg','var2'),
    (0x0C,'ldloc','var2'),(0x0D,'ldloca','var2'),(0x0E,'stloc','var2'),(0x0F,'localloc','n'),(0x11,'endfilter','n'),
    (0x12,'unaligned.','var1'),(0x13,'volatile.','n'),(0x14,'tail.','n'),(0x15,'initobj','tok'),(0x16,'constrained.','tok'),
    (0x17,'cpblk','n'),(0x18,'initblk','n'),(0x1A,'rethrow','n'),(0x1C,'sizeof','tok'),(0x1D,'refanytype','n'),(0x1E,'readonly.','n'),
]
for op, name, k in _two: TWO[op] = (name, k)

KSZ = {'n':0,'b':1,'i':4,'i8':8,'r4':4,'r8':8,'var1':1,'var2':2,'str':4,'tok':4}

# token name map (optional annotation)
TOKMAP = {}
try:
    with gzip.open('/workspace/airexplorer-reactor-handoff/work/tokmap_official.tsv.gz', 'rt') as f:
        for line in f:
            p = line.rstrip('\n').split('\t')
            if len(p) >= 3: TOKMAP[p[1].upper()] = p[2]
except Exception as e:
    print(f'(tokmap unavailable: {e})')

def parse(il):
    ins = []  # (off, name, kind, operand, plen)
    i = 0
    n = len(il)
    while i < n:
        off = i
        b = il[i]
        if b == 0xFE:
            if i + 1 >= n: raise ValueError(f'truncated FE at {off:X}')
            name, k = TWO.get(il[i+1])
            if name is None: raise ValueError(f'unknown FE opcode {il[i+1]:02X} at {off:X}')
            plen = 2; i += 2
        else:
            name, k = ONE.get(b)
            if name is None: raise ValueError(f'unknown opcode {b:02X} at {off:X}')
            plen = 1; i += 1
        if k == 'sw':
            cnt = struct.unpack_from('<i', il, i)[0]
            base = i + 4 + cnt * 4
            targets = [base + struct.unpack_from('<i', il, i + 4 + 4*t)[0] for t in range(cnt)]
            ins.append((off, name, 'sw', targets, plen)); i += 4 + cnt * 4
        elif k == 'br1':
            d = struct.unpack_from('<b', il, i)[0]; ins.append((off, name, 'br1', i + 1 + d, plen)); i += 1
        elif k == 'br4':
            d = struct.unpack_from('<i', il, i)[0]; ins.append((off, name, 'br4', i + 4 + d, plen)); i += 4
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
    if k == 'sw': return plen + 4 + 4 * len(op)
    if k == 'br1': return plen + 1
    if k == 'br4': return plen + 4
    if k == 'var': return plen * 2  # var1: 1+1=2, var2(FE): 2+2=4
    return plen + KSZ[k]

def eval_back(byoff, ins, st_off, vars_):
    """constant-fold the expression feeding stloc at st_off; returns int or None"""
    chain = []
    ip = st_off
    deficit = 1
    for _ in range(16):
        prev = None
        for x in reversed(ins):
            if x[0] < ip:
                prev = x; break
        if prev is None: return None
        off, name, k, op, plen = prev
        if name.startswith('stloc') or name == 'switch': return None
        consumes = {'add':2,'sub':2,'xor':2,'and':2,'or':2,'mul':2,'div.un':2,'rem.un':2,'shl':2,'shr':2,'shr.un':2,
                    'neg':1,'not':1,'dup':1,'conv.u8':1,'conv.i8':1,'conv.u4':1,'conv.i4':1,'conv.u':1,'conv.i':1}.get(name)
        if consumes is None:
            if name.startswith('ldc.i4') or name in ('ldloc','ldloc.s','ldnull'): consumes = 0
            else: return None
        chain.insert(0, prev)
        deficit = deficit - 1 + consumes
        ip = off
        if deficit == 0: break
    if deficit != 0: return None
    st = []
    for off, name, k, op, plen in chain:
        if name.startswith('ldc.i4.'):
            st.append({'m1':0xFFFFFFFF,'0':0,'1':1,'2':2,'3':3,'4':4,'5':5,'6':6,'7':7,'8':8}[name.split('.')[-1]])
        elif name == 'ldc.i4.s': st.append(op & 0xFFFFFFFF)
        elif name == 'ldc.i4': st.append(op & 0xFFFFFFFF)
        elif name == 'ldc.i8': st.append(op & 0xFFFFFFFF)
        elif name in ('ldloc','ldloc.s'):
            if op in vars_: st.append(vars_[op] & 0xFFFFFFFF)
            else: return None
        elif name == 'ldnull': return None
        elif name == 'add': b = st.pop(); a = st.pop(); st.append((a+b) & 0xFFFFFFFF)
        elif name == 'sub': b = st.pop(); a = st.pop(); st.append((a-b) & 0xFFFFFFFF)
        elif name == 'xor': b = st.pop(); a = st.pop(); st.append((a^b) & 0xFFFFFFFF)
        elif name == 'and': b = st.pop(); a = st.pop(); st.append(a & b)
        elif name == 'or': b = st.pop(); a = st.pop(); st.append(a | b)
        elif name == 'mul': b = st.pop(); a = st.pop(); st.append((a*b) & 0xFFFFFFFF)
        elif name == 'div.un':
            b = st.pop(); a = st.pop(); st.append((a // b) & 0xFFFFFFFF if b else None)
            if st[-1] is None: return None
        elif name == 'rem.un':
            b = st.pop(); a = st.pop(); st.append((a % b) & 0xFFFFFFFF if b else None)
            if st[-1] is None: return None
        elif name == 'shl': b = st.pop(); a = st.pop(); st.append((a << (b & 31)) & 0xFFFFFFFF)
        elif name in ('shr','shr.un'): b = st.pop(); a = st.pop(); st.append((a & 0xFFFFFFFF) >> (b & 31))
        elif name == 'neg': a = st.pop(); st.append((-a) & 0xFFFFFFFF)
        elif name == 'not': a = st.pop(); st.append(a ^ 0xFFFFFFFF)
        elif name == 'dup': st.append(st[-1])
        elif name.startswith('conv.'): pass  # identity in u32 domain
        else: return None
    if len(st) != 1 or st[0] is None: return None
    return st[0]

def main():
    path = sys.argv[1]
    stateVar = int(sys.argv[2]) if len(sys.argv) > 2 else 37
    swVar = int(sys.argv[3]) if len(sys.argv) > 3 else 25
    outpath = sys.argv[4] if len(sys.argv) > 4 else '/tmp/flat_out.txt'
    bin = open(path, 'rb').read()
    ilSize = struct.unpack_from('<i', bin, 4)[0]
    il = bin[24:24+ilSize]
    ins = parse(il)
    byoff = {x[0]: x for x in ins}
    swi = next((idx for idx, x in enumerate(ins) if x[1] == 'switch'), None)
    if swi is None:
        print('no switch'); return
    sw_targets = ins[swi][3]
    disp_off = ins[swi-1][0]
    n = len(sw_targets)

    vars_ = {}
    out = []
    emitted = set()
    pending = [(0, 'entry')]
    guard = 2000000

    def tokname(tok):
        if isinstance(tok, int):
            return TOKMAP.get('%08X' % tok, '')
        return ''

    while pending and guard > 0:
        guard -= 1
        start, why = pending.pop()
        if start in emitted: continue
        emitted.add(start)
        emit = out.append
        emit(f'=== BLOCK IL_{start:04X} ({why}) ===')
        ip = start
        while True:
            x = byoff.get(ip)
            if x is None:
                emit('  <end boundary>'); break
            off, name, k, op, plen = x
            L = ins_len(x)
            # dispatch: ldloc swVar + switch
            if name == 'ldloc' and op == swVar:
                nxt_ins = byoff.get(ip + L)
                if nxt_ins and nxt_ins[1] == 'switch':
                    sv = vars_.get(swVar)
                    if sv is not None and 0 <= sv < n:
                        tgt = sw_targets[sv]
                        emit(f';; dispatch v{swVar}={sv} -> IL_{tgt:04X}')
                        if tgt in emitted:
                            emit('  ;; back-edge stop'); break
                        emitted.add(tgt)
                        emit(f'=== BLOCK IL_{tgt:04X} ===')
                        ip = tgt
                        continue
                    else:
                        emit(f'  !! dispatch unknown v{swVar}={sv}'); break
            # stloc state/switch var
            if name in ('stloc','stloc.s') and op in (stateVar, swVar):
                val = eval_back(byoff, ins, ip, vars_)
                if val is None:
                    vars_.pop(op, None)
                    emit(f'  [stloc v{op}] ;; UNKNOWN <- {name} v{op}')
                else:
                    vars_[op] = val
                    emit(f'  ;; v{op} = {val} (0x{val:X})')
                ip = ip + L
                continue
            # branches
            if k in ('br1', 'br4'):
                cond = name not in ('br', 'br.s', 'leave', 'leave.s')
                nm = TOKMAP.get(name, name)
                emit(f'  (real) {name} IL_{op:04X}')
                if cond:
                    pending.append((ip + L, 'fallthrough'))
                if op == disp_off:
                    if cond:
                        emit('  ;; join dispatch'); break
                    ip = disp_off; continue
                if op in emitted:
                    emit(f'  ;; join visited IL_{op:04X}'); break
                emitted.add(op)
                emit(f'=== BLOCK IL_{op:04X} (branch-target) ===')
                ip = op
                continue
            if name in ('ret', 'throw', 'rethrow', 'jmp', 'endfinally', 'endfilter'):
                emit(f'  (real) {name}'); break
            # emit instruction with token annotation
            if k == 'tok':
                nm = tokname(op)
                emit(f'  {name} 0x{op:08X}' + (f'   ; {nm}' if nm else ''))
            elif k == 'var': emit(f'  {name} v{op}')
            elif k == 'b': emit(f'  {name} {op}')
            elif k == 'i': emit(f'  {name} {op} (0x{op&0xFFFFFFFF:X})')
            elif k == 'i8': emit(f'  {name} {op} (0x{op&0xFFFFFFFFFFFFFFFF:X})')
            elif k == 'sw': emit(f'  {name} ({len(op)} targets)')
            elif k == 'n': emit(f'  {name}')
            else: emit(f'  {name} {op}')
            ip += L
        if len(out) > 400000:
            emit('!! out cap'); break

    with open(outpath, 'w') as f:
        f.write('\n'.join(out) + '\n')
    print(f'lines={len(out)} blocks={len(emitted)}/{n} guard_left={guard} -> {outpath}')

if __name__ == '__main__':
    main()
