#!/usr/bin/env python3
# ildis.py — minimal CIL disassembler for m_*.bin dumps (24B header + raw IL)
import struct, sys, zipfile

# one-byte opcodes
OPS1 = {
0x00:('nop',0),0x01:('break',0),0x02:('ldarg.0',0),0x03:('ldarg.1',0),0x04:('ldarg.2',0),0x05:('ldarg.3',0),
0x06:('ldloc.0',0),0x07:('ldloc.1',0),0x08:('ldloc.2',0),0x09:('ldloc.3',0),0x0A:('stloc.0',0),0x0B:('stloc.1',0),
0x0C:('stloc.2',0),0x0D:('stloc.3',0),0x0E:('ldarg.s',1),0x0F:('ldarga.s',1),0x10:('starg.s',1),0x11:('ldloca.s',1),
0x12:('ldc.i4.m1',0),0x13:('ldc.i4.s',1),0x14:('ldc.i4.0',0),0x15:('ldc.i4.1',0),0x16:('ldc.i4.2',0),0x17:('ldc.i4.3',0),
0x18:('ldc.i4.4',0),0x19:('ldc.i4.5',0),0x1A:('ldc.i4.6',0),0x1B:('ldc.i4.7',0),0x1C:('ldc.i4.8',0),0x1D:('ldc.i4.s',1),
0x1E:('ldc.i4.s',1),
0x20:('ldc.i4',4),0x21:('ldc.i8',8),0x22:('ldc.r4',4),0x23:('ldc.r8',8),0x25:('dup',0),0x26:('pop',0),
0x28:('call',4),0x29:('calli',4),0x2A:('ret',0),0x2B:('br.s',1),0x2C:('brfalse.s',1),0x2D:('brtrue.s',1),
0x2E:('beq.s',1),0x2F:('bge.s',1),0x30:('bgt.s',1),0x31:('ble.s',1),0x32:('blt.s',1),0x33:('bne.un.s',1),
0x34:('bge.un.s',1),0x35:('bgt.un.s',1),0x36:('ble.un.s',1),0x37:('blt.un.s',1),0x38:('br',4),0x39:('brfalse',4),
0x3A:('brtrue',4),0x3B:('beq',4),0x3C:('bge',4),0x3D:('bgt',4),0x3E:('ble',4),0x3F:('blt',4),0x40:('bne.un',4),
0x41:('bge.un',4),0x42:('bgt.un',4),0x43:('ble.un',4),0x44:('blt.un',4),0x45:('switch','switch'),
0x58:('add',0),0x59:('sub',0),0x5A:('mul',0),0x5B:('div',0),0x5C:('div.un',0),0x5D:('rem',0),0x5E:('rem.un',0),
0x5F:('and',0),0x60:('or',0),0x61:('xor',0),0x62:('shl',0),0x63:('shr',0),0x64:('shr.un',0),0x65:('neg',0),0x66:('not',0),
0x67:('conv.i1',0),0x68:('conv.i2',0),0x69:('conv.i4',0),0x6A:('conv.i8',0),0x6B:('conv.r4',0),0x6C:('conv.r8',0),
0x6D:('conv.u4',0),0x6E:('conv.u8',0),0x6F:('callvirt',4),0x72:('ldstr',4),0x73:('newobj',4),0x74:('castclass',4),
0x75:('isinst',4),0x79:('unbox.any',4),0x7B:('ldfld',4),0x7C:('ldflda',4),0x7D:('stfld',4),0x7E:('ldsfld',4),
0x7F:('ldsflda',4),0x80:('stsfld',4),0x81:('stobj',4),0x82:('conv.ovf.i1.un',0),0x83:('conv.ovf.i2.un',0),
0x84:('conv.ovf.i4.un',0),0x85:('conv.ovf.i8.un',0),0x86:('conv.ovf.u1.un',0),0x87:('conv.ovf.u2.un',0),
0x88:('conv.ovf.u4.un',0),0x89:('conv.ovf.u8.un',0),0x8C:('box',4),0x8D:('newarr',4),0x8E:('ldlen',0),
0x8F:('ldelema',4),0x90:('ldelem.i1',0),0x91:('ldelem.u1',0),0x92:('ldelem.i2',0),0x93:('ldelem.u2',0),
0x94:('ldelem.i4',0),0x95:('ldelem.u4',0),0x96:('ldelem.i8',0),0x97:('ldelem.i',0),0x98:('ldelem.r4',0),
0x99:('ldelem.r8',0),0x9A:('ldelem.ref',0),0x9B:('stelem.i',0),0x9C:('stelem.i1',0),0x9D:('stelem.i2',0),
0x9E:('stelem.i4',0),0x9F:('stelem.i8',0),0xA0:('stelem.r4',0),0xA1:('stelem.r8',0),0xA2:('stelem.ref',0),
0xA3:('ldelem',4),0xA4:('stelem',4),0xA5:('unbox.any',4),0xD0:('ldtoken',4),0xDC:('endfinally',0),
0xDD:('leave',4),0xDE:('leave.s',1),0xFE:('prefix','prefix'),
}
OPS2 = {
0x01:('ceq',0),0x02:('cgt',0),0x03:('cgt.un',0),0x04:('clt',0),0x05:('clt.un',0),0x06:('ldftn',4),0x07:('ldvirtftn',4),
0x09:('ldarg',2),0x0A:('ldarga',2),0x0B:('starg',2),0x0C:('ldloc',2),0x0D:('ldloca',2),0x0E:('stloc',2),
0x0F:('localloc',0),0x11:('endfilter',0),0x12:('unaligned.',1),0x13:('volatile.',0),0x14:('tail.',0),0x15:('initobj',4),
0x16:('constrained.',4),0x17:('cpblk',0),0x18:('initblk',0),0x1A:('rethrow',0),0x1C:('sizeof',4),0x1D:('refanytype',0),
0x1E:('readonly.',0),
}

def disasm(il, base=0):
    out = []
    i = 0
    n = len(il)
    while i < n:
        off = i
        b = il[i]
        if b == 0xFE:
            b2 = il[i+1]
            nm, opnd = OPS2.get(b2, ('unk.fe%02x' % b2, 0))
            i += 2
            if isinstance(opnd, int) and opnd:
                v = int.from_bytes(il[i:i+opnd], 'little'); i += opnd
                out.append((off, '%s %d' % (nm, v)))
            else:
                out.append((off, nm))
            continue
        nm, opnd = OPS1.get(b, ('unk%02x' % b, 0))
        i += 1
        if opnd == 'switch':
            cnt = int.from_bytes(il[i:i+4], 'little'); i += 4
            tgts = []
            for k in range(cnt):
                d = struct.unpack_from('<i', il, i)[0]; i += 4
                tgts.append(i + d)
            out.append((off, 'switch(%d) %s' % (cnt, ','.join(hex(t) for t in tgts))))
            continue
        if isinstance(opnd, int) and opnd:
            v = int.from_bytes(il[i:i+opnd], 'little')
            i += opnd
            if nm in ('br.s','brfalse.s','brtrue.s','beq.s','bge.s','bgt.s','ble.s','blt.s','bne.un.s','bge.un.s','bgt.un.s','ble.un.s','blt.un.s','leave.s'):
                if v >= 0x80: v -= 0x100
                out.append((off, '%s IL_%04x' % (nm, i + v)))
            elif nm in ('br','brfalse','brtrue','beq','bge','bgt','ble','blt','bne.un','bge.un','bgt.un','ble.un','blt.un','leave'):
                v = struct.unpack('<i', il[i-opnd:i])[0]
                out.append((off, '%s IL_%04x' % (nm, i + v)))
            else:
                out.append((off, '%s 0x%x' % (nm, v)))
        else:
            out.append((off, nm))
    return out

def main():
    W = r'C:\Users\xaxka\.zcode\workspace\draft-7d4f519b-6da7-4fdf-befe-8fe2605c4eff'
    z = zipfile.ZipFile(W + r'\airexplorer-reactor-handoff\work\dump_official_16598.zip')
    for tok in sys.argv[1:]:
        d = z.read('m_%s.bin' % tok)
        ilsize, maxstack, ehcnt = struct.unpack_from('<III', d, 4)
        il = d[24:24+ilsize]
        print('=== %s ilSize=%d maxStack=%d eh=%d ===' % (tok, ilsize, maxstack, ehcnt))
        for off, s in disasm(il):
            print('  IL_%04x  %s' % (off, s))

if __name__ == '__main__':
    main()
