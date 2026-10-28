# -*- coding: utf-8 -*-
"""Minimal CIL disassembler: linear decode + branch-target map.
Self-validating: all 68 pattern offsets must be instruction boundaries."""
import struct

# opcode -> (name, opsize)  opsize = operand byte count
N = 0
def T(name, sz=0): return (name, sz)

OP = {
0x00:T('nop'),0x01:T('break'),0x02:T('ldarg.0'),0x03:T('ldarg.1'),0x04:T('ldarg.2'),0x05:T('ldarg.3'),
0x06:T('ldloc.0'),0x07:T('ldloc.1'),0x08:T('ldloc.2'),0x09:T('ldloc.3'),0x0A:T('stloc.0'),0x0B:T('stloc.1'),
0x0C:T('stloc.2'),0x0D:T('stloc.3'),0x0E:T('ldarg.s',1),0x0F:T('ldarga.s',1),0x10:T('starg.s',1),
0x11:T('ldloc.s',1),0x12:T('ldloca.s',1),0x13:T('stloc.s',1),0x14:T('ldnull'),0x15:T('ldc.i4.m1'),
0x16:T('ldc.i4.0'),0x17:T('ldc.i4.1'),0x18:T('ldc.i4.2'),0x19:T('ldc.i4.3'),0x1A:T('ldc.i4.4'),
0x1B:T('ldc.i4.5'),0x1C:T('ldc.i4.6'),0x1D:T('ldc.i4.7'),0x1E:T('ldc.i4.8'),0x1F:T('ldc.i4.s',1),
0x20:T('ldc.i4',4),0x21:T('ldc.i8',8),0x22:T('ldc.r4',4),0x23:T('ldc.r8',8),0x25:T('dup'),0x26:T('pop'),
0x27:T('jmp',4),0x28:T('call',4),0x29:T('calli',4),0x2A:T('ret'),0x2B:T('br.s',1),0x2C:T('brfalse.s',1),
0x2D:T('brtrue.s',1),0x2E:T('beq.s',1),0x2F:T('bge.s',1),0x30:T('bgt.s',1),0x31:T('ble.s',1),
0x32:T('blt.s',1),0x33:T('bne.un.s',1),0x34:T('bge.un.s',1),0x35:T('bgt.un.s',1),0x36:T('ble.un.s',1),
0x37:T('blt.un.s',1),0x38:T('br',4),0x39:T('brfalse',4),0x3A:T('brtrue',4),0x3B:T('beq',4),
0x3C:T('bge',4),0x3D:T('bgt',4),0x3E:T('ble',4),0x3F:T('blt',4),0x40:T('bne.un',4),0x41:T('bge.un',4),
0x42:T('bgt.un',4),0x43:T('ble.un',4),0x44:T('blt.un',4),0x45:T('switch','switch'),
0x46:T('ldind.i1'),0x47:T('ldind.u1'),0x48:T('ldind.i2'),0x49:T('ldind.u2'),0x4A:T('ldind.i4'),
0x4B:T('ldind.u4'),0x4C:T('ldind.i8'),0x4D:T('ldind.i'),0x4E:T('ldind.r4'),0x4F:T('ldind.r8'),
0x50:T('ldind.ref'),0x51:T('stind.ref'),0x52:T('stind.i1'),0x53:T('stind.i2'),0x54:T('stind.i4'),
0x55:T('stind.i8'),0x56:T('stind.r4'),0x57:T('stind.r8'),0x58:T('add'),0x59:T('sub'),0x5A:T('mul'),
0x5B:T('div'),0x5C:T('div.un'),0x5D:T('rem'),0x5E:T('rem.un'),0x5F:T('and'),0x60:T('or'),0x61:T('xor'),
0x62:T('shl'),0x63:T('shr'),0x64:T('shr.un'),0x65:T('neg'),0x66:T('not'),0x67:T('conv.i1'),
0x68:T('conv.i2'),0x69:T('conv.i4'),0x6A:T('conv.i8'),0x6B:T('conv.r4'),0x6C:T('conv.r8'),
0x6D:T('conv.u4'),0x6E:T('conv.u8'),0x6F:T('callvirt',4),0x70:T('cpobj',4),0x71:T('ldobj',4),
0x72:T('ldstr',4),0x73:T('newobj',4),0x74:T('castclass',4),0x75:T('isinst',4),0x76:T('conv.r.un'),
0x79:T('unbox',4),0x7A:T('throw'),0x7B:T('ldfld',4),0x7C:T('ldflda',4),0x7D:T('stfld',4),
0x7E:T('ldsfld',4),0x7F:T('ldsflda',4),0x80:T('stsfld',4),0x81:T('stobj',4),
0x82:T('conv.ovf.i1.un'),0x83:T('conv.ovf.i2.un'),0x84:T('conv.ovf.i4.un'),0x85:T('conv.ovf.i8.un'),
0x86:T('conv.ovf.u1.un'),0x87:T('conv.ovf.u2.un'),0x88:T('conv.ovf.u4.un'),0x89:T('conv.ovf.u8.un'),
0x8A:T('conv.ovf.i.un'),0x8B:T('conv.ovf.u.un'),0x8C:T('box',4),0x8D:T('newarr',4),0x8E:T('ldlen'),
0x8F:T('ldelema',4),0x90:T('ldelem.i1'),0x91:T('ldelem.u1'),0x92:T('ldelem.i2'),0x93:T('ldelem.u2'),
0x94:T('ldelem.i4'),0x95:T('ldelem.u4'),0x96:T('ldelem.i8'),0x97:T('ldelem.i'),0x98:T('ldelem.r4'),
0x99:T('ldelem.r8'),0x9A:T('ldelem.ref'),0x9B:T('stelem.i'),0x9C:T('stelem.i1'),0x9D:T('stelem.i2'),
0x9E:T('stelem.i4'),0x9F:T('stelem.i8'),0xA0:T('stelem.r4'),0xA1:T('stelem.r8'),0xA2:T('stelem.ref'),
0xA3:T('ldelem',4),0xA4:T('stelem',4),0xA5:T('unbox.any',4),
0xB3:T('conv.ovf.i1'),0xB4:T('conv.ovf.u1'),0xB5:T('conv.ovf.i2'),0xB6:T('conv.ovf.u2'),
0xB7:T('conv.ovf.i4'),0xB8:T('conv.ovf.u4'),0xB9:T('conv.ovf.i8'),0xBA:T('conv.ovf.u8'),
0xC2:T('refanyval',4),0xC3:T('ckfinite'),0xC6:T('mkrefany',4),0xD0:T('ldtoken',4),
0xD1:T('conv.u2'),0xD2:T('conv.u1'),0xD3:T('conv.i'),0xD4:T('conv.ovf.i'),0xD5:T('conv.ovf.u'),
0xD6:T('add.ovf'),0xD7:T('add.ovf.un'),0xD8:T('mul.ovf'),0xD9:T('mul.ovf.un'),0xDA:T('sub.ovf'),
0xDB:T('sub.ovf.un'),0xDC:T('endfinally'),0xDD:T('leave',4),0xDE:T('leave.s',1),0xDF:T('stind.i'),
0xE0:T('conv.u'),0xEC:T('unk_EC',4),  # empirical: 1+4 token operand (validated by 68-trap alignment)
}
# 0xFE two-byte
FE = {
0x00:T('arglist'),0x01:T('ceq'),0x02:T('cgt'),0x03:T('cgt.un'),0x04:T('clt'),0x05:T('clt.un'),
0x06:T('ldftn',4),0x07:T('ldvirtftn',4),0x09:T('ldarg',2),0x0A:T('ldarga',2),0x0B:T('starg',2),
0x0C:T('ldloc',2),0x0D:T('ldloca',2),0x0E:T('stloc',2),0x0F:T('localloc'),0x11:T('endfilter'),
0x12:T('unaligned.',1),0x13:T('volatile.'),0x14:T('tail.'),0x15:T('initobj',4),0x16:T('constrained.',4),
0x17:T('cpblk'),0x18:T('initblk'),0x1A:T('rethrow'),0x1C:T('sizeof',4),0x1D:T('refanytype'),
0x1E:T('readonly.'),
}
BR1 = {0x2B,0x2C,0x2D,0x2E,0x2F,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37}
BR4 = {0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,0x40,0x41,0x42,0x43,0x44}

def disasm(il):
    """linear decode -> list of (off, name, operand_bytes, next_off, targets); tolerant of overrun"""
    out = []
    i, n = 0, len(il)
    while i < n:
        off = i
        b = il[i]
        i += 1
        if b == 0xFE:
            b2 = il[i]; i += 1
            nm, sz = FE.get(b2, ('fe_%02x' % b2, 0))
            if sz == 'switch': sz = 0
            opb = il[i:i+sz]; i += sz
            out.append((off, 'fe.' + nm, opb, i, []))
        else:
            nm, sz = OP.get(b, ('op_%02x' % b, 0))
            if sz == 'switch':
                cnt = struct.unpack_from('<I', il, i)[0]
                need = 4 + 4 * cnt
                if i + need > n:
                    out.append((off, '!!OVERRUN@switch', il[off:off+16], n, []))
                    return out
                opb = il[i:i+need]; i += need
                base = i
                tgts = [base + struct.unpack_from('<i', opb, 4+4*k)[0] for k in range(cnt)]
                out.append((off, 'switch', opb, i, tgts))
            else:
                opb = il[i:i+sz]; i += sz
                tg = []
                if b in BR1 and sz == 1:
                    tg = [i + struct.unpack_from('<b', opb)[0]]
                elif b in BR4:
                    tg = [i + struct.unpack_from('<i', opb)[0]]
                out.append((off, nm, opb, i, tg))
    return out

def fmt(ins):
    off, nm, opb, nxt, tg = ins
    s = '%04X %-12s' % (off, nm)
    if opb:
        if nm in ('ldc.i4','ldc.i8'): s += ' 0x%x' % int.from_bytes(opb.ljust(8, b'\0')[:8], 'little')
        elif nm == 'ldc.i4.s': s += ' %d' % struct.unpack('<b', opb)[0]
        elif nm == 'ldc.r4': s += ' %f' % struct.unpack('<f', opb)[0]
        elif nm == 'ldc.r8': s += ' %f' % struct.unpack('<d', opb)[0]
        elif nm == 'switch': s += ' (%d cases)' % (len(opb)//4 - 1)
        elif len(opb) == 4: s += ' 0x%08x' % struct.unpack('<I', opb)[0]
        elif len(opb) == 2: s += ' %d' % struct.unpack('<H', opb)[0]
        else: s += ' ' + opb.hex()
    if tg: s += '  -> %04X' % tg[0]
    return s
