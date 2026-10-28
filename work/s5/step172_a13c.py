#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step172: 4192 EH clauses + @2300 window; generate a13c = a13 + trap-block
rewritten as `ldc.i4.0; stloc.s c; leave 2309` + nop fill (skip trap AND its successor)."""
import sys, hashlib
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
IL0 = 0x3F91DC

il = open(ALL, 'rb').read()
bodies = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))

pe = dnfile.dnPE(EXE)
md = pe.net.mdtables
mrow = md.MethodDef.rows[0x4192-1]

# manual method-body parse for EH
data = pe.__data__
rva = mrow.Rva
off = pe.get_offset_from_rva(rva)
hdr = data[off]
if (hdr & 3) == 2:
    csize = hdr >> 2
    eh_off = off + 1 + csize
    fat = False
else:
    flags = int.from_bytes(data[off:off+2], 'little')
    hsize = (flags >> 12) * 4
    csize = int.from_bytes(data[off+4:off+8], 'little')
    eh_off = off + hsize + csize
    fat = True
print('4192 body: fat=%s csize=%d eh_off=%06x' % (fat, csize, eh_off))

# check table presence: flags bit 8 = MoreSects
if fat:
    fl = int.from_bytes(data[off:off+2], 'little')
    print('fat flags=%04x moreSects=%s initLocals=%s' % (fl, bool(fl & 8), bool(fl & 0x10)))

# walk EH clauses
o = eh_off
kind = data[o]
isfat = kind & 0x40
scount = int.from_bytes(data[o+1:o+4], 'little') >> 8
print('EH section: kind=%02x fat=%s clauses=%d' % (kind, bool(isfat), scount))
o += 4
clauses = []
for i in range(scount):
    if isfat:
        fl2 = int.from_bytes(data[o:o+4], 'little')
        tof = int.from_bytes(data[o+4:o+8], 'little')
        tlen = int.from_bytes(data[o+8:o+12], 'little')
        hof = int.from_bytes(data[o+12:o+16], 'little')
        hlen = int.from_bytes(data[o+16:o+20], 'little')
        cof = int.from_bytes(data[o+20:o+24], 'little')
        o += 24
    else:
        fl2 = data[o]
        tof = int.from_bytes(data[o+2:o+4], 'little')
        tlen = int.from_bytes(data[o+4:o+6], 'little')
        hof = int.from_bytes(data[o+6:o+8], 'little')
        hlen = int.from_bytes(data[o+8:o+10], 'little')
        cof = int.from_bytes(data[o+10:o+12], 'little')
        o += 12
    clauses.append((fl2 & 0x0f, tof, tlen, hof, hlen, cof))
    tok = fl2 & 0x0f
    kindn = {0:'catch',1:'filter',2:'finally',3:'fault',4:'dup'}[tok] if tok <= 4 else '?'
    print('  EH%d %s try[%04x+%04x) handler[%04x+%04x) class/filter=%06x  @0a72-in-try=%s @0a9b-in-try=%s' % (
        i, kindn, tof, tlen, hof, hlen, cof,
        tof <= 0x0a72 < tof+tlen, tof <= 0x0a9b < tof+tlen))

c, p = bodies[0x06004192]
ins = list(parse(il[p:p+c]))
print('== 4192 @22f0-2330 window ==')
for off2, name, k, op, plen in ins:
    if 0x22f0 <= off2 <= 0x2330:
        if k == 'tok': print('  @%04x %-10s %s' % (off2, name, mname(op)) if False else '  @%04x %-10s %02x:%06x' % (off2, name, op))
        elif k == 'str': print('  @%04x %-10s %r' % (off2, name, '?'))
        else: print('  @%04x %-10s %s' % (off2, name, ('%x' % op) if op is not None else ''))

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06: return '06:%06x:%s' % (r, str(md.MethodDef.rows[r-1].Name))
        if t == 0x0A:
            m2 = md.MemberRef.rows[r-1]
            cn = m2.Class.row
            nm = getattr(cn, 'TypeName', None)
            full = (str(getattr(cn, 'TypeNamespace', '') or '') + '.' if nm else '') + str(nm or getattr(cn, 'Name', '?'))
            return '%s::%s' % (full, str(m2.Name))
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

# a13c generation
SRC = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
DST = '/workspace/repo_git/exes/AirExplorer_a13c_trapbr.exe'
data2 = bytearray(open(SRC, 'rb').read())

off_a13 = IL0 + 0x04e0
assert bytes(data2[off_a13:off_a13+5]) == bytes.fromhex('16fe01130c')
data2[off_a13:off_a13+5] = bytes.fromhex('2617130c00')

off_trap = IL0 + 0x0a72
orig = bytes(data2[off_trap:off_trap+0x29])
assert orig[:5] == bytes([0xd0, 0x22, 0x06, 0x00, 0x02])

# ldc.i4.0 (16) @0a72; stloc.s c (13 0C) @0a74; br @0a76 (5B, opcode 0x38): next=0a7b, delta=0x2309-0x0a7b=0x188E
# trap block is not inside any known try -> leave illegal -> use br
leave_off = 0x0a7b
delta = 0x2309 - leave_off
new = bytes([0x16, 0x13, 0x0c, 0x38]) + delta.to_bytes(4, 'little', signed=True)
print('a13c new head: %s (br delta=0x%x)' % (new.hex(), delta))
blob = new + b'\x00' * (0x29 - len(new))
data2[off_trap:off_trap+0x29] = blob

open(DST, 'wb').write(bytes(data2))
print('[out] %s md5=%s' % (DST, hashlib.md5(bytes(data2)).hexdigest().upper()))
