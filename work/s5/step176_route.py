#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step176: 第二哨兵路由分析。
① 4192 内 loc17 (ldloc 17/ldloc.s 17 = 0xFE0C11/0x11) 的全部消费点 + 后续 8 条 (比较/分支→路由)
② 4192 调度器窗口 @0a9b-0aeb + @00fb 窗口 (try[00fb+894) 头部)
③ 4523 EH + try 区内全部 call + throw@046f 前后文"""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'

il = open(ALL, 'rb').read()
bodies = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))

pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06: return '0600%04x:%s' % (r, str(md.MethodDef.rows[r-1].Name))
        if t == 0x0A:
            m2 = md.MemberRef.rows[r-1]
            cn = m2.Class.row
            nm = getattr(cn, 'TypeName', None)
            full = (str(getattr(cn, 'TypeNamespace', '') or '') + '.' if nm else '') + str(nm or getattr(cn, 'Name', '?'))
            return '%s::%s' % (full, str(m2.Name))
        if t == 0x04: return 'fld:%06x:%s' % (r, str(md.Field.rows[r-1].Name))
        if t == 0x01: return 'td:%06x:%s' % (r, str(md.TypeDef.rows[r-1].TypeName))
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

c, p = bodies[0x06004192]
ins = list(parse(il[p:p+c]))
N = len(ins)

def dump_range(lo, hi, tag):
    print('== 4192 %s [%04x,%04x) ==' % (tag, lo, hi))
    for off2, name, k, op, plen in ins:
        if lo <= off2 < hi:
            if k == 'tok': print('  @%04x %-10s %s' % (off2, name, mname(op)))
            elif k == 'str': print('  @%04x %-10s %r' % (off2, name, op))
            else: print('  @%04x %-10s %s' % (off2, name, ('%x' % op) if (op is not None and not hasattr(op, '__len__')) else (op if hasattr(op, '__len__') else '')))

# ① loc17 消费点
print('== 4192 loc17 (ldloc 17 / ldloc.s 17) consumers ==')
for i, (off2, name, k, op, plen) in enumerate(ins):
    is17 = (name in ('ldloc', 'ldloc.s') and op == 17) or (name == 'ldloc.s' and op == 17)
    if name == 'ldloc.s' and op == 17 or name == 'ldloc' and op == 17:
        print('  --- @%04x %s 17 ---' % (off2, name))
        for j in range(1, 9):
            if i + j >= N: break
            o2, n2, k2, op2, pl2 = ins[i + j]
            if k2 == 'tok': print('    @%04x %-10s %s' % (o2, n2, mname(op2)))
            else: print('    @%04x %-10s %s' % (o2, n2, ('%x' % op2) if (op2 is not None and not hasattr(op2, '__len__')) else ''))

# ② dispatcher windows
dump_range(0x0a9b, 0x0aeb, 'dispatcher-head')
dump_range(0x00fb, 0x0140, 'try00fb-head')

# ③ 4523 EH + try region calls
data = pe.__data__
mrow = md.MethodDef.rows[0x4523-1]
off = pe.get_offset_from_rva(mrow.Rva)
hdr = data[off]
if (hdr & 3) == 2:
    csize = hdr >> 2; eh_off = off + 1 + csize; isfat = False
else:
    flags = int.from_bytes(data[off:off+2], 'little')
    hsize = (flags >> 12) * 4
    csize = int.from_bytes(data[off+4:off+8], 'little')
    eh_off = off + hsize + csize; isfat = True
print('4523 body: fat=%s csize=%d eh_off=%06x' % (isfat, csize, eh_off))
o = eh_off
kind = data[o]; isfatsec = bool(kind & 0x40)
scount = int.from_bytes(data[o+1:o+4], 'little') >> 8
print('4523 EH kind=%02x fat=%s scount_raw=%d' % (kind, isfatsec, scount))
o += 4
clauses = []
for i in range(scount):
    if isfatsec:
        fl2 = int.from_bytes(data[o:o+4], 'little')
        tof = int.from_bytes(data[o+4:o+8], 'little'); tlen = int.from_bytes(data[o+8:o+12], 'little')
        hof = int.from_bytes(data[o+12:o+16], 'little'); hlen = int.from_bytes(data[o+16:o+20], 'little')
        cof = int.from_bytes(data[o+20:o+24], 'little'); o += 24
    else:
        fl2 = data[o]
        tof = int.from_bytes(data[o+2:o+4], 'little'); tlen = int.from_bytes(data[o+4:o+6], 'little')
        hof = int.from_bytes(data[o+6:o+8], 'little'); hlen = int.from_bytes(data[o+8:o+10], 'little')
        cof = int.from_bytes(data[o+10:o+12], 'little'); o += 12
    tk = fl2 & 0x0f
    kn = {0: 'catch', 1: 'filter', 2: 'finally', 3: 'fault', 4: 'dup'}.get(tk, '?')
    cls = mname(0x01000000 | cof) if tk == 0 and cof else cof
    print('  EH%d %s try[%04x+%04x) handler[%04x+%04x) cls=%s' % (i, kn, tof, tlen, hof, hlen, cls))
    clauses.append((tk, tof, tlen, hof, hlen))

c2, p2 = bodies[0x06004523]
ins2 = list(parse(il[p2:p2+c2]))
# try region calls
for tk, tof, tlen, hof, hlen in clauses:
    if tk == 0:
        print('== 4523 try[%04x+%04x) calls ==' % (tof, tlen))
        for off2, name, k, op, plen in ins2:
            if tof <= off2 < tof + tlen and k == 'tok' and (op >> 24) in (0x06, 0x0A):
                print('  @%04x %-10s %s' % (off2, name, mname(op)))
        # handler context
        print('== 4523 handler [%04x+%04x) ==' % (hof, hlen))
        for off2, name, k, op, plen in ins2:
            if hof <= off2 < hof + hlen + 0x10:
                if k == 'tok': print('  @%04x %-10s %s' % (off2, name, mname(op)))
                else: print('  @%04x %-10s %s' % (off2, name, ('%x' % op) if (op is not None and not hasattr(op, '__len__')) else ''))
# throw @046f context
print('== 4523 @0440-0490 (throw ctx) ==')
for off2, name, k, op, plen in ins2:
    if 0x0440 <= off2 <= 0x0490:
        if k == 'tok': print('  @%04x %-10s %s' % (off2, name, mname(op)))
        else: print('  @%04x %-10s %s' % (off2, name, ('%x' % op) if (op is not None and not hasattr(op, '__len__')) else ''))
