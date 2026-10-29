#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step178: a15 生成。
① raw 字节级扫描 4192 全部 -> 0x0a72 的跳转 (flat.py 对 brtrue@22f7 解析异常, raw 为准)
② a15 = a13(@04e0 c=0) + pop@22f7 (brtrue->pop, 栈平衡) + 陷阱块改写 (c=0; br ret@2309)
③ 顺带 dump 4521 PlanRunner (23 ins) 找 'AirExplorer ' (name+' ') 第二陷阱"""
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

c, p = bodies[0x06004192]
body = bytes(il[p:p+c])
print('4192 csize=%x' % c)

# ① raw edge scan: all branch opcodes, signed rel -> 0x0a72
OPS = {0x2b: 'br.s', 0x2c: 'brfalse.s', 0x2d: 'brtrue.s', 0x38: 'br', 0x39: 'brfalse', 0x3a: 'brtrue', 0xdd: 'switch'}
print('== raw edges -> 0x0a72 ==')
hits = []
for i in range(len(body)):
    b = body[i]
    if b in (0x2b, 0x2c, 0x2d):
        if i + 2 <= len(body):
            rel = int.from_bytes(body[i+1:i+2], 'little', signed=True)
            if i + 2 + rel == 0x0a72: hits.append((i, OPS[b]))
    elif b in (0x38, 0x39, 0x3a):
        if i + 5 <= len(body):
            rel = int.from_bytes(body[i+1:i+5], 'little', signed=True)
            if i + 5 + rel == 0x0a72: hits.append((i, OPS[b]))
    elif b == 0xdd:
        n = int.from_bytes(body[i+1:i+5], 'little')
        base = i + 5 + 4 * n
        if base <= len(body):
            for j in range(n):
                rel = int.from_bytes(body[i+5+4*j:i+9+4*j], 'little', signed=True)
                if base + rel == 0x0a72: hits.append((i, 'switch#%d' % j))
for off2, nm in hits:
    print('  @%04x %s -> 0a72' % (off2, nm))
print('  total=%d' % len(hits))

# verify @22f7 bytes
print('@22f7 raw:', body[0x22f7:0x22fc].hex())

# ② a15 generation
SRC = EXE
DST = '/workspace/repo_git/exes/AirExplorer_a15_combo.exe'
data2 = bytearray(open(SRC, 'rb').read())

# patch1: a13 @04e0: c=0 (16 FE01 130C -> 26 16 13 0C 00)
off_a13 = IL0 + 0x04e0
assert bytes(data2[off_a13:off_a13+5]) == bytes.fromhex('16fe01130c')
data2[off_a13:off_a13+5] = bytes.fromhex('2616130c00')
print('[patch1] a13 c=0 @%06x' % off_a13)

# patch2: @22f7 brtrue(5B) -> pop + 4 nop  (loc2.Length!=0 -> trap  => never)
off_chk = IL0 + 0x22f7
assert bytes(data2[off_chk:off_chk+5]) == bytes.fromhex('3a16ddffff'), bytes(data2[off_chk:off_chk+5]).hex()
data2[off_chk:off_chk+5] = bytes.fromhex('2600000000')
print('[patch2] pop@22f7 (bypass loc2.Length check) @%06x' % off_chk)

# patch3: trap block rewrite: ldc.i4.0; stloc.s c; br ret@2309
off_trap = IL0 + 0x0a72
assert bytes(data2[off_trap:off_trap+5]) == bytes([0xd0, 0x22, 0x06, 0x00, 0x02])
delta = 0x2309 - 0x0a7a
new = bytes([0x16, 0x13, 0x0c, 0x38]) + delta.to_bytes(4, 'little', signed=True)
blob = new + b'\x00' * (0x29 - len(new))
data2[off_trap:off_trap+0x29] = blob
print('[patch3] trap rewrite br->%04x (delta=0x%x) @%06x' % (0x2309, delta & 0xffffffff, off_trap))

open(DST, 'wb').write(bytes(data2))
print('[out] %s md5=%s' % (DST, hashlib.md5(bytes(data2)).hexdigest().upper()))

# ③ 4521 PlanRunner dump
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
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)
for tok in (0x06004521,):
    if tok not in bodies: continue
    cc, pp = bodies[tok]
    print('== %06x %s ==' % (tok & 0xFFFFFF, mname(tok)))
    for off2, name, k, op, plen in parse(il[pp:pp+cc]):
        if k == 'tok': print('  @%04x %-10s %s' % (off2, name, mname(op)))
        elif k == 'str': print('  @%04x %-10s %r' % (off2, name, op))
        else: print('  @%04x %-10s %s' % (off2, name, ('%x' % op) if (op is not None and not hasattr(op, '__len__')) else ''))
