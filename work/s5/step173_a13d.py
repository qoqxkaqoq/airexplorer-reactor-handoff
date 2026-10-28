#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step173: a13d = a13 + trap-block `ldc.i4.0; stloc.s c; br <ret>` 修正版。
a13c off-by-one: br opcode 在 0x0a75, 指令尾 = 0x0a7a (不是 0x0a7b) →
delta=0x188E 实际跳 0x2308 (ret 前一字节, 指令中间) → JIT InvalidProgramException。
本版动态找 0x22f0-0x2340 窗口内的 ret 作为落点, delta = ret_off - 0x0a7a。"""
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
ins = list(parse(il[p:p+c]))
print('== 4192 @22f0-2340 window ==')
rets = []
for off2, name, k, op, plen in ins:
    if 0x22f0 <= off2 <= 0x2340:
        print('  @%04x %-10s %s' % (off2, name, ('%x' % op) if (op is not None and not hasattr(op, '__len__')) else ''))
        if name == 'ret':
            rets.append(off2)

assert 0x2309 in rets, 'ret@2309 missing! rets=%s' % [hex(x) for x in rets]
TGT = 0x2309
NEXT = 0x0a7a          # br @0a75, 5B -> next = 0a7a  (a13c 误用 0a7b)
delta = TGT - NEXT
print('target=%04x next=%04x delta=0x%x' % (TGT, NEXT, delta))

SRC = EXE
DST = '/workspace/repo_git/exes/AirExplorer_a13d_trapbr2.exe'
data2 = bytearray(open(SRC, 'rb').read())

# a13 补丁 (与 a13c 相同)
off_a13 = IL0 + 0x04e0
assert bytes(data2[off_a13:off_a13+5]) == bytes.fromhex('16fe01130c')
data2[off_a13:off_a13+5] = bytes.fromhex('2617130c00')

# 陷阱块改写 (修正 delta)
off_trap = IL0 + 0x0a72
orig = bytes(data2[off_trap:off_trap+0x29])
assert orig[:5] == bytes([0xd0, 0x22, 0x06, 0x00, 0x02]), orig[:8].hex()
new = bytes([0x16, 0x13, 0x0c, 0x38]) + delta.to_bytes(4, 'little', signed=True)
blob = new + b'\x00' * (0x29 - len(new))
data2[off_trap:off_trap+0x29] = blob

open(DST, 'wb').write(bytes(data2))
print('[out] %s md5=%s' % (DST, hashlib.md5(bytes(data2)).hexdigest().upper()))
