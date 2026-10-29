#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step179: a15 终版 = 三补丁组合。
① a13 @04e0: c=0 (16 FE01 130C -> 26 16 13 0C 00)  —— 第一哨兵输出归零
② @00f1: brfalse(39) -> br(38) 1 字节 —— 陷阱路由器 @00d3 块 c!=0 也走正常调度器,
   陷阱唯一入口 @00f6 br a72 变死码; 同时中和 @2283 catch 的 c=1 路由
③ 陷阱块改写 (a13d): c=0; br ret@2309 —— 若仍有其他路径进入则静默返回(保险网)
注: @22f7 brtrue 实际目标是 0x12 调度器(非陷阱), 不动。"""
import sys, hashlib
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse

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
assert body[0x00f1] == 0x39 and int.from_bytes(body[0x00f2:0x00f6], 'little', signed=True) + 0x00f6 == 0x12
assert body[0x00f6] == 0x38 and int.from_bytes(body[0x00f7:0x00fb], 'little', signed=True) + 0x00fb == 0x0a72

SRC = EXE
DST = '/workspace/repo_git/exes/AirExplorer_a15_combo.exe'
data2 = bytearray(open(SRC, 'rb').read())

off1 = IL0 + 0x04e0
assert bytes(data2[off1:off1+5]) == bytes.fromhex('16fe01130c')
data2[off1:off1+5] = bytes.fromhex('2616130c00')
print('[p1] a13 c=0 @%06x' % off1)

off2 = IL0 + 0x00f1
assert data2[off2] == 0x39
data2[off2] = 0x38
print('[p2] brfalse->br @%06x (1B, c!=0 also -> dispatcher 0x12)' % off2)

off3 = IL0 + 0x0a72
assert bytes(data2[off3:off3+5]) == bytes([0xd0, 0x22, 0x06, 0x00, 0x02])
delta = 0x2309 - 0x0a7a
new = bytes([0x16, 0x13, 0x0c, 0x38]) + delta.to_bytes(4, 'little', signed=True)
blob = new + b'\x00' * (0x29 - len(new))
data2[off3:off3+0x29] = blob
print('[p3] trap rewrite br->2309 @%06x' % off3)

open(DST, 'wb').write(bytes(data2))
print('[out] %s md5=%s' % (DST, hashlib.md5(bytes(data2)).hexdigest().upper()))
