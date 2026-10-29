#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step180: a15 InvalidProgram 隔离变体（a13d 与 a15 仅差 2B: 39→38@00f1, 17→16@04e1）。
v2 = p1(16) + p3            (无 p2)  — 若合法 → p2 是凶手
v4 = p1(17) + p2 + p3       (=a13d+p2) — 若非法 → p2 是凶手 (与 a13d 仅差 p2)
v5 = p1(16) + p3 + @00f6 目标改 0x12  — 替代路由补丁 (brfalse 保留, c!=0 落 @00f6 br→0x12)"""
import sys, hashlib
sys.path.insert(0, '/workspace/repo_git/work')

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
IL0 = 0x3F91DC

def build(dst, c_byte, do_p2, do_p5):
    data = bytearray(open(EXE, 'rb').read())
    # p1: a13 c=X @04e0
    off1 = IL0 + 0x04e0
    assert bytes(data[off1:off1+5]) == bytes.fromhex('16fe01130c')
    data[off1:off1+5] = bytes([0x26, c_byte, 0x13, 0x0C, 0x00])
    # p3: trap rewrite
    off3 = IL0 + 0x0a72
    assert bytes(data[off3:off3+5]) == bytes([0xd0, 0x22, 0x06, 0x00, 0x02])
    delta = 0x2309 - 0x0a7a
    new = bytes([0x16, 0x13, 0x0c, 0x38]) + delta.to_bytes(4, 'little', signed=True)
    data[off3:off3+0x29] = new + b'\x00' * (0x29 - len(new))
    # p2: brfalse->br @00f1
    if do_p2:
        off2 = IL0 + 0x00f1
        assert data[off2] == 0x39
        data[off2] = 0x38
    # p5: @00f6 br a72 -> br 12
    if do_p5:
        off5 = IL0 + 0x00f6
        assert bytes(data[off5:off5+5]) == bytes.fromhex('3877090000'), bytes(data[off5:off5+5]).hex()
        data[off5:off5+5] = bytes.fromhex('3817ffffff')   # 0x00fb + (-0x17) = 0x12... verify below
    b = bytes(data)
    open(dst, 'wb').write(b)
    print('%s md5=%s' % (dst.split('/')[-1], hashlib.md5(b).hexdigest().upper()))

# verify p5 rel: target 0x12 from 0x00fb: rel = 0x12 - 0x00fb = -0xE9
assert (0x00fb + (-0xE9)) == 0x12
# fix: -0xE9 = 0xFFFFFF17 little-endian 17 ff ff ff  (matches bytes above)

build('/workspace/repo_git/exes/AirExplorer_a15v2_p1p3.exe', 0x16, False, False)
build('/workspace/repo_git/exes/AirExplorer_a15v4_a13dp2.exe', 0x17, True, False)
build('/workspace/repo_git/exes/AirExplorer_a15v5_p1p3p5.exe', 0x16, False, True)
