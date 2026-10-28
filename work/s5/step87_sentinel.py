#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step87: (1) who ldstr's the 'AirExplorer' sentinel message?
(2) does 4528 reference the 5 patched method tokens / their RVAs?
(3) brief the callvirt chain 06004409/0600457F/06004559/06004581."""
import sys, struct
sys.path.insert(0, '/workspace/repo_git/work')
sys.path.insert(0, '/workspace/repo_git/work/s5')
from flat import parse

EXE = '/workspace/repo_git/exes/AirExplorer_a1.exe'
IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'

il = open(ALL, 'rb').read()
idx = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        idx[int(p[0], 16)] = (int(p[1]), int(p[4]))

import dnfile
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables
us = bytes(pe.net.metadata.streams[b'#US'].__data__)

def usdec(t):
    p = t & 0xFFFFFF
    b0 = us[p]
    if b0 & 0x80 == 0:
        ln, p = b0, p + 1
    elif b0 & 0xC0 == 0x80:
        ln = ((b0 & 0x3F) << 8) | us[p + 1]; p += 2
    else:
        ln = ((b0 & 0x1F) << 24) | (us[p + 1] << 16) | (us[p + 2] << 8) | us[p + 3]; p += 4
    return us[p:p + max(0, ln - 1)].decode('utf-16-le', 'replace')

# --- 1) find 'AirExplorer' in #US, then who references that token ---
want = []
p = 1
while p < len(us):
    b0 = us[p]
    if b0 & 0x80 == 0:
        ln, q = b0, p + 1
    elif b0 & 0xC0 == 0x80:
        ln = ((b0 & 0x3F) << 8) | us[p + 1]; q = p + 2
    else:
        ln = ((b0 & 0x1F) << 24) | (us[p+1] << 16) | (us[p+2] << 8) | us[p+3]; q = p + 4
    if ln > 0:
        s = us[q:q + ln - 1].decode('utf-16-le', 'replace')
        if s in ('AirExplorer', 'ValidatorArgument.EmitterReporter') or 'EmitterReporter' in s:
            want.append((p, s))
    p = q + ln
print('[US] sentinel strings:')
for off, s in want:
    tok = 0x70000000 | off
    print('  off=%#x tok=%s %r' % (off, hex(tok), s))
    # who ldstr's it
    for t, (cl, pos) in idx.items():
        b = il[pos:pos + cl]
        pat = struct.pack('<I', tok)
        if pat in b:
            print('    <- tok=%s' % hex(t))

# --- 2) 4528 references to patched tokens / RVA-like constants ---
b = il[idx[0x06004528][1]:idx[0x06004528][1] + idx[0x06004528][0]]
ins = parse(b)
TARGETS = [0x0600212A, 0x06002157, 0x06002127, 0x06002133, 0x06002145]
for e in ins:
    if e[1] in ('call', 'callvirt', 'newobj', 'ldtoken'):
        t = struct.unpack_from('<I', b, e[0] + 1)[0]
        if t in TARGETS:
            print('[4528] REFS-TARGET %04x %s %s' % (e[0], e[1], hex(t)))

# --- 3) brief callvirt chain core ---
def brief(tok):
    if tok not in idx:
        print('tok=%s NOT-IN-IDX' % hex(tok)); return
    cl, pos = idx[tok]
    bb = il[pos:pos + cl]
    i2 = parse(bb)
    print('tok=%s len=%d ins=%d' % (hex(tok), len(bb), len(i2)))
    print('  ' + ' | '.join(e[1] for e in i2[:24]))
    for e in i2:
        if e[1] in ('call', 'callvirt'):
            print('  %04x %s %s' % (e[0], e[1], hex(struct.unpack_from('<I', bb, e[0] + 1)[0])))
        elif e[1] == 'ldstr':
            print('  %04x ldstr %r' % (e[0], usdec(struct.unpack_from('<I', bb, e[0] + 1)[0])))
        elif e[1] in ('ldfld', 'ldsfld') and e[0] + 5 <= len(bb):
            print('  %04x %s %s' % (e[0], e[1], hex(struct.unpack_from('<I', bb, e[0] + 1)[0])))
for t in (0x06004409, 0x0600457F, 0x06004559, 0x06004581):
    brief(t)
