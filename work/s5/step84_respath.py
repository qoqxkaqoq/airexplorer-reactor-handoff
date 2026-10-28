#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step84: trace resource-read path of second-layer guard (06004523/4524/4528).
Goal: which resource holds the SHA1 hashtable, and via which helper."""
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

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            return '06:' + str(md.MethodDef.rows[r - 1].Name)
        if t == 0x0A:
            row = md.MemberRef.rows[r - 1]
            cn = '?'
            try:
                c = row.Class
                r2 = c.row if hasattr(c, 'row') else c
                if hasattr(r2, 'TypeName'):
                    cn = (str(r2.TypeNamespace) + '.' if str(r2.TypeNamespace) else '') + str(r2.TypeName)
                elif hasattr(r2, 'Name'):
                    cn = str(r2.Name)
            except Exception:
                pass
            return '0A:' + cn + '::' + str(row.Name)
    except Exception as e:
        return '%s:<err>' % hex(tok)
    return hex(tok)

def body(tok):
    cl, pos = idx[tok]
    return il[pos:pos + cl]

def scan(tok, label):
    b = body(tok)
    ins = parse(b)
    print('=== %s tok=%s len=%d ins=%d' % (label, hex(tok), len(b), len(ins)))
    calls = {}
    for e in ins:
        if e[1] in ('call', 'callvirt', 'newobj'):
            t = struct.unpack_from('<I', b, e[0] + 1)[0]
            calls[t] = calls.get(t, 0) + 1
    hits = 0
    for t in sorted(calls):
        n = mname(t)
        low = n.lower()
        if any(k in low for k in ('resource', 'stream', 'assembly', 'sha', 'hash', 'crypto', 'manifest')):
            print('  CALL %s x%d -> %s' % (hex(t), calls[t], n))
            hits += 1
    for e in ins:
        if e[1] == 'ldstr':
            t = struct.unpack_from('<I', b, e[0] + 1)[0]
            print('  LDSTR@%04x %r' % (e[0], usdec(t)))
    print('  [calls uniq=%d hits=%d]' % (len(calls), hits))
    return calls

c23 = scan(0x06004523, '4523 checker')
c24 = scan(0x06004524, '4524 entry')
c28 = scan(0x06004528, '4528 guard2')

fam = sorted(t for t in c28 if (t >> 24) == 0x06 and 0x06007700 <= t <= 0x060078FF)
print('=== 4528 helper family 0600 77xx/78xx (%d)' % len(fam))
for t in fam:
    print('  %s %s' % (hex(t), mname(t)))
