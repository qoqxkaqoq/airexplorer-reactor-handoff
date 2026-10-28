#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step137: dissect 4192 SHA1 chain — all crypto-related MemberRef calls + data flow windows."""
import sys, re
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
        if t == 0x06: return '06:%06x:%s' % (r, md.MethodDef.rows[r-1].Name)
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]
            cls = m.Class.row
            cn = getattr(cls, 'TypeName', getattr(cls, 'Name', '?'))
            ns = getattr(cls, 'TypeNamespace', '')
            return '0A:%s%s::%s' % (ns + '.' if ns else '', cn, m.Name)
        if t == 0x04: return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        if t == 0x01: return 'tspec:%06x' % r
        if t == 0x02: return 'tdef:%06x' % r
        if t == 0x2B: return 'mspec:%06x' % r
        if t == 0x11: return 'stsig:%06x' % r
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

clen, pos = bodies[0x06004192]
ins = list(parse(il[pos:pos+clen]))
print('[4192] clen=%d ins=%d' % (clen, len(ins)))

# 1) crypto-related calls
pat = re.compile(r'Hash|SHA|MD5|Crypto|Rijndael|Aes|AES|HMAC|Key|Transform|Compute|Cipher|Verify|Signature|Encoding|ToBase64|FromXml', re.I)
print('\n[1] crypto-ish call sites:')
for off, name, k, op, plen in ins:
    if k == 'tok' and (name in ('call', 'callvirt', 'newobj')):
        n = mname(op)
        if pat.search(n):
            print('   @%04x %s %s' % (off, name, n))

# 2) ldstr in 4192
print('\n[2] ldstr sites:')
for off, name, k, op, plen in ins:
    if k == 'str':
        # read #US heap
        try:
            us = pe.net.user_strings.get(op)
            s = us.value if us else '?'
        except Exception:
            s = '?'
        print('   @%04x ldstr 0x%08x %r' % (off, op, s[:80] if s else s))

# 3) ldsfld/stsfld field table (state IO)
print('\n[3] stsfld sites (writers):')
for off, name, k, op, plen in ins:
    if k == 'tok' and name == 'stsfld':
        print('   @%04x stsfld %s' % (off, mname(op)))

# 4) all unique called MethodDefs (0x06) — for closure context
mds = {}
for off, name, k, op, plen in ins:
    if k == 'tok' and name in ('call', 'callvirt', 'newobj') and (op >> 24) == 0x06:
        mds.setdefault(op, []).append(off)
print('\n[4] unique MethodDef callees (%d):' % len(mds))
for tok in sorted(mds):
    print('   %s  sites@%s' % (mname(tok), ','.join('%04x' % x for x in mds[tok][:6])))
