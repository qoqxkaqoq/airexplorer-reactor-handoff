#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step137b: fix ldstr read + dissect 41C9-41F2 stub family (SHA1/AES hiding place?)."""
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
us = pe.net.user_strings

def sval(tok):
    try:
        s = us.get(tok & 0xFFFFFF)
        return str(s.value) if s and s.value is not None else '?'
    except Exception as e:
        return '<err %s>' % e

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
        if t == 0x2B: return 'mspec:%06x' % r
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

# 1) 4192 ldstr fixed
clen, pos = bodies[0x06004192]
ins = list(parse(il[pos:pos+clen]))
print('[4192] ldstr (fixed):')
for off, name, k, op, plen in ins:
    if k == 'str':
        print('   @%04x ldstr 0x%08x %r' % (off, op, sval(op)[:100]))

# 2) stub family 41C9..41F2: size + crypto calls + inner callees
pat = re.compile(r'Hash|SHA|MD5|Crypto|Rijndael|Aes|HMAC|Compute|Transform|Cipher|Verify|Signature|FromXml|Convert', re.I)
print('\n[2] stub family 41c9..41f2:')
for rid in range(0x41C9, 0x41F3):
    tok = 0x06000000 | rid
    if tok not in bodies:
        print('   06:%06x  NOT-IN-INDEX' % rid)
        continue
    c, p = bodies[tok]
    body = il[p:p+c]
    sins = list(parse(body))
    crypto = []
    callees = {}
    flds = []
    for off, name, k, op, plen in sins:
        if k == 'tok' and name in ('call', 'callvirt', 'newobj'):
            n = mname(op)
            if pat.search(n): crypto.append('@%04x %s %s' % (off, name, n))
            callees.setdefault(n, 0)
            callees[n] += 1
        if k == 'tok' and name in ('ldsfld', 'stsfld', 'ldsflda'):
            flds.append('@%04x %s %s' % (off, name, mname(op)))
    print('   06:%06x clen=%-6d ins=%-5d crypto=%d' % (rid, c, len(sins), len(crypto)))
    for x in crypto[:8]: print('        ' + x)
    if flds:
        for x in flds[:8]: print('        ' + x)

# 3) 41ED/41EE bodies (known) + what HashAlgorithm type m_ExtendedSchemaTemplate is
for rid in (0x41ED, 0x41EE):
    tok = 0x06000000 | rid
    if tok in bodies:
        c, p = bodies[tok]
        print('\n[3] 06:%06x clen=%d' % (rid, c))
        for off, name, k, op, plen in parse(il[p:p+c]):
            ann = ' ' + mname(op) if k == 'tok' else (' %d' % op if k in ('var','b') else '')
            print('   @%04x %s%s' % (off, name, ann))
