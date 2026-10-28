#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step137e: resolve the exact MemberRefs behind stub forwards + tamper block identity."""
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

def clsname(cls):
    # cls may be TypeDef/TypeRef/TypeSpec row
    tn = getattr(cls, 'TypeName', None)
    if tn is not None:
        ns = str(getattr(cls, 'TypeNamespace', '') or '')
        return (ns + '.' if ns else '') + str(tn)
    nm = getattr(cls, 'Name', None)
    return str(nm) if nm is not None else '<cls?>'

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06:
            return '06:%06x:%s' % (r, md.MethodDef.rows[r-1].Name)
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]
            return '0A:%06x %s::%s' % (r, clsname(m.Class.row), str(m.Name))
        if t == 0x04:
            return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        if t == 0x2B:
            ms = md.MethodSpec.rows[r-1]
            mt = ms.Method.row
            inner = getattr(mt, 'Class', None)
            s = 'mspec:%06x -> ' % r
            try:
                s += clsname(mt.Class.row) + '::' + str(mt.Name)
            except Exception:
                s += '%06x' % (mt.row_index if hasattr(mt, 'row_index') else 0)
            return s
        return '%02x:%06x' % (t, r)
    except Exception as e:
        return '%02x:%06x <%s>' % (t, r, e)

print('[tamper block tokens]')
for tok in (0x0A000996, 0x0A000997, 0x0A0009CF, 0x0A0009D0, 0x0A0009F0, 0x0A000252):
    print('  ', mname(tok))

print('\n[stub forward targets]')
for rid in (0x41cb, 0x41d0, 0x41cf, 0x41f0, 0x41f1, 0x41f2, 0x41d1, 0x41d2, 0x41d3, 0x41d4, 0x41d5,
            0x41c9, 0x41ca, 0x41cc, 0x41cd, 0x41ce, 0x41d6, 0x41d7, 0x41d8, 0x41d9, 0x41da,
            0x41db, 0x41dc, 0x41dd, 0x41de, 0x41df, 0x41e0, 0x41e1, 0x41e2, 0x41e3, 0x41e4,
            0x41e5, 0x41e6, 0x41e7, 0x41e8, 0x41e9, 0x41ea, 0x41eb, 0x41ec, 0x41ef):
    tok = 0x06000000 | rid
    if tok not in bodies:
        print('  06:%06x NOT-IN-INDEX' % rid); continue
    c, p = bodies[tok]
    calls = []
    for off, name, k, op, plen in parse(il[p:p+c]):
        if k == 'tok' and name in ('call', 'callvirt', 'newobj'):
            calls.append('%s %s' % (name, mname(op)))
    print('  06:%06x  %s' % (rid, ' | '.join(calls) if calls else '(no call)'))

# res5 block: 06004264 .ctor body (RandomDecryptor ctor) — what does it wrap?
print('\n[06004264 .ctor]')
c, p = bodies.get(0x06004264, (0, 0))
if c:
    for off, name, k, op, plen in parse(il[p:p+c]):
        ann = ' ' + mname(op) if k == 'tok' else (' %s' % op if k in ('br4','br1','var','b') else '')
        print('   @%04x %s%s' % (off, name, ann))
else:
    print('  NOT-IN-INDEX')

# TypeDef 0x622 info
td = md.TypeDef.rows[0x622 - 1]
mlist = td.MethodList
print('\n[02000622] %s.%s methods=%d' % (td.TypeNamespace, td.TypeName, len(mlist)))
