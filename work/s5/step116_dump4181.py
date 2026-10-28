#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step116: dump 06004181 and 0600418b full IL (the _ExtractorVisitors writers)."""
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
        if t == 0x06:
            return '06:%06x:%s' % (r, md.MethodDef.rows[r-1].Name)
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]
            cls = m.Class.row
            cn = getattr(cls, 'TypeName', getattr(cls, 'Name', '?'))
            return '0A:%s::%s' % (cn, m.Name)
        if t == 0x04:
            return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def fname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    if t == 0x04:
        try: return 'fld:%06x:%s' % (r, md.Field.rows[r-1].Name)
        except Exception: return 'fld:%06x' % r
    try:
        if t == 0x06: return '06:%06x:%s' % (r, md.MethodDef.rows[r-1].Name)
        if t == 0x0A:
            m = md.MemberRef.rows[r-1]
            cls = m.Class.row
            return '0A:%s::%s' % (getattr(cls, 'TypeName', '?'), m.Name)
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

for tok in (0x06004181, 0x0600418b):
    clen, pos = bodies[tok]
    ins = list(parse(il[pos:pos+clen]))
    out = '/tmp/step116_%06x.txt' % (tok & 0xFFFFFF)
    with open(out, 'w') as f:
        for e in ins:
            off, name, k, op, plen = e
            ann = ''
            if k in ('tok', 'str'):
                ann = ' ' + fname(op)
            elif k == 'br4':
                ann = ' -> %04x' % op
            elif k == 'br1':
                ann = ' -> %04x' % op
            elif k == 'sw':
                ann = ' -> ' + ','.join('%04x' % t for t in op)
            f.write('%04x %s%s\n' % (off, name, ann))
    print('[%08x] size=%d ins=%d -> %s' % (tok & 0xFFFFFF, clen, len(ins), out))
    # quick: print windows around the stsfld sites
    for e in ins:
        if e[1] == 'stsfld' and e[2] == 'tok' and (e[3] & 0xFFFFFF) in (0x1FD0, 0x1FCD):
            o = e[0]
            print('  --- window around stsfld @%04x ---' % o)
            idx = [i for i, x in enumerate(ins) if x[0] == o][0]
            for x in ins[max(0, idx-14):idx+4]:
                off, name, k, op, plen = x
                ann = fname(op) if k in ('tok', 'str') else ''
                print('     %04x %s %s' % (off, name, ann))
