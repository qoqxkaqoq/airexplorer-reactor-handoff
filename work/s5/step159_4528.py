#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step159: resolve gspec 0x2B000170 (42AD trampoline target) + 4528 census (input sources)."""
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

# ---- 1) MethodSpec 0x2B000170 -> MethodDef
try:
    ms = md.MethodSpec.rows[0x170 - 1]
    m = ms.Method.row
    print('[gspec 0x2B000170] Method table=%s rid=%s' % (type(m).__name__, getattr(m, 'row_index', '?')))
    if hasattr(m, 'Name'):
        owner = ''
        try:
            # find owner type
            rid = m.row_index
            for td in md.TypeDef.rows:
                for mm in (td.MethodList or []):
                    if mm.row_index == rid:
                        owner = str(td.TypeName)
                        break
        except Exception:
            pass
        print('  -> %s::%s' % (owner, str(m.Name)))
except Exception as e:
    print('[gspec resolve fail]', e)

def clsname(cls):
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
            return '06:%06x:%s' % (r, str(md.MethodDef.rows[r-1].Name))
        if t == 0x0A:
            m2 = md.MemberRef.rows[r-1]
            return '%s::%s' % (clsname(m2.Class.row), str(m2.Name))
        if t == 0x04:
            return 'fld:%06x:%s' % (r, str(md.Field.rows[r-1].Name))
        if t == 0x01:
            return 'T:%s' % str(md.TypeRef.rows[r-1].TypeName)
        if t == 0x02:
            return 'TD%06x:%s' % (r, str(md.TypeDef.rows[r-1].TypeName))
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def sval(tok):
    try:
        s = pe.net.user_strings.get(tok & 0xFFFFFF)
        return str(s.value) if s and s.value is not None else '?'
    except Exception:
        return '?'

# ---- 2) 4528 owner + census
tok = 0x06004528
rid = tok & 0xFFFFFF
own = '?'
for td in md.TypeDef.rows:
    try:
        for mm in (td.MethodList or []):
            if mm.row_index == rid:
                own = str(td.TypeNamespace) + '.' + str(td.TypeName)
                break
    except Exception:
        pass
    if own != '?':
        break
nm = str(md.MethodDef.rows[rid-1].Name)
print('\n[4528 owner] %s :: %s' % (own, nm))

c, p = bodies[tok]
ins = list(parse(il[p:p+c]))
print('[4528] clen=%d ins=%d' % (c, len(ins)))

import re as _re
pat = _re.compile(r'Hash|SHA|Crypto|Transform|Compute|Verify|File|Stream|Read|Location|Resource|Assembly|Length|Exists|41e|41d|419|42a|42b|GetManifest|Buffer|BlockCopy', _re.I)
cc = {}
for off, name, k, op, plen in ins:
    if k == 'tok' and name in ('call', 'callvirt', 'newobj') and (op >> 24) in (0x06, 0x0A):
        n = mname(op)
        cc.setdefault(n, []).append(off)
print('-- key callees:')
for n in sorted(cc):
    if pat.search(n):
        print('   %-58s x%d @%s' % (n, len(cc[n]), ','.join('%04x' % x for x in cc[n][:6])))
print('-- all MethodDef callees:')
for n in sorted(n for n in cc if n.startswith('06:')):
    print('   %-58s x%d @%s' % (n, len(cc[n]), ','.join('%04x' % x for x in cc[n][:6])))
print('-- ldstr:')
for off, name, k, op, plen in ins:
    if k == 'str':
        print('   @%04x %r' % (off, sval(op)[:70]))
