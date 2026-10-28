#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step154: 428A callee census (dependency on 4192/419C/42AD) + reflective trigger of 428E."""
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
            m = md.MemberRef.rows[r-1]
            return '%s::%s' % (clsname(m.Class.row), str(m.Name))
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

# ---- 1) 428A callee census + key ldstr
c, p = bodies[0x0600428A]
ins = list(parse(il[p:p+c]))
print('===== 428A census (%d ins) =====' % len(ins))
cc = {}
for off, name, k, op, plen in ins:
    if k == 'tok' and name in ('call', 'callvirt', 'newobj') and (op >> 24) in (0x06, 0x0A):
        n = mname(op)
        cc.setdefault(n, []).append(off)
# show 4192/419C/41A8/41AA/41D8/41ED/41EE/42AD/41D3 etc + top MethodDefs
KEY = re = None
import re as _re
pat = _re.compile(r'004192|00419c|0041a8|0041aa|0041bf|0041d8|0041ed|0041ee|0042ad|0041d3|0042ac|0042af|0042b0|00428|004181|004196|004195|GetManifestResource|Load|Assembly|Resource|Hash|Verify|Transform|Decrypt|Rijndael|Aes|CreateDecryptor|FromXml|Stream|Read|Buffer|BlockCopy|MemoryStream|Binary', _re.I)
print('-- key callees:')
for n in sorted(cc):
    if pat.search(n):
        print('   %-60s @%s' % (n, ','.join('%04x' % x for x in cc[n][:8])))
print('-- top-20 MethodDef callees:')
mds = {n: v for n, v in cc.items() if n.startswith('06:')}
for n in sorted(mds, key=lambda x: -len(mds[x]))[:20]:
    print('   %-60s x%d @%s' % (n, len(mds[n]), ','.join('%04x' % x for x in mds[n][:5])))
print('-- ldstr:')
for off, name, k, op, plen in ins:
    if k == 'str':
        print('   @%04x %r' % (off, sval(op)[:80]))

# ---- 2) reflective trigger of 428E: ldtoken 0600428E / methodof / name string
print('\n===== 428E reflective trigger search =====')
for t, (c2, p2) in bodies.items():
    try:
        for off, name, k, op, plen in parse(il[p2:p2+c2]):
            if k == 'tok' and op == 0x0600428E:
                print('   ldtoken/ref %08x @%04x %s' % (t, off, name))
            if k == 'str':
                sv = sval(op)
                if sv and ('ValidateAccessibleResponderManager' in sv or 'WrapCommonSorter' in sv or 'InstantiateEnumerator' in sv or 'EncapsulateMixedDispatcher' in sv):
                    print('   name-str %08x @%04x %r' % (t, off, sv[:60]))
    except Exception:
        pass

# ---- 3) 42AD census (dispatcher): features + 4192/419C deps
c3, p3 = bodies[0x060042AD]
ins3 = list(parse(il[p3:p3+c3]))
print('\n===== 42AD census (%d ins) =====' % len(ins3))
cc3 = {}
for off, name, k, op, plen in ins3:
    if k == 'tok' and name in ('call', 'callvirt', 'newobj') and (op >> 24) in (0x06, 0x0A):
        cc3.setdefault(mname(op), []).append(off)
for n in sorted(cc3):
    if _re.search(r'00419|0041a|0041b|0041c|0041d|0041e|0041f|0042a|0042b', n):
        print('   %-56s @%s' % (n, ','.join('%04x' % x for x in cc3[n][:8])))
