#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step181: 全库找 'AirExplorer ' (name+' ') 异常构造方。
模式: ldstr ' ' (单空格) 或 'AirExplorer ' + newobj Exception/Concat + throw"""
import sys
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'

il = open(ALL, 'rb').read()
bodies = {}
order = []
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))
        order.append(int(p[0], 16))

pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

def mname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x06: return '0600%04x:%s' % (r, str(md.MethodDef.rows[r-1].Name))
        if t == 0x0A:
            m2 = md.MemberRef.rows[r-1]
            cn = m2.Class.row
            nm = getattr(cn, 'TypeName', None)
            full = (str(getattr(cn, 'TypeNamespace', '') or '') + '.' if nm else '') + str(nm or getattr(cn, 'Name', '?'))
            return '%s::%s' % (full, str(m2.Name))
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def sval(tok):
    try:
        s = pe.net.user_strings.get(tok & 0xFFFFFF)
        return str(s.value) if s and s.value is not None else None
    except Exception:
        return None

hits = []
for tok in order:
    c, p = bodies[tok]
    try:
        ins = list(parse(il[p:p+c]))
    except Exception:
        continue
    strs = [(o, sval(op)) for o, n, k, op, pl in ins if k == 'str' and isinstance(op, int) and (op >> 24) == 0x70]
    throws = [o for o, n, k, op, pl in ins if n in ('throw', 'rethrow')]
    news = [mname(op) for o, n, k, op, pl in ins if k == 'tok' and (op >> 24) == 0x2B and 'Exception' in mname(op)]
    has_name_call = any(k == 'tok' and 'get_Name' in mname(op) for o, n, k, op, pl in ins)
    interesting = [s for o, s in strs if s is not None and (s == ' ' or 'AirExplorer' in s or 'tamper' in s.lower())]
    if interesting and (throws or news):
        hits.append((tok, interesting, len(throws), news, has_name_call, len(ins)))

print('== methods with suspicious ldstr + throw/Exception-ctor ==')
for tok, strs, nt, news, hn, ni in hits:
    print('%06x ins=%d throws=%d name_call=%s strs=%r newobj=%s' % (tok, ni, nt, hn, strs, news))

# fallback: any method with ldstr == ' '
print('== all methods with ldstr " " ==')
cnt = 0
for tok in order:
    c, p = bodies[tok]
    try:
        ins = list(parse(il[p:p+c]))
    except Exception:
        continue
    for o, n, k, op, pl in ins:
        if k == 'str' and isinstance(op, int) and (op >> 24) == 0x70:
            s = sval(op)
            if s == ' ':
                cnt += 1
                if cnt <= 30:
                    has_throw = any(n2 in ('throw', 'rethrow') for o2, n2, k2, op2, pl2 in ins)
                    print('  %06x @%04x ldstr" " throw=%s' % (tok, o, has_throw))
                break
print('  total=%d' % cnt)
