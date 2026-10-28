#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step167: whole-exe hash-related scan:
(1) xref 060041ED; (2) all call/ldfld ComputeHash/get_Hash/Create MemberRefs;
(3) ldstr containing SHA/MD5/Crypto/Hash/Assembly/Location (file-hash input hints)."""
import sys, re
sys.path.insert(0, '/workspace/repo_git/work')
from flat import parse
import dnfile

IDX = '/workspace/repo_git/work/s5/mem5/il_index.tsv'
ALL = '/workspace/repo_git/work/s5/mem5/il_all.bin'
EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'

il = open(ALL, 'rb').read()
bodies = {}
names = {}
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))
        names[int(p[0], 16)] = '%s::%s' % (p[2], p[3])

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

print('== (1) xref 060041ED VerifyVirtualMatcher ==')
x41 = []
print('== (2) hash-ish MemberRef call sites ==')
HASHRE = re.compile(r'ComputeHash|get_Hash|HashCore|HashFinal|::Create|get_Location|GetTickCount|VerifyHash', re.I)
hits = {}   # memberref-name -> list of (tok, off)
for tok in sorted(bodies):
    c, p = bodies[tok]
    try:
        ins = list(parse(il[p:p+c]))
    except Exception:
        continue
    for off, name, k, op, plen in ins:
        if k == 'tok' and name in ('call', 'callvirt', 'newobj') and (op >> 24) in (0x06, 0x0A):
            tn = op & 0xFFFFFF
            if op >> 24 == 0x06 and tn == 0x0041ed:
                x41.append((tok, off))
            if (op >> 24) == 0x0A:
                full = mname(op)
                if HASHRE.search(full.split('::')[-1]) and not full.startswith('System.Runtime'):
                    hits.setdefault(full, []).append((tok, off))
for tok, off in x41:
    print('  41ED <- %s @%04x' % (names.get(tok, '%06x' % tok), off))
print('  total 41ED refs: %d' % len(x41))
print()
for full in sorted(hits):
    sites = hits[full]
    print('  %-70s x%d: %s' % (full, len(sites), ', '.join('%s@%04x' % (names.get(t, '%06x' % t)[:44], o) for t, o in sites[:6])))
print()
print('== (3) ldstr crypto/assembly hints ==')
SRE = re.compile(r'SHA|MD5|Crypto|HashAlgorithm|\$asm|\.exe$|\.dll$|Assembly', re.I)
shits = {}
for tok in sorted(bodies):
    c, p = bodies[tok]
    try:
        ins = list(parse(il[p:p+c]))
    except Exception:
        continue
    for off, name, k, op, plen in ins:
        if k == 'str':
            v = sval(op)
            if SRE.search(v):
                shits.setdefault(v[:70], []).append('%s@%04x' % (names.get(tok, '%06x' % tok)[:44], off))
for v in sorted(shits):
    print('  %r x%d: %s' % (v, len(shits[v]), ', '.join(shits[v][:5])))
