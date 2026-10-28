#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step168: scan all 219 DispatcherInitializer methods for hash/verify features,
dump each hit method fully."""
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
tods = []
for line in open(IDX):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 5:
        bodies[int(p[0], 16)] = (int(p[1]), int(p[4]))
        names[int(p[0], 16)] = '%s::%s' % (p[2], p[3])
        if p[2] == 'CloudClient.Templating.DispatcherInitializer':
            tods.append(int(p[0], 16))

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

FEAT = re.compile(r'get_Location|ComputeHash|VerifyHash|get_Hash|ReadAllBytes|OpenRead|ReadBytes|get_CodeBase|GetManifestResource|get_EntryPoint|VerifyData|SignHash|Decrypt|ImportParameters', re.I)
SFEAT = re.compile(r'^SHA1$|AesCrypto|32\.dll|clrjit|\$asm|\.exe|\.dll$|tamper', re.I)

hits = []
for tok in sorted(tods):
    c, p = bodies[tok]
    try:
        ins = list(parse(il[p:p+c]))
    except Exception:
        continue
    marks = []
    for off, name, k, op, plen in ins:
        if k == 'tok' and name in ('call', 'callvirt', 'newobj', 'ldfld', 'ldsfld', 'stsfld') and (op >> 24) in (0x06, 0x0A, 0x04):
            f = mname(op)
            if FEAT.search(f.split('::')[-1]):
                marks.append('@%04x %s %s' % (off, name, f))
        elif k == 'str' and SFEAT.search(sval(op)):
            marks.append('@%04x ldstr %r' % (off, sval(op)[:50]))
    if marks:
        hits.append((tok, c, len(ins), marks))

print('== %d/%d DispatcherInitializer methods with features ==' % (len(hits), len(tods)))
for tok, c, n, marks in hits:
    print('%s (%dB, %d ins)' % (names[tok], c, n))
    for m in marks:
        print('   ' + m)
print()
print('== small hit methods full dump (<=120B) ==')
for tok, c, n, marks in hits:
    if c <= 120:
        cc, p = bodies[tok]
        ins = list(parse(il[p:p+cc]))
        print('---- %s (%dB) ----' % (names[tok], cc))
        for off, name, k, op, plen in ins:
            if k == 'tok': print('  @%04x %-10s %s' % (off, name, mname(op)))
            elif k == 'str': print('  @%04x %-10s %r' % (off, name, sval(op)[:60]))
            elif k == 'sw': print('  @%04x %-10s [%d tgts]' % (off, name, len(op)))
            else: print('  @%04x %-10s %s' % (off, name, ('%x' % op) if op is not None else ''))
