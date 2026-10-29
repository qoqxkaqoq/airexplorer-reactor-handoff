#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step182: 全库扫 newobj Exception 构造点（直连 System.Exception 及其子类），
打印每个命中点前 10 条指令（找 'AirExplorer ' 消息源：ldstr/Concat/get_Name/char 32）。"""
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

def tname(tok):
    t, r = tok >> 24, tok & 0xFFFFFF
    try:
        if t == 0x02:
            row = md.TypeDef.rows[r - 1]
            return '02:%06x:%s.%s' % (r, row.TypeNamespace, row.TypeName)
        if t == 0x01:
            row = md.TypeRef.rows[r - 1]
            return '01:%06x:%s.%s' % (r, row.TypeNamespace, row.TypeName)
        if t == 0x06:
            return '06:%06x:%s' % (r, md.MethodDef.rows[r - 1].Name)
        if t == 0x0A:
            m2 = md.MemberRef.rows[r - 1]
            cn = m2.Class.row
            nm = getattr(cn, 'TypeName', None) or getattr(cn, 'Name', '?')
            ns = str(getattr(cn, 'TypeNamespace', '') or '')
            return '0A:%06x:%s%s%s::%s' % (r, ns, '.' if ns else '', nm, m2.Name)
        if t == 0x04:
            return '04:%06x:%s' % (r, md.Field.rows[r - 1].Name)
        if t == 0x1B:
            return '1B:%06x:TypeSpec' % r
        return '%02x:%06x' % (t, r)
    except Exception:
        return '%02x:%06x' % (t, r)

def usval(tok):
    try:
        u = pe.net.user_strings.get(tok & 0xFFFFFF)
        if u is None:
            return None
        v = u.value
        return v.decode('utf-8', 'replace') if isinstance(v, (bytes, bytearray)) else str(v)
    except Exception:
        return None

# 1) System.Exception 直连 MemberRef ctor 集合
exc_refs = set()
for i, m2 in enumerate(md.MemberRef.rows, 1):
    try:
        cn = m2.Class.row
        tn = getattr(cn, 'TypeName', None)
        ns = str(getattr(cn, 'TypeNamespace', '') or '')
        if tn is not None and str(tn) == 'Exception' and ns == 'System':
            exc_refs.add(0x0A000000 | i)
    except Exception:
        pass
print('MemberRef Exception ctors: %d -> %s' % (len(exc_refs), sorted('%08x' % t for t in exc_refs)))

# 2) 子类 TypeDef（BaseType=Exception）的 ctor MethodDef 集合
sub_ctors = {}
for i, td in enumerate(md.TypeDef.rows, 1):
    try:
        bt = td.BaseType.row
        tn = str(getattr(bt, 'TypeName', ''))
        ns = str(getattr(bt, 'TypeNamespace', ''))
        if tn == 'Exception' and ns == 'System':
            sub_ctors[0x02000000 | i] = (ns + '.' + tn, td.Name)
    except Exception:
        pass
print('Exception subclasses (TypeDef): %d' % len(sub_ctors))
for t, (bt, nm) in sorted(sub_ctors.items()):
    print('  %08x %s : %s' % (t, nm, bt))

sub_ctor_meths = set()
for tt in sub_ctors:
    rid = tt & 0xFFFFFF
    td = md.TypeDef.rows[rid - 1]
    start = td.MethodList.row_index if td.MethodList else 0
    # dnfile: MethodList is a list of rows; walk
    try:
        for m in td.MethodList:
            r = m.row_index
            name = str(md.MethodDef.rows[r - 1].Name)
            if name in ('.ctor', '.cctor'):
                sub_ctor_meths.add(0x06000000 | r)
    except Exception:
        pass
print('subclass ctors (MethodDef): %d' % len(sub_ctor_meths))

# 3) 全库扫描
total = hits = parse_fail = 0
for tok in sorted(bodies):
    c, p = bodies[tok]
    total += 1
    try:
        ins = list(parse(il[p:p + c]))
    except Exception:
        parse_fail += 1
        continue
    for i, x in enumerate(ins):
        off, name, k, op, plen = x
        if name != 'newobj':
            continue
        isexc = op in exc_refs or op in sub_ctor_meths
        if not isexc:
            continue
        hits += 1
        print('---- HIT %s (newobj %s) ----' % (tname(tok), tname(op)))
        lo = max(0, i - 10)
        for y in ins[lo:i + 2]:
            yo, yn, yk, yo_op, ypl = y
            if yk == 'tok':
                print('  @%04x %-10s %s' % (yo, yn, tname(yo_op)))
            elif yk == 'str':
                v = usval(yo_op)
                print('  @%04x %-10s %r' % (yo, yn, v))
            elif yk == 'i':
                print('  @%04x %-10s %d (0x%x)' % (yo, yn, yo_op, yo_op & 0xFFFFFFFF))
            elif yk == 'b':
                print('  @%04x %-10s %d' % (yo, yn, yo_op))
            else:
                print('  @%04x %-10s' % (yo, yn))
print('== total bodies=%d parse_fail=%d exc_ctor_hits=%d ==' % (total, parse_fail, hits))
