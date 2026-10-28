# -*- coding: utf-8 -*-
"""step6: resolve MemberRef/TypeRef/Field tokens + helper bodies for GAE catch."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def type_name(t):
    if t is None:
        return '(none)'
    try:
        ns, nm = str(t.TypeNamespace), str(t.TypeName)
        return ('%s.%s' % (ns, nm)) if ns else nm
    except Exception:
        return '?'

def memberref(tok):
    r = md.MemberRef.rows[(tok & 0xFFFFFF) - 1]
    cls = r.Class
    tn = type_name(cls.row) if cls and cls.row else '?'
    return '%s::%s' % (tn, str(r.Name))

def typedef_of_method(rid):
    for ti, t in enumerate(md.TypeDef.rows):
        for mi in t.MethodList:
            if mi.row_index == rid:
                return ti + 1
    return None

def full_method(tok):
    rid = tok & 0xFFFFFF
    r = md.MethodDef.rows[rid - 1]
    ti = typedef_of_method(rid)
    t = md.TypeDef.rows[ti - 1]
    return '%s.%s::%s' % (str(t.TypeNamespace), str(t.TypeName), str(r.Name))

def fieldref(tok):
    r = md.Field.rows[(tok & 0xFFFFFF) - 1]
    return str(r.Name)

print('== MemberRefs ==')
for tok in (0x0a000a62, 0x0a000a63, 0x0a000a64, 0x0a000a67, 0x0a000a66, 0x0a000a49, 0x0a000a4d, 0x0a000a4e, 0x0a000a65, 0x0a00008f, 0x0a000a67):
    try:
        print('  %08x %s' % (tok, memberref(tok)))
    except Exception as e:
        print('  %08x ERR %s' % (tok, e))

print('== TypeRef 0x01000080 ==')
try:
    r = md.TypeRef.rows[0x80 - 1]
    print('  %s' % type_name(r))
except Exception as e:
    print('  ERR', e)

print('== Fields ==')
for f in (0x04002030, 0x04002032, 0x04002036, 0x04002037, 0x0400204a, 0x0400204c, 0x0400204d, 0x0400204e, 0x04002053, 0x04002069, 0x04002068, 0x04002145, 0x04002048, 0x04002012):
    try:
        print('  %08x %s' % (f, fieldref(f)))
    except Exception as e:
        print('  %08x ERR %s' % (f, e))

print('== helper methods ==')
for tok in (0x06004521, 0x06004524, 0x06004526, 0x06004527, 0x0600457e, 0x0600457f, 0x060046ac, 0x06004546, 0x06004527):
    try:
        rid = tok & 0xFFFFFF
        r = md.MethodDef.rows[rid - 1]
        print('  %08x rva=0x%x %s' % (tok, r.Rva, full_method(tok)))
    except Exception as e:
        print('  %08x ERR %s' % (tok, e))

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}
for tok in ('06004521', '06004524', '06004526', '06004527', '0600457e', '0600457f', '060046ac'):
    k = 'm_' + tok + '.bin'
    print('  dump %s: %s' % (tok, 'YES' if k in names else 'no'))
