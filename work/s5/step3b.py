# -*- coding: utf-8 -*-
"""step3b: inheritance chain + MonitorStaticSingleton body + 452E switch + stloc02 sites."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

def tname(r):
    return '%s.%s' % (r.TypeNamespace, r.TypeName)

def typedef_by_method(rid):
    for ti, t in enumerate(md.TypeDef.rows):
        for mi in t.MethodList:
            if mi.row_index == rid:
                return ti + 1
    return None

# find ProgramFinder / ConnectedObserver / DistributorStrategy typedef rows
targets = {}
for ti, t in enumerate(md.TypeDef.rows):
    n = str(t.TypeName)
    if n in ('ProgramFinder', 'ConnectedObserver', 'DistributorStrategy', 'TemplateThread'):
        targets[n] = ti + 1
print('typedef rows:', targets)

for n, rid in sorted(targets.items()):
    t = md.TypeDef.rows[rid - 1]
    ext = t.Extends
    en = tname(ext.row) if ext and ext.row else '(none)'
    print('  %s (row %d) extends %s' % (n, rid, en))

# MonitorStaticSingleton + ControlBridge bodies
z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}
for tok in ('06004550', '06004559', '06004566'):
    k = 'm_' + tok + '.bin'
    if k in names:
        b = z.read(names[k])
        tokv, ilsize, maxstack, ehcnt, prex, loctok = struct.unpack('<6I', b[:24])
        print('== %s dump body ilsize=%d ==' % (tok, ilsize))
        for ins in disasm(b[24:24+ilsize]):
            print('  ' + fmt(ins))
    else:
        print('== %s NOT IN DUMP ==' % tok)

# 452E switch targets
b = z.read(names['m_0600452e.bin'])
il = b[24:]
print('== 452E switch targets ==')
for ins in disasm(il):
    if ins[1] == 'switch':
        cnt = len(ins[3]) // 4 - 1
        base = ins[4]
        for k in range(cnt):
            print('  case %d -> %04X' % (k, base + struct.unpack_from('<i', ins[3], 4 + 4*k)[0]))

# 4528 stloc 02 sites
b28 = z.read(names['m_06004528.bin'])
il28 = b28[24:]
print('== 4528 stloc 02 write sites ==')
for ins in disasm(il28):
    if ins[1] == 'stloc.s' and ins[3] == b'\x02':
        print('  %04X stloc.s 02' % ins[0])
    elif ins[1] == 'fe.stloc' and struct.unpack_from('<H', ins[3])[0] == 0x0200:
        print('  %04X stloc 02' % ins[0])
