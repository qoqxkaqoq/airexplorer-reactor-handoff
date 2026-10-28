# -*- coding: utf-8 -*-
"""step22: locate DispatcherInitializer.VerifyProcessor token + inspect its dump body
(IL size, EH clauses, leave/endfinally placement) for the InvalidProgramException root cause."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

# find type CloudClient.Templating.DispatcherInitializer
target = None
for i, t in enumerate(md.TypeDef.rows):
    if str(t.TypeName) == 'DispatcherInitializer':
        print('TypeDef %08x %s.%s' % (0x02000000 + i + 1, str(t.TypeNamespace), str(t.TypeName)))
        target = (0x02000000 + i + 1, t)
        break

# list its methods
ti = target[0] & 0xFFFFFF
ml = target[1].MethodList
try:
    for k, m in enumerate(ml):
        row = m.row if hasattr(m, 'row') else m
        idx = m.row_index if hasattr(m, 'row_index') else None
        print('  idx %s name=%s' % (idx, str(row.Name)))
except Exception as e:
    print('iter fail', e, type(ml))
