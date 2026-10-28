#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step114b: name resolution for DispatcherInitializer fields + token check."""
import dnfile

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

# (1) DispatcherInitializer full field name list
tgt = None
for i, t in enumerate(md.TypeDef.rows):
    if t.TypeName == 'DispatcherInitializer':
        tgt = (i, t)
        break
i0, td = tgt
print('[DispatcherInitializer] typedef idx %d, fields:' % i0)
for row in td.FieldList:
    rid = row.row_index
    nm = str(row.row.Name) if hasattr(row, 'row') else str(row.Name)
    mark = ' <<<<' if rid == 0x1FCD else ''
    print('   0x%08x %r%s' % (0x04000000 | rid, nm, mark))

# (2) direct token check
print('\n[token check]')
f = md.Field.rows[0x1FCD - 1]
print('   0x04001FCD = %r' % (str(f.Name),))
sig = f.Signature.__bytes__() if hasattr(f.Signature, '__bytes__') else None
print('   sig=%s' % (sig.hex() if sig else '?'))
