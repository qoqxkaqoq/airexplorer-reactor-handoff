#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""step124: resolve MethodSpec 0x2B000170 -> target method."""
import dnfile

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables

ms = md.MethodSpec.rows[0x170 - 1]
mth = ms.Method  # MethodDefOrRef coded index
print('[MethodSpec 0x170] Method.table=%s row_index=%s' % (
    getattr(mth, 'table', '?'), getattr(mth, 'row_index', '?')))
row = getattr(mth, 'row', mth)
print('  Name=%r' % (str(row.Name),))
try:
    cls = row.Class.row
    print('  Class=%s.%s' % (getattr(cls, 'TypeNamespace', ''), getattr(cls, 'TypeName', getattr(cls, 'Name', '?'))))
except Exception as e:
    print('  Class: %s' % e)
