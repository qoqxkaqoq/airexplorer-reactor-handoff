# -*- coding: utf-8 -*-
"""stepW: enumerate all P/Invoke (ImplMap) entries -> shim requirements."""
import dnfile
pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables
im = md.ImplMap
if im is None:
    print('no ImplMap'); raise SystemExit
scopes = {}
for r in im.rows:
    scope = r.ImportScope.row.Name.value if r.ImportScope and r.ImportScope.row else '?'
    fn = r.ImportName.value if r.ImportName else '?'
    cc = r.MappingFlags
    scopes.setdefault(scope, []).append((fn, str(cc)))
for s, fns in sorted(scopes.items()):
    print('=== scope:', s, '(%d funcs)' % len(fns))
    for fn, cc in fns:
        print('   ', fn, cc)
