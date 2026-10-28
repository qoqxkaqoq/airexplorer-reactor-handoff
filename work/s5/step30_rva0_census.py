# -*- coding: utf-8 -*-
"""step30: census of rva=0 non-abstract methods in baseline + call-site references
from injected dump bodies. Decides if m1b can be revived by in-place stubbing."""
import struct, os, dnfile

BASE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
BODIES = '/workspace/repo_git/work/c2_pack/bodies'

pe = dnfile.dnPE(BASE)
mdt = pe.net.mdtables
zero = []  # (rid, name, is_abstract, flags_enum)
for i, row in enumerate(mdt.MethodDef.rows):
    if row.Rva == 0:
        fl = row.Flags
        enumv = getattr(fl.mdAbstract, 'corhdr_enum', 0) if hasattr(fl, 'mdAbstract') else 0
        is_abstract = bool(enumv & 0x0400)
        zero.append((i + 1, str(row.Name), is_abstract, enumv))
na = [z for z in zero if not z[2]]
print('MethodDef total: %d | rva=0: %d | non-abstract rva=0: %d' % (len(mdt.MethodDef.rows), len(zero), len(na)))
ztokens = set(0x06000000 + z[0] for z in na)
print('non-abstract rva=0 tokens (first 20):', ' '.join('%08X' % t for t in sorted(ztokens)[:20]))

# scan dump bodies for refs (28/6F/73/2D? call/callvirt/newobj/ldftn=FE06/newobj 73; also 28)
OPC = {b'\x28': 'call', b'\x6F': 'callvirt', b'\x73': 'newobj', b'\x2D': 'constrained?'}
# ldftn = FE 06; ldvirtftn = FE 07
refs = {}
nfiles = 0
for fn in os.listdir(BODIES):
    if not fn.endswith('.bin'):
        continue
    d = open(os.path.join(BODIES, fn), 'rb').read()
    if len(d) < 24:
        continue
    tok, ilsize = struct.unpack('<II', d[:8])
    il = d[24:24 + ilsize]
    nfiles += 1
    i = 0
    while i < len(il) - 5:
        b = il[i:i + 1]
        if b in OPC:
            t = struct.unpack('<I', il[i + 1:i + 5])[0]
            if t in ztokens:
                refs.setdefault(t, []).append((tok, OPC[b]))
            i += 5
        elif il[i:i + 2] in (b'\xfe\x06', b'\xfe\x07'):
            t = struct.unpack('<I', il[i + 2:i + 6])[0]
            if t in ztokens:
                refs.setdefault(t, []).append((tok, 'ldftn'))
            i += 6
        else:
            i += 1
print('dump bodies scanned: %d' % nfiles)
print('rva=0 methods referenced from dump bodies: %d (unique tokens)' % len(refs))
total_sites = sum(len(v) for v in refs.values())
print('total call sites: %d' % total_sites)
for t in sorted(refs)[:20]:
    callers = set(c for c, _ in refs[t])
    print('  %08X sites=%d callers=%d e.g. %08X(%s)' % (t, len(refs[t]), len(callers), refs[t][0][0], refs[t][0][1]))
import json
json.dump({'%08X' % t: [[('%08X' % c), op] for c, op in v] for t, v in refs.items()},
          open('/workspace/repo_git/work/s5/step30_refs.json', 'w'))
print('refs written to work/s5/step30_refs.json')
