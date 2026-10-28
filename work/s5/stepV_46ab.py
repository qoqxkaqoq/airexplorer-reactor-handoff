# -*- coding: utf-8 -*-
"""stepV: extract 060046AB chain from official memdump (mem[i] <-> RVA 0x2000+i)."""
import struct, sys, zipfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm

MEM = '/workspace/repo_git/work_a1_pack/memdump/module_text.bin'
mem = open(MEM, 'rb').read()

import dnfile
pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables
names = {}
for line in open('/workspace/repo_git/work/c2_pack/bodies_manifest.tsv'):
    p = line.rstrip('\n').split('\t')
    if len(p) >= 3 and p[1].startswith('0600'):
        names[p[1]] = p[2]

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')

def body_from_mem(rva):
    i = rva - 0x2000
    b0 = mem[i]
    if (b0 & 3) == 2:
        size = b0 >> 2
        return 'tiny', size, mem[i+1:i+1+size]
    fs = struct.unpack_from('<H', mem, i)[0]
    hsize = (fs >> 12) * 4
    size = struct.unpack_from('<I', mem, i+4)[0]
    loctok = struct.unpack_from('<I', mem, i+8)[0]
    return 'fat', size, mem[i+hsize:i+hsize+size], loctok

def mref(tok):
    t24 = tok & 0xFFFFFF
    k = tok >> 24
    if k == 0x0A:
        r = md.MemberRef.rows[t24-1]
        c = r.Class.row
        try:
            return '%s.%s::%s' % (c.TypeNamespace.value, c.TypeName.value, r.Name.value)
        except Exception:
            return 'MR %08x' % tok
    if k == 0x06:
        return 'MD 0600%x(%s)' % (t24, names.get('0600%x' % t24, '?'))
    if k == 0x04:
        return 'Fld %08x' % tok
    if k == 0x01:
        try:
            r = md.TypeRef.rows[t24-1]
            return 'TR %s.%s' % (r.TypeNamespace.value, r.TypeName.value)
        except Exception:
            return 'TR %08x' % tok
    if k == 0x02:
        try:
            r = md.TypeDef.rows[t24-1]
            return 'TD %s.%s' % (r.TypeNamespace.value, r.TypeName.value)
        except Exception:
            return 'TD %08x' % tok
    if k == 0x72:
        return 'US %08x' % tok
    return '%02x-%08x' % (k, tok)

seen = []
def dump_chain(tok, depth=0, maxdepth=2):
    rid = tok & 0xFFFFFF
    row = md.MethodDef.rows[rid-1]
    rva = row.Rva
    kind = body_from_mem(rva)
    il = kind[2]
    ind = '  ' * depth
    print('%s=== 0600%05X (%s) rva=0x%x %s ilsize=%d ===' % (ind, rid, names.get('0600%x' % rid, '?'), rva, kind[0], len(il)))
    if len(il) > 400:
        print('%s  (large body, head only)' % ind)
        rng = disasm(il)
        cnt = 0
        for o, name, opb, no, tg in rng:
            ann = ''
            if name in ('call', 'callvirt', 'newobj', 'ldstr', 'ldfld', 'stfld', 'ldsfld', 'stsfld', 'castclass', 'isinst') and opb:
                t = struct.unpack('<I', opb)[0]
                ann = ' ; ' + mref(t)
            print('%s  IL_%04x: %-14s %-12s%s' % (ind, o, name, opb.hex() if opb else '', ann))
            cnt += 1
            if cnt > 60:
                print('%s  ...(%d instr total)' % (ind, len(rng)))
                break
        return
    for o, name, opb, no, tg in disasm(il):
        ann = ''
        if name in ('call', 'callvirt', 'newobj', 'ldfld', 'stfld', 'ldsfld', 'stsfld', 'castclass', 'isinst', 'ldstr') and opb:
            t = struct.unpack('<I', opb)[0]
            ann = ' ; ' + mref(t)
        print('%s  IL_%04x: %-14s %-12s%s' % (ind, o, name, opb.hex() if opb else '', ann))
        if name in ('call', 'callvirt', 'newobj') and opb and (struct.unpack('<I', opb)[0] >> 24) == 6 and depth < maxdepth:
            t = struct.unpack('<I', opb)[0]
            if t != tok and '0600%x' % (t & 0xFFFFFF) not in [s for s in seen]:
                pass

dump_chain(0x060046AB, 0, 1)
