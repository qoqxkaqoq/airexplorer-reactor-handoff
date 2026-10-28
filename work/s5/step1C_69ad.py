# -*- coding: utf-8 -*-
"""step1C: context around 0x69AD (the v17=35 writer) in 4528."""
import sys, struct, zipfile, bisect
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm
import dnfile

EXE = '/workspace/repo_git/exes/AirExplorer_baseline_verified.exe'
pe = dnfile.dnPE(EXE)
md = pe.net.mdtables
mtype = {}
for td in md.TypeDef.rows:
    for mr_ in (td.MethodList or []):
        try: mtype[mr_.row_index] = td.TypeName.value
        except Exception: pass

def res(tok):
    t, rid = tok & 0xFF000000, tok & 0xFFFFFF
    try:
        if t == 0x06000000:
            return 'M:%s::%s' % (mtype.get(rid, '?'), md.MethodDef.rows[rid-1].Name.value)
        if t == 0x0A000000:
            r = md.MemberRef.rows[rid-1]
            cn = '?'
            try: cn = r.Class.row.TypeName.value
            except Exception:
                try: cn = r.Class.row.Name.value
                except Exception: pass
            return 'R:%s::%s' % (cn, r.Name.value)
        if t in (0x07000000, 0x04000000):
            return 'F:%s' % md.Field.rows[rid-1].Name.value
        if t == 0x01000000:
            r = md.TypeRef.rows[rid-1]
            ns = ''
            try: ns = r.TypeNamespace.value
            except Exception: pass
            return 'TR:%s.%s' % (ns, r.TypeName.value)
        if t == 0x1B000000:
            return 'TypeSpec#%d' % rid
        if t == 0x02000000:
            return 'T:%s' % md.TypeDef.rows[rid-1].TypeName.value
    except Exception as e:
        return 'tok%08x(!%s)' % (tok, e)
    return 'tok%08x' % tok

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
il28 = z.read('m_06004528.bin')[24:]
ins = disasm(il28)
idx = {o: i for i, (o, *_ ) in enumerate(ins)}

# all branch targets (to know block structure)
tgt = {}
for off, nm, opb, nxt, tg in ins:
    for t in tg:
        tgt.setdefault(t, []).append((off, nm))

lo, hi = 0x68C0, 0x6A60
print('---- disasm %04X..%04X ----' % (lo, hi))
for off, nm, opb, nxt, tg in ins:
    if lo <= off < hi:
        ann = ''
        if nm in ('call', 'callvirt', 'newobj', 'ldfld', 'stfld', 'ldsfld', 'stsfld',
                  'castclass', 'isinst', 'newarr', 'box', 'unbox.any', 'ldtoken',
                  'ldftn', 'constrained.'):
            if opb and len(opb) >= 4:
                ann = '  ; %s' % res(struct.unpack('<I', opb[:4])[0])
        bt = ''
        if tg:
            bt = ' -> ' + ','.join('%04X' % t for t in tg)
        mark = ''
        for t in tg:
            if t in tgt and any(o2 not in (off,) for o2, _ in tgt[t]):
                pass
        print('%04X %-14s %-10s%s%s' % (off, nm, opb.hex(), ann, bt))
