# -*- coding: utf-8 -*-
"""step1A: extract runtime bodies of 06004555/0600448F from official memdump + v17 writers scan."""
import sys, struct, zipfile
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
            # TypeRef
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

mem = open('/workspace/repo_git/work_a1_pack/memdump/module_text.bin', 'rb').read()
print('memdump size', len(mem))
base_off = 0x2000  # mem[i] <-> RVA 0x2000+i

def rtbody(tok):
    rid = tok & 0xFFFFFF
    rva = md.MethodDef.rows[rid-1].Rva
    if not rva:
        return None, None, 'RVA=0'
    o = rva - base_off
    if o < 0 or o >= len(mem):
        return None, rva, 'out of range'
    b0 = mem[o]
    if (b0 & 3) == 2:  # tiny
        size = b0 >> 2
        il = mem[o+1:o+1+size]
        return il, rva, 'tiny %d' % size
    # fat
    flags = struct.unpack_from('<H', mem, o)[0]
    hsize = (flags >> 12) * 4
    csize = struct.unpack_from('<I', mem, o+4)[0]
    il = mem[o+hsize:o+hsize+csize]
    return il, rva, 'fat h=%d c=%d' % (hsize, csize)

def show(il, label):
    print('---- %s (%d B) ----' % (label, len(il) if il else 0))
    if not il: return
    for off, nm, opb, nxt, tg in disasm(il):
        ann = ''
        if nm in ('call', 'callvirt', 'newobj', 'ldfld', 'stfld', 'ldsfld', 'stsfld',
                  'castclass', 'isinst', 'ldstr', 'newarr', 'box', 'unbox.any', 'ldtoken'):
            if opb and len(opb) >= 4:
                ann = '  ; %s' % res(struct.unpack('<I', opb[:4])[0])
        print('%04X %-12s %-10s%s%s' % (off, nm, opb.hex(), ann,
              ' -> ' + ','.join('%04X' % t for t in tg) if tg else ''))

for tok in (0x06004555, 0x0600448F, 0x06004581, 0x06004566):
    il, rva, how = rtbody(tok)
    print('== 0x%08X rva=0x%X %s ==' % (tok, rva or 0, how))
    show(il, '0x%08X runtime body' % tok)

# ---- v17 (local 0x17) writers in 4528
z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
il28 = z.read('m_06004528.bin')[24:]
ins = disasm(il28)
idx = {o: i for i, (o, *_ ) in enumerate(ins)}

def ctx(i, n=8):
    out = []
    k = i - 1
    while k >= 0 and len(out) < n:
        out.append('%04X %s %s' % (ins[k][0], ins[k][1], ins[k][2].hex()))
        k -= 1
    return ' | '.join(reversed(out))

print('== v17 writers (fe.stloc 1700 / stloc.s 17) in 4528 ==')
n = 0
for i, (off, nm, opb, nxt, tg) in enumerate(ins):
    is17 = (nm == 'fe.stloc' and opb == b'\x17\x00') or (nm == 'stloc.s' and opb == b'\x17')
    if not is17: continue
    n += 1
    # what feeds it: look back until a ldloc/ldc
    feed = []
    k = i - 1
    while k >= 0 and len(feed) < 3:
        p = ins[k]
        feed.append('%s %s' % (p[1], p[2].hex()))
        if p[1].startswith('ldc') or p[1] == 'fe.ldloc' or p[1].startswith('ldloc'):
            break
        k -= 1
    print('  @%04X <- %s' % (off, ' | '.join(reversed(feed))))
print('total v17 writers:', n)
