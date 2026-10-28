# -*- coding: utf-8 -*-
"""step1E: correct EH parse for 4528 + predecessors of 0x6996 + GAE 0x46D routing."""
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

mem = open('/workspace/repo_git/work_a1_pack/memdump/module_text.bin', 'rb').read()
BASE = 0x2000

def eh_clauses(tok):
    rid = tok & 0xFFFFFF
    rva = md.MethodDef.rows[rid-1].Rva
    o = rva - BASE
    flags = struct.unpack_from('<H', mem, o)[0]
    hsize = (flags >> 12) * 4
    csize = struct.unpack_from('<I', mem, o+4)[0]
    so = (o + hsize + csize + 3) & ~3
    b0 = mem[so]
    assert b0 & 0x40, 'not fat section: %02X' % b0
    size = (struct.unpack_from('<I', mem, so)[0] >> 8) & 0x00FFFFFF
    n = (size - 4) // 24
    out = []
    for k in range(n):
        f, tryo, tryl, ho, hl, ct = struct.unpack_from('<IIIIII', mem, so + 4 + 24*k)
        out.append((f, tryo, tryl, ho, hl, ct))
    return out, rva

for tok in (0x06004528, 0x06004523):
    cls, rva = eh_clauses(tok)
    print('== %08X rva=0x%X: %d EH clauses' % (tok, rva, len(cls)))
    for (f, tryo, tryl, ho, hl, ct) in cls:
        kind = 'FIN' if f & 4 else ('FILT' if f & 1 else 'TYPED')
        print('   flags=%X %s try=[%04X..%04X) handler=[%04X..%04X) tok=%08X %s' % (
            f, kind, tryo, tryo+tryl, ho, ho+hl, ct, res(ct) if ct else ''))

# ---- trap/case35 coverage in 4528
z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
il28 = z.read('m_06004528.bin')[24:]
ins = disasm(il28)
idx = {o: i for i, (o, *_ ) in enumerate(ins)}
PAT = bytes.fromhex('738F4400067A')
traps = []
p = 0
while True:
    j = il28.find(PAT, p)
    if j < 0: break
    traps.append(j); p = j + 1
cls28, _ = eh_clauses(0x06004528)
def in_try(o):
    return [ (f, t, t+l, h) for (f, t, l, h, hl, ct) in cls28 if t <= o < t+l ]
covered = sum(1 for o in traps if in_try(o))
print('== 4528: %d/%d traps inside a try; case35@0x3522 try=%s; case34@0x5E0C try=%s' % (
    covered, len(traps), in_try(0x3538), in_try(0x5E12)))
print('   v17=35 writer @0x69AD in try: %s' % in_try(0x69AD))
for (f, t, l, h, hl, ct) in cls28:
    print('   clause try=[%04X..%04X) h=[%04X..%04X) flags=%X tok=%08X' % (t, t+l, h, h+hl, f, ct))

# ---- predecessors of 0x6996
tgt = {}
for off, nm, opb, nxt, tg in ins:
    for t in tg:
        tgt.setdefault(t, []).append((off, nm))
print('== predecessors of 0x6996:', tgt.get(0x6996))
print('== predecessors of 0x3522:', tgt.get(0x3522))

# ---- GAE 0x540..0x640 (routing to 0x46D) and 0x1B0..0x200
il23 = z.read('m_06004523.bin')[24:]
ins23 = disasm(il23)
print('---- GAE 0x1A0..0x210 ----')
for off, nm, opb, nxt, tg in ins23:
    if 0x1A0 <= off < 0x210:
        ann = '  ; %s' % res(struct.unpack('<I', opb[:4])[0]) if (nm in ('call','callvirt','newobj','stfld','ldfld','isinst','castclass','ldsfld') and opb and len(opb)>=4) else ''
        print('%04X %-12s %-10s%s%s' % (off, nm, opb.hex(), ann, ' -> ' + ','.join('%04X' % t for t in tg) if tg else ''))
print('---- GAE 0x530..0x680 ----')
for off, nm, opb, nxt, tg in ins23:
    if 0x530 <= off < 0x680:
        ann = '  ; %s' % res(struct.unpack('<I', opb[:4])[0]) if (nm in ('call','callvirt','newobj','stfld','ldfld','isinst','castclass','ldsfld') and opb and len(opb)>=4) else ''
        print('%04X %-12s %-10s%s%s' % (off, nm, opb.hex(), ann, ' -> ' + ','.join('%04X' % t for t in tg) if tg else ''))
