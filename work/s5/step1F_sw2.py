# -*- coding: utf-8 -*-
"""step1F: main switch casemap of 4528 + second-level switch value + GAE V_8 writers."""
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

# all switches
sws = [(o, tg) for o, nm, opb, nxt, tg in ins if nm == 'switch']
print('switches in 4528:', [(hex(o), len(tg)) for o, tg in sws])
SW1 = 0x16
SW2 = 0x45B1
cm1 = dict()
for k, t in enumerate(dict(sws)[SW1]): cm1.setdefault(t, []).append(k)
cm2 = dict()
for k, t in enumerate(dict(sws)[SW2]): cm2.setdefault(t, []).append(k)
print('SW1(0x16): case35 -> %s case34 -> %s case143 -> %s' % (
    [hex(t) for t, ks in cm1.items() if 35 in ks],
    [hex(t) for t, ks in cm1.items() if 34 in ks],
    [hex(t) for t, ks in cm1.items() if 143 in ks]))
print('SW2(0x45B1): case35 -> %s case34 -> %s case28 -> %s' % (
    [hex(t) for t, ks in cm2.items() if 35 in ks],
    [hex(t) for t, ks in cm2.items() if 34 in ks],
    [hex(t) for t, ks in cm2.items() if 28 in ks]))

# what value feeds SW2: disasm 0x4560..0x45B8
print('---- 4528 disasm 0x4560..0x45B8 (before SW2) ----')
for off, nm, opb, nxt, tg in ins:
    if 0x4560 <= off < 0x45B8:
        ann = ''
        if nm in ('call','callvirt','newobj','ldfld','stfld','ldsfld','isinst','castclass') and opb and len(opb) >= 4:
            ann = '  ; %s' % res(struct.unpack('<I', opb[:4])[0])
        print('%04X %-12s %-10s%s%s' % (off, nm, opb.hex(), ann, ' -> ' + ','.join('%04X' % t for t in tg) if tg else ''))

# where do 0x3522's SW2-predecessors come from: who jumps to SW2 dispatch (0x45B1)
tgt = {}
for off, nm, opb, nxt, tg in ins:
    for t in tg:
        tgt.setdefault(t, []).append((off, nm))
print('who jumps into SW2 area 0x45B1:', tgt.get(0x45B1))

# ---- GAE V_8 writers
il23 = z.read('m_06004523.bin')[24:]
ins23 = disasm(il23)
print('== GAE V_8 (local 08) writers + V_8 readers ==')
for ii, (off, nm, opb, nxt, tg) in enumerate(ins23):
    w = (nm == 'stloc.s' and opb == b'\x08') or (nm == 'fe.stloc' and opb == b'\x08\x00')
    r = (nm == 'ldloc.s' and opb == b'\x08') or (nm == 'fe.ldloc' and opb == b'\x08\x00')
    if not (w or r): continue
    ctx = []
    k = ii - 3 if w else ii - 1
    end = ii if w else ii + 2
    j = max(0, k)
    while j < min(len(ins23), end + 1):
        p = ins23[j]
        ctx.append('%04X %s %s' % (p[0], p[1], p[2].hex()))
        j += 1
    print('  %s @%04X: %s' % ('W' if w else 'R', off, ' | '.join(ctx)))

# GAE disasm 0x640..0x6E0 (V_8 true path + tail)
print('---- GAE 0x640..0x727 ----')
for off, nm, opb, nxt, tg in ins23:
    if 0x640 <= off < 0x728:
        ann = ''
        if nm in ('call','callvirt','newobj','ldfld','stfld','ldsfld','isinst','castclass') and opb and len(opb) >= 4:
            ann = '  ; %s' % res(struct.unpack('<I', opb[:4])[0])
        print('%04X %-12s %-10s%s%s' % (off, nm, opb.hex(), ann, ' -> ' + ','.join('%04X' % t for t in tg) if tg else ''))
