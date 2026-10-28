# -*- coding: utf-8 -*-
"""stepZ: state machine dispatch analysis of 06004528."""
import sys, struct, zipfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt
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
            return 'TypeRef#%d' % rid
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

def show(lo, hi, label):
    print('---- %s ----' % label)
    for off, nm, opb, nxt, tg in ins:
        if lo <= off < hi:
            ann = ''
            if nm in ('call', 'callvirt', 'newobj', 'ldfld', 'ldsfld', 'stfld', 'stsfld',
                      'castclass', 'isinst', 'newarr', 'box', 'unbox.any', 'ldtoken',
                      'ldftn', 'ldvirtftn'):
                if opb:
                    tokv = struct.unpack('<I', opb[:4])[0] if len(opb) >= 4 else 0
                    ann = '  ; %s' % res(tokv)
            print('%04X %-12s %-10s%s%s' % (off, nm, opb.hex(), ann,
                  ' -> ' + ','.join('%04X' % t for t in tg) if tg else ''))

# ---- 1. dispatch head
show(0x0000, 0x0080, '4528 head 0..80')

# ---- 2. switch at 17841 (0x45B1)
SW = 17841
off, nm, opb, nxt, tg = ins[idx[SW]]
print('== switch @ %04X: %d cases' % (off, (len(opb)-4)//4))
casemap = {}
for i, t in enumerate(tg):
    casemap.setdefault(t, []).append(i)
print('distinct targets:', len(casemap))
for probe in (0x3522, 0x3539, 0x3550, 0x34DA, 0x35B2, 0x35E5):
    print('  target %04X <- cases %s' % (probe, casemap.get(probe)))

# ---- 3. all 68 trap sites: which case index contains them?
PAT = bytes.fromhex('738F4400067A')
traps = []
p = 0
while True:
    j = il28.find(PAT, p)
    if j < 0: break
    traps.append(j); p = j + 1
def case_of(o):
    for t, cs in casemap.items():
        if t <= o:
            pass
    # find the case whose target is the start of the block containing o:
    # block boundaries = switch targets; find largest target <= o
    ts = sorted(casemap)
    import bisect
    k = bisect.bisect_right(ts, o) - 1
    return ts[k] if k >= 0 else None
print('== trap sites -> containing case target (first 12) ==')
for o in traps[:12]:
    print('  trap@%04X block@%04X cases=%s' % (o, case_of(o), casemap.get(case_of(o))))

# ---- 4. every throw site classification (16B context)
print('== all throws in 4528 ==')
for off, nm, opb, nxt, tg in ins:
    if nm != 'throw': continue
    i = idx[off]
    prev = []
    k = i - 1
    while k >= 0 and len(prev) < 4:
        prev.append(ins[k]); k -= 1
    ctx = ' | '.join('%s %s' % (p[1], p[2].hex()[:8]) for p in reversed(prev))
    print('  @%04X  prev: %s' % (off, ctx))

# ---- 5. P6/P7 site case membership
for o in (0x5E0C, 0x3522):
    print('site %04X block@%04X cases=%s' % (o, case_of(o), casemap.get(case_of(o))))

# ---- 6. 06004523 GAE: region around 0x280-0x2c0, 0x450-0x5d0
il23 = z.read('m_06004523.bin')[24:]
ins23 = disasm(il23)
print('== GAE 06004523 @0x270..0x2d0 and 0x450..0x4e0 ==')
for off, nm, opb, nxt, tg in ins23:
    if 0x270 <= off < 0x2d0 or 0x450 <= off < 0x4e0:
        ann = ''
        if nm in ('call', 'callvirt', 'newobj', 'ldfld', 'stfld', 'ldsfld', 'stsfld', 'castclass'):
            if opb:
                ann = '  ; %s' % res(struct.unpack('<I', opb[:4])[0])
        print('%04X %-12s %-10s%s%s' % (off, nm, opb.hex(), ann,
              ' -> ' + ','.join('%04X' % t for t in tg) if tg else ''))

# ---- 7. GAE all stloc.s 0c / fe.stloc 0c00 (V_12)
print('== GAE V_12 (local 0c) stores ==')
for off, nm, opb, nxt, tg in ins23:
    if (nm == 'stloc.s' and opb == b'\x0c') or (nm == 'fe.stloc' and opb == b'\x0c\x00'):
        print('  @%04X %s' % (off, nm))

# ---- 8. vault presence of 0600448F/06004555
vault = {}
for line in open('/workspace/repo_git/work/c2_pack/vault_index.tsv'):
    p_ = line.rstrip('\n').split('\t')
    if len(p_) > 4 and p_[1].lower().startswith('0600'):
        vault[p_[1].lower()] = p_
for tok in ('0600448f', '06004555', '06004528', '06004523', '06004581', '0600455a'):
    print('vault[%s]:' % tok, 'YES pos=%s size=%s' % (vault[tok][3], vault[tok][4]) if tok in vault else 'no')
