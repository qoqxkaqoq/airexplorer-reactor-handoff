# -*- coding: utf-8 -*-
"""stepY: identify (1) 06004555 = "AirExplorer " birth point?
(2) AOR source in DefineSetSet after P7; (3) branch structure around 0x3522."""
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

def tname(row, fallback):
    for attr in ('TypeName', 'Name'):
        try:
            v = getattr(row, attr).value
            if v: return v
        except Exception: pass
    return fallback

def res(tok):
    t, rid = tok & 0xFF000000, tok & 0xFFFFFF
    try:
        if t == 0x06000000:
            return 'M:%s::%s' % (mtype.get(rid, '?'), md.MethodDef.rows[rid-1].Name.value)
        if t == 0x0A000000:
            r = md.MemberRef.rows[rid-1]
            cn = '?'
            try: cn = tname(r.Class.row, '?')
            except Exception: pass
            return 'R:%s::%s' % (cn, r.Name.value)
        if t == 0x07000000:
            return 'F:%s' % md.Field.rows[rid-1].Name.value
        if t == 0x01000000:
            s = pe.net.user_strings.get(rid)
            return 'US:%r' % (s.value if s else None)
        if t == 0x04000000:
            return 'FldDef:%s' % md.Field.rows[rid-1].Name.value
        if t == 0x1B000000:
            return 'TypeSpec#%d' % rid
        if t == 0x02000000:
            return 'T:%s' % md.TypeDef.rows[rid-1].TypeName.value
    except Exception as e:
        return 'tok%08x(!%s)' % (tok, e)
    return 'tok%08x' % tok

def us(tok):
    try:
        s = pe.net.user_strings.get(tok & 0xFFFFFF)
        return repr(s.value)[:80] if s else 'None'
    except Exception as e:
        return 'err:%s' % e

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
def body(tok):  # returns IL image (fat header incl.) or None
    try: return z.read('m_%08x.bin' % tok)[24:]
    except KeyError: return None

def show(il, lo, hi, label):
    print('---- %s [%04X..%04X] ----' % (label, lo, hi))
    ins = disasm(il)
    # boundary map
    bset = set(o for o, _, _, _, _ in ins)
    for off, nm, opb, nxt, tg in ins:
        if lo <= off < hi:
            ann = ''
            if nm in ('call', 'callvirt', 'newobj', 'ldfld', 'ldsfld', 'stfld', 'stsfld',
                      'castclass', 'isinst', 'ldstr', 'newarr', 'box', 'unbox.any', 'ldtoken',
                      'ldftn', 'ldvirtftn', 'initobj', 'constrained.', 'cpobj', 'ldobj',
                      'sizeof', 'stobj', 'ldelema'):
                if opb:
                    tokv = struct.unpack('<I', opb[:4])[0] if len(opb) >= 4 else 0
                    ann = '  ; %s' % res(tokv)
            print('%04X %-12s %-10s%s -> %s' % (off, nm, opb.hex(), ann,
                  ','.join('%04X' % t for t in tg) if tg else ''))
    return bset

il28 = body(0x06004528)
print('4528 il size', len(il28))

# ---- 1. branch sources into window 0x3500..0x3620
ins = disasm(il28)
tgt = {}
for off, nm, opb, nxt, tg in ins:
    for t in tg:
        tgt.setdefault(t, []).append((off, nm))
print('== branch targets into 0x3500..0x3620 ==')
for t in sorted(tgt):
    if 0x3500 <= t <= 0x3620:
        print('  -> %04X from %s' % (t, tgt[t]))

# ---- 2. disasm around P7 block
show(il28, 0x34C0, 0x3620, '4528 around P7')

# ---- 3. AOR-capable calls in 4528 (get_Item/get_Chars/Substring/Insert/Remove)
AORN = ('get_Item', 'get_Chars', 'Substring', 'Insert', 'Remove', 'CopyTo', 'get_Data')
print('== 4528 AOR-capable call sites ==')
for off, nm, opb, nxt, tg in ins:
    if nm in ('callvirt', 'call') and opb:
        tokv = struct.unpack('<I', opb[:4])[0]
        rn = res(tokv)
        base = rn.split('::')[-1]
        if any(base.startswith(a) for a in AORN) or '.get_Item' in rn:
            print('  %04X %s %s' % (off, nm, rn))

# ---- 4. 06004555 disasm full
il55 = body(0x06004555)
print('== 06004555 il size', len(il55) if il55 else None)
if il55: show(il55, 0, len(il55), '06004555')

# ---- 5. 0600448F disasm full (TemplatePredicate ctor)
il8f = body(0x0600448F)
print('== 0600448F il size', len(il8f) if il8f else None)
if il8f: show(il8f, 0, len(il8f), '0600448F')

# ---- 6. all callers of 06004555 across dump
PATC = bytes.fromhex('55450006')
print('== dump-wide callers of 06004555 (28/6F 55450006) ==')
for n in sorted(z.namelist()):
    if not n.startswith('m_'): continue
    b = z.read(n)[24:]
    k = 0
    while True:
        j = b.find(PATC, k)
        if j < 0: break
        # check preceding opcode
        if j >= 1 and b[j-1] in (0x28, 0x6F):
            print('  %s +%X op=%02X' % (n, j-1, b[j-1]))
        k = j + 1
