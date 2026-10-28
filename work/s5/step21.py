# -*- coding: utf-8 -*-
"""step21: precise disasm of 06004192 around the verify region (+0x440..+0x560 body offset)
to determine branch polarity after VerifyHash, plus context of the two catch-flag sites
(+0x995, +0x2289) and RSA ctor region (+0x22a9..)."""
import zipfile, struct, sys
import dnfile
sys.path.insert(0, '/workspace/repo_git/work/s5')
from cildasm import disasm, fmt

pe = dnfile.dnPE('/workspace/repo_git/exes/AirExplorer_baseline_verified.exe')
md = pe.net.mdtables

mref_names = {}
for i, r in enumerate(md.MemberRef.rows):
    try:
        ns, tn = str(r.Class.row.TypeNamespace), str(r.Class.row.TypeName)
    except Exception:
        ns, tn = '?', '?'
    mref_names[0x0A000000 + i + 1] = '%s.%s::%s' % (ns, tn, str(r.Name))
def_names = {}
for i, r in enumerate(md.MethodDef.rows):
    def_names[0x06000000 + i + 1] = str(r.Name)
# field names
field_names = {}
for i, r in enumerate(md.Field.rows):
    field_names[0x04000000 + i + 1] = str(r.Name)

def tokname(tok):
    t = tok >> 24
    if t == 0x0A: return mref_names.get(tok, '?mref %08x' % tok)
    if t == 0x06: return 'MD::' + def_names.get(tok, '?%08x' % tok)
    if t == 0x04: return 'FLD::' + field_names.get(tok, '?%08x' % tok)
    if t == 0x70: return 'STR'
    return '%08x' % tok

z = zipfile.ZipFile('/workspace/repo_git/work/dump_official_16598.zip')
names = {n.lower(): n for n in z.namelist()}
b = z.read(names['m_06004192.bin'])
ilsize = struct.unpack_from('<I', b, 4)[0]
ehcnt = struct.unpack_from('<I', b, 12)[0]
print('ilsize=%d eh=%d' % (ilsize, ehcnt))
code = b[24:24 + ilsize]

def dump(lo, hi, title):
    print('---- %s [+%04x..%04x) ----' % (title, lo, hi))
    for ins in disasm(code[lo:hi]):
        off, name, opb, nxt, tgts = ins
        s = fmt(ins)
        line = s
        m = None
        for op in ('call ', 'callvirt ', 'newobj ', 'ldsfld ', 'stsfld ', 'ldfld ', 'stfld ', 'ldstr '):
            idx = s.find(op)
            if idx >= 0:
                m = s[idx + len(op):].strip().rstrip(',')
                break
        if m:
            try:
                tok = int(m, 16)
                line = '%s   ; %s' % (s, tokname(tok))
            except ValueError:
                pass
        print('  ' + line)

dump(0x440, 0x560, 'verify region')
dump(0x940, 0x9c0, 'catch flag site +0x995')
dump(0x2240, 0x2330, 'RSA ctor region +0x22a9 / flag +0x2289')

# also dump the EH clauses to know try/catch ranges near these regions
n24 = 24
if ehcnt:
    # fat header: eh table after code, aligned
    start = 24 + ilsize
    if start % 4: start += 4 - (start % 4)
    for c in range(ehcnt):
        off = start + c * 24
        flags, try_off, try_len, hand_off, hand_len, cls_tok = struct.unpack_from('<IIIIII', b, off)
        print('EH%d flags=%x try=[%04x..%04x) hand=[%04x..%04x) cls=%08x' % (c, flags, try_off, try_off + try_len, hand_off, hand_off + hand_len, cls_tok))
